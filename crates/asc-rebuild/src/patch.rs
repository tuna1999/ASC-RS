//! Optional string-constant patches applied while rebuilding.
//!
//! A [`StringPatch`] turns a resolved `invoke-static …getString(J)` +
//! `move-result-object vB` pair (4 code units) into
//! `const-string vB, "…"` padded with `nop`s, so the decompiler sees the
//! literal. Strings already in the source pool reuse their index; new
//! ones are merged into the rebuilt pool in UTF-16 order, as the DEX
//! format requires.

use std::collections::{BTreeSet, HashMap};

use asc_dex::mutf8::{from_utf16, to_utf16};
use asc_dex::{DexView, StringIdx};

use crate::closure::Closure;
use crate::error::RebuildError;
use crate::remap::IndexMap;

/// Replace the call at `offset` in the method whose source `code_off` is
/// `code_off` with `const-string result, value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringPatch {
    /// Source-side `code_item` offset of the patched method.
    pub code_off: u32,
    /// Code-unit offset of the 3-unit `invoke-static[/range]`; the
    /// `move-result-object` must follow it directly.
    pub offset: u32,
    /// Destination register of that `move-result-object`.
    pub result: u8,
    /// String value as UTF-16 code units.
    pub value: Vec<u16>,
}

/// One entry of the rebuilt string pool, in output order.
pub(crate) enum Slot {
    Old(u32),
    New(Vec<u16>),
}

/// Rebuilt string-pool order plus the per-method instruction edits.
pub(crate) struct Plan {
    pub order: Vec<Slot>,
    /// `code_off → [(offset, result register, new string idx)]`.
    pub edits: HashMap<u32, Vec<(u32, u8, u32)>>,
}

impl Plan {
    /// Adds the patch strings to the closure/pool and returns the plan.
    /// With no patches the order is exactly `closure.strings`.
    pub(crate) fn build(
        view: &DexView<'_>,
        closure: &mut Closure,
        patches: &[StringPatch],
        strings: &mut IndexMap<StringIdx>,
    ) -> Result<Self, RebuildError> {
        if patches.is_empty() {
            return Ok(Self {
                order: closure.strings.iter().map(|&o| Slot::Old(o)).collect(),
                edits: HashMap::new(),
            });
        }
        let utf16 = |i: u32| -> Result<Vec<u16>, RebuildError> {
            Ok(to_utf16(view.string(StringIdx(i))?.raw_mutf8()))
        };
        let mut extras: BTreeSet<&[u16]> = BTreeSet::new();
        let mut existing: Vec<Option<u32>> = Vec::with_capacity(patches.len());
        for p in patches {
            let pos = partition_point(view.string_count(), |i| {
                Ok(utf16(i)?.as_slice() < &p.value[..])
            })?;
            if pos < view.string_count() && utf16(pos)? == p.value {
                closure.strings.insert(pos);
                existing.push(Some(pos));
            } else {
                extras.insert(&p.value);
                existing.push(None);
            }
        }

        let mut order = Vec::with_capacity(closure.strings.len() + extras.len());
        let mut extras = extras.into_iter().peekable();
        for &old in &closure.strings {
            if extras.peek().is_some() {
                let cur = utf16(old)?;
                while let Some(e) = extras.next_if(|e| *e < cur.as_slice()) {
                    order.push(Slot::New(e.to_vec()));
                }
            }
            order.push(Slot::Old(old));
        }
        order.extend(extras.map(|e| Slot::New(e.to_vec())));

        *strings = IndexMap::from_order(
            order.iter().map(|s| match s {
                Slot::Old(o) => Some(*o),
                Slot::New(_) => None,
            }),
            view.string_count(),
        );
        let new_idx: HashMap<&[u16], u32> = order
            .iter()
            .enumerate()
            .filter_map(|(i, s)| match s {
                Slot::New(v) => Some((v.as_slice(), i as u32)),
                Slot::Old(_) => None,
            })
            .collect();

        let mut edits: HashMap<u32, Vec<(u32, u8, u32)>> = HashMap::new();
        for (p, old) in patches.iter().zip(existing) {
            let idx = match old {
                Some(old) => strings.lookup(old)?,
                None => new_idx[p.value.as_slice()],
            };
            edits
                .entry(p.code_off)
                .or_default()
                .push((p.offset, p.result, idx));
        }
        Ok(Self { order, edits })
    }

    /// Applies the edits for the method at source `code_off` to its
    /// already-remapped `insns`. Each site must still be
    /// `invoke-static[/range]` + `move-result-object result`.
    pub(crate) fn apply(&self, code_off: u32, insns: &mut [u8]) -> Result<(), RebuildError> {
        let Some(edits) = self.edits.get(&code_off) else {
            return Ok(());
        };
        for &(offset, result, idx) in edits {
            let at = offset as usize * 2;
            let site = insns
                .get_mut(at..at + 8)
                .ok_or(RebuildError::Internal("string patch outside insns"))?;
            if !matches!(site[0], 0x71 | 0x77) || site[6] != 0x0C || site[7] != result {
                return Err(RebuildError::Internal(
                    "string patch site is not invoke + move-result-object",
                ));
            }
            site.fill(0);
            site[1] = result;
            if let Ok(i) = u16::try_from(idx) {
                site[0] = 0x1A;
                site[2..4].copy_from_slice(&i.to_le_bytes());
            } else {
                site[0] = 0x1B;
                site[2..6].copy_from_slice(&idx.to_le_bytes());
            }
        }
        Ok(())
    }
}

/// `string_data` record for a new string: uleb utf16 length + MUTF-8 + NUL.
pub(crate) fn push_new_string_data(out: &mut Vec<u8>, units: &[u16]) {
    let _ = crate::util::write_uleb128_to(out, units.len() as u64, crate::util::ULEB_GENERIC_MAX);
    out.extend_from_slice(&from_utf16(units));
    out.push(0);
}

/// First index in `0..n` where `lt` is false (`lt` must be monotone).
fn partition_point(
    n: u32,
    lt: impl Fn(u32) -> Result<bool, RebuildError>,
) -> Result<u32, RebuildError> {
    let (mut lo, mut hi) = (0, n);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if lt(mid)? {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    Ok(lo)
}
