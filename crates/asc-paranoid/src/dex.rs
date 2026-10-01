//! Locating Paranoid deobfuscator classes and their call sites in a DEX.

use std::collections::{HashMap, HashSet};

use asc_bytecode::{Format, insn_width, opcode_info};
use asc_dex::{ClassData, CodeItem, DexView, FieldIdx, MethodIdx, ProtoIdx, StringIdx, TypeIdx};

const ACC_STATIC: u32 = 0x0008;
/// First multiplier of `RandomHelper.seed`; present in every R8-inlined
/// `getString(J)` body.
const SEED_MAGIC: i64 = 0x62A9_D9ED_7997_05F5;
const STRING: &[u8] = b"Ljava/lang/String;";
const STRING_ARRAY: &[u8] = b"[Ljava/lang/String;";
/// Largest chunk array accepted from `<clinit>` (u16 index space).
const MAX_CHUNKS: i64 = 1 << 16;

/// One `getString(J)Ljava/lang/String;` method plus its chunk table.
#[derive(Debug, Clone)]
pub struct Deobfuscator {
    /// Declaring class descriptor (`Lio/michaelrocks/paranoid/Deobfuscator$app;`).
    pub class: String,
    /// Method name (`getString` unless minified).
    pub method: String,
    chunks: Vec<Vec<u16>>,
}

impl Deobfuscator {
    /// Decodes the string with Paranoid id `id`.
    pub fn decode(&self, id: i64) -> Option<Vec<u16>> {
        crate::decode(id, &self.chunks)
    }
}

/// A resolved `getString` call site inside one code body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// Code-unit offset of the 3-unit `invoke-static` / `invoke-static/range`.
    pub offset: u32,
    /// Destination of the `move-result-object` directly after the invoke
    /// (`None` when the result is discarded).
    pub result: Option<u8>,
    /// Decoded string as UTF-16 code units.
    pub value: Vec<u16>,
}

pub(crate) fn str_bytes<'a>(view: &DexView<'a>, idx: StringIdx) -> Option<&'a [u8]> {
    view.string(idx).ok().map(|s| s.raw_mutf8())
}

pub(crate) fn type_bytes<'a>(view: &DexView<'a>, idx: TypeIdx) -> Option<&'a [u8]> {
    str_bytes(view, view.type_(idx).ok()?)
}

pub(crate) fn lossy(bytes: &[u8]) -> String {
    asc_dex::decode_mutf8_lossy(bytes, 0).into_owned()
}

/// Proto ids of the form `(<param>)Ljava/lang/String;` in `view`.
pub(crate) fn string_protos(view: &DexView<'_>, params: &[&[u8]]) -> HashSet<u32> {
    (0..view.proto_count())
        .filter(|&p| {
            let Ok(proto) = view.proto(ProtoIdx(p)) else {
                return false;
            };
            type_bytes(view, proto.return_type) == Some(STRING)
                && proto.parameters.len() == params.len()
                && proto
                    .parameters
                    .iter()
                    .zip(params)
                    .all(|(t, want)| type_bytes(view, t) == Some(*want))
        })
        .collect()
}

/// Finds every Paranoid deobfuscator class defined in `view`.
///
/// A match is a static `(J)Ljava/lang/String;` method whose body reads
/// exactly one `String[]` field of its own class and either contains the
/// `RandomHelper.seed` constant or calls a `(J[Ljava/lang/String;)String`
/// helper; the chunks come from that field's `<clinit>` initialisation.
/// Malformed class data is skipped.
pub fn find_deobfuscators(view: &DexView<'_>) -> Vec<Deobfuscator> {
    let mut out = Vec::new();
    let get_protos = string_protos(view, &[b"J"]);
    if get_protos.is_empty() {
        return out;
    }
    let helper_protos = string_protos(view, &[b"J", STRING_ARRAY]);
    let classes: HashSet<u32> = (0..view.method_count())
        .filter_map(|m| view.method(MethodIdx(m)).ok())
        .filter(|m| get_protos.contains(&m.proto.0))
        .map(|m| m.class.0)
        .collect();

    for i in 0..view.class_def_count() {
        let Ok(cd) = view.class_def(i) else { continue };
        if !classes.contains(&cd.class.0) {
            continue;
        }
        let Ok(Some(data)) = view.class_data(cd.class_data_off) else {
            continue;
        };
        let Some(class) = type_bytes(view, cd.class) else {
            continue;
        };
        let mut chunk_cache: HashMap<u32, Option<Vec<Vec<u16>>>> = HashMap::new();
        for em in &data.direct_methods {
            if em.access_flags & ACC_STATIC == 0 || em.code_off == 0 {
                continue;
            }
            let Ok(mi) = view.method(em.method_idx) else {
                continue;
            };
            if !get_protos.contains(&mi.proto.0) {
                continue;
            }
            let Ok(Some(code)) = view.code_item(em.code_off) else {
                continue;
            };
            let Some(field) = getstring_field(view, &code, &helper_protos) else {
                continue;
            };
            if view.field(field).map(|f| f.class) != Ok(cd.class) {
                continue;
            }
            let chunks = chunk_cache
                .entry(field.0)
                .or_insert_with(|| clinit_chunks(view, &data, field));
            let (Some(chunks), Some(name)) = (chunks, str_bytes(view, mi.name)) else {
                continue;
            };
            out.push(Deobfuscator {
                class: lossy(class),
                method: lossy(name),
                chunks: chunks.clone(),
            });
        }
    }
    out
}

/// Instruction start offsets and widths of a code body (payloads included).
pub(crate) fn decode_insns(insns: &[u8], units: u32) -> Option<Vec<(u32, u32)>> {
    let mut out = Vec::new();
    let mut off = 0;
    while off < units {
        let w = insn_width(insns, off, units).ok()?;
        out.push((off, w));
        off = off.checked_add(w)?;
    }
    Some(out)
}

#[inline]
pub(crate) fn unit(insns: &[u8], off: u32, k: u32) -> u16 {
    let b = (off + k) as usize * 2;
    u16::from_le_bytes([insns[b], insns[b + 1]])
}

#[inline]
pub(crate) fn unit32(insns: &[u8], off: u32, k: u32) -> u32 {
    unit(insns, off, k) as u32 | (unit(insns, off, k + 1) as u32) << 16
}

pub(crate) fn is_payload(insns: &[u8], off: u32) -> bool {
    matches!(unit(insns, off, 0), 0x0100 | 0x0200 | 0x0300)
}

/// `(dest, value)` of a `const-wide*` instruction.
fn const_wide(insns: &[u8], off: u32) -> Option<(u16, i64)> {
    let first = unit(insns, off, 0);
    let aa = first >> 8;
    let v = match first as u8 {
        0x16 => unit(insns, off, 1) as i16 as i64,
        0x17 => unit32(insns, off, 1) as i32 as i64,
        0x18 => (unit32(insns, off, 1) as u64 | (unit32(insns, off, 3) as u64) << 32) as i64,
        0x19 => (unit(insns, off, 1) as i16 as i64) << 48,
        _ => return None,
    };
    Some((aa, v))
}

/// Register operands of an instruction: explicit list or `/range`.
pub(crate) enum Regs {
    List([u16; 5], usize),
    Range(u16, u16),
}

pub(crate) fn regs(insns: &[u8], off: u32) -> Regs {
    let first = unit(insns, off, 0);
    let b1 = first >> 8;
    let (a4, b4) = (b1 & 0xF, b1 >> 4);
    let one = |r| Regs::List([r, 0, 0, 0, 0], 1);
    let two = |r, s| Regs::List([r, s, 0, 0, 0], 2);
    match opcode_info(first as u8).format {
        Format::Format12x | Format::Format22t | Format::Format22s | Format::Format22c => {
            two(a4, b4)
        }
        Format::Format11n => one(a4),
        Format::Format11x
        | Format::Format21t
        | Format::Format21s
        | Format::Format21h
        | Format::Format21c
        | Format::Format31i
        | Format::Format31t
        | Format::Format31c
        | Format::Format51l => one(b1),
        Format::Format22x => two(b1, unit(insns, off, 1)),
        Format::Format23x => {
            let u = unit(insns, off, 1);
            Regs::List([b1, u & 0xFF, u >> 8, 0, 0], 3)
        }
        Format::Format22b => two(b1, unit(insns, off, 1) & 0xFF),
        Format::Format32x => two(unit(insns, off, 1), unit(insns, off, 2)),
        Format::Format35c | Format::Format35mi | Format::Format45cc => {
            let u = unit(insns, off, 2);
            let r = [u & 0xF, (u >> 4) & 0xF, (u >> 8) & 0xF, u >> 12, a4];
            Regs::List(r, (b4 as usize).min(5))
        }
        Format::Format3rc | Format::Format4rcc => Regs::Range(unit(insns, off, 2), b1),
        _ => Regs::List([0; 5], 0),
    }
}

/// Whether the instruction at `off` names any register overlapping the
/// wide pair `c, c+1` (operands are treated as possibly wide).
fn touches_pair(insns: &[u8], off: u32, c: u16) -> bool {
    let (lo, hi) = (c as i32 - 1, c as i32 + 1);
    match regs(insns, off) {
        Regs::List(r, n) => r[..n].iter().any(|&r| (lo..=hi).contains(&(r as i32))),
        Regs::Range(s, n) => n > 0 && (s as i32) <= hi && (s as i32 + n as i32 - 1) >= lo,
    }
}

/// Offsets that can be entered other than by falling through from the
/// previous instruction: branch/switch targets and catch handlers.
pub(crate) fn leaders(
    view: &DexView<'_>,
    code: &CodeItem<'_>,
    insns: &[u8],
    list: &[(u32, u32)],
) -> HashSet<u32> {
    let mut out = HashSet::new();
    let mut add = |base: u32, rel: i64| {
        if let Ok(t) = u32::try_from(base as i64 + rel) {
            out.insert(t);
        }
    };
    for &(off, _) in list {
        if is_payload(insns, off) {
            continue;
        }
        let first = unit(insns, off, 0);
        match first as u8 {
            0x28 => add(off, (first >> 8) as u8 as i8 as i64),
            0x29 | 0x32..=0x3d => add(off, unit(insns, off, 1) as i16 as i64),
            0x2a => add(off, unit32(insns, off, 1) as i32 as i64),
            0x2b | 0x2c => {
                let Ok(p) = u32::try_from(off as i64 + unit32(insns, off, 1) as i32 as i64) else {
                    continue;
                };
                let Some(&(_, pw)) = list.iter().find(|(o, _)| *o == p) else {
                    continue;
                };
                if !is_payload(insns, p) {
                    continue;
                }
                let size = unit(insns, p, 1) as u32;
                // packed: ident, size, first_key(2), targets; sparse: ident, size, keys, targets.
                let targets = if first as u8 == 0x2b { 4 } else { 2 + size * 2 };
                for k in 0..size {
                    let at = targets + k * 2;
                    if at + 1 < pw {
                        add(off, unit32(insns, p, at) as i32 as i64);
                    }
                }
            }
            _ => {}
        }
    }
    if code.tries_size > 0
        && let Ok(Some(list)) = view.catch_handler_list(code)
        && let Ok(handlers) = list.iter_all()
    {
        for h in handlers {
            out.extend(h.pairs.iter().map(|&(_, addr)| addr));
            out.extend(h.catch_all_addr);
        }
    }
    out
}

/// The single `String[]` static field a `getString(J)` candidate reads,
/// if its body also carries a Paranoid fingerprint.
fn getstring_field(
    view: &DexView<'_>,
    code: &CodeItem<'_>,
    helper_protos: &HashSet<u32>,
) -> Option<FieldIdx> {
    let insns = code.insns_exact();
    let list = decode_insns(insns, code.insns_size)?;
    let mut field = None;
    let mut fingerprint = false;
    for &(off, _) in &list {
        if is_payload(insns, off) {
            continue;
        }
        match unit(insns, off, 0) as u8 {
            0x62 => {
                let f = FieldIdx(unit(insns, off, 1) as u32);
                let ty = view.field(f).ok().and_then(|fi| type_bytes(view, fi.ty));
                if ty == Some(STRING_ARRAY) {
                    if field.is_some_and(|g| g != f) {
                        return None;
                    }
                    field = Some(f);
                }
            }
            0x18 => fingerprint |= const_wide(insns, off).is_some_and(|(_, v)| v == SEED_MAGIC),
            0x71 | 0x77 => {
                let m = MethodIdx(unit(insns, off, 1) as u32);
                fingerprint |= view
                    .method(m)
                    .is_ok_and(|mi| helper_protos.contains(&mi.proto.0));
            }
            _ => {}
        }
    }
    field.filter(|_| fingerprint)
}

#[derive(Clone, Copy)]
enum Val {
    Int(i64),
    Str(u32),
    Arr(usize),
}

/// Runs the class's `<clinit>` symbolically to recover the chunk array
/// stored into `field`. Any instruction it does not model clears the
/// registers it names, so an unexpected shape yields `None`, never a
/// wrong table.
fn clinit_chunks(view: &DexView<'_>, data: &ClassData, field: FieldIdx) -> Option<Vec<Vec<u16>>> {
    let code = data.direct_methods.iter().find_map(|em| {
        let mi = view.method(em.method_idx).ok()?;
        (str_bytes(view, mi.name)? == b"<clinit>").then_some(em.code_off)
    })?;
    let code = view.code_item(code).ok()??;
    let insns = code.insns_exact();
    let list = decode_insns(insns, code.insns_size)?;

    let mut regs_v: HashMap<u16, Val> = HashMap::new();
    let mut arrays: Vec<Vec<Option<u32>>> = Vec::new();
    let mut bound: Option<usize> = None;
    let mut pending: Option<usize> = None;
    let is_string_array = |t: u16| type_bytes(view, TypeIdx(t as u32)) == Some(STRING_ARRAY);

    for &(off, _) in &list {
        if is_payload(insns, off) {
            continue;
        }
        let first = unit(insns, off, 0);
        let b1 = first >> 8;
        let (a4, b4) = (b1 & 0xF, b1 >> 4);
        let fresh = pending.take();
        match first as u8 {
            0x12 => {
                regs_v.insert(a4, Val::Int(((b1 as u8 as i8) >> 4) as i64));
            }
            0x13 => {
                regs_v.insert(b1, Val::Int(unit(insns, off, 1) as i16 as i64));
            }
            0x14 => {
                regs_v.insert(b1, Val::Int(unit32(insns, off, 1) as i32 as i64));
            }
            0x15 => {
                regs_v.insert(
                    b1,
                    Val::Int(((unit(insns, off, 1) as i16 as i32) << 16) as i64),
                );
            }
            0x1a => {
                regs_v.insert(b1, Val::Str(unit(insns, off, 1) as u32));
            }
            0x1b => {
                regs_v.insert(b1, Val::Str(unit32(insns, off, 1)));
            }
            0x07..=0x09 => {
                let (dst, src) = match first as u8 {
                    0x07 => (a4, b4),
                    0x08 => (b1, unit(insns, off, 1)),
                    _ => (unit(insns, off, 1), unit(insns, off, 2)),
                };
                match regs_v.get(&src).copied() {
                    Some(v) => regs_v.insert(dst, v),
                    None => regs_v.remove(&dst),
                };
            }
            0x0c => match fresh {
                Some(a) => {
                    regs_v.insert(b1, Val::Arr(a));
                }
                None => {
                    regs_v.remove(&b1);
                }
            },
            0x23 if is_string_array(unit(insns, off, 1)) => match regs_v.get(&b4) {
                Some(&Val::Int(n)) if (0..=MAX_CHUNKS).contains(&n) => {
                    arrays.push(vec![None; n as usize]);
                    regs_v.insert(a4, Val::Arr(arrays.len() - 1));
                }
                _ => {
                    regs_v.remove(&a4);
                }
            },
            0x24 | 0x25 if is_string_array(unit(insns, off, 1)) => {
                let names: Vec<u16> = match regs(insns, off) {
                    Regs::List(r, n) => r[..n].to_vec(),
                    Regs::Range(s, n) => (0..n).map(|k| s.wrapping_add(k)).collect(),
                };
                let items: Option<Vec<Option<u32>>> = names
                    .iter()
                    .map(|r| match regs_v.get(r) {
                        Some(&Val::Str(s)) => Some(Some(s)),
                        _ => None,
                    })
                    .collect();
                if let Some(items) = items {
                    arrays.push(items);
                    pending = Some(arrays.len() - 1);
                }
            }
            0x4d => {
                let u = unit(insns, off, 1);
                if let (Some(&Val::Str(s)), Some(&Val::Arr(a)), Some(&Val::Int(i))) = (
                    regs_v.get(&b1),
                    regs_v.get(&(u & 0xFF)),
                    regs_v.get(&(u >> 8)),
                ) && let Some(slot) = usize::try_from(i).ok().and_then(|i| arrays[a].get_mut(i))
                {
                    *slot = Some(s);
                }
            }
            0x69 if unit(insns, off, 1) as u32 == field.0 => {
                bound = match regs_v.get(&b1) {
                    Some(&Val::Arr(a)) => Some(a),
                    _ => None,
                };
            }
            0x62 if unit(insns, off, 1) as u32 == field.0 => match bound {
                Some(a) => {
                    regs_v.insert(b1, Val::Arr(a));
                }
                None => {
                    regs_v.remove(&b1);
                }
            },
            _ => {
                let mut clear = |r: u16| {
                    regs_v.remove(&r);
                    regs_v.remove(&r.wrapping_add(1));
                };
                match regs(insns, off) {
                    Regs::List(r, n) => r[..n].iter().for_each(|&r| clear(r)),
                    Regs::Range(s, n) => (0..n).for_each(|k| clear(s.wrapping_add(k))),
                }
            }
        }
    }

    arrays
        .get(bound?)?
        .iter()
        .map(|s| Some(asc_dex::mutf8::to_utf16(str_bytes(view, StringIdx((*s)?))?)))
        .collect()
}

/// Per-DEX index of the `getString` method ids that resolve to a known
/// [`Deobfuscator`] (which may live in another DEX of the same APK).
pub struct Resolver<'d> {
    targets: HashMap<u32, &'d Deobfuscator>,
}

impl<'d> Resolver<'d> {
    /// Matches `view`'s method ids against `deobs` by class descriptor,
    /// name and `(J)Ljava/lang/String;` proto.
    pub fn new(view: &DexView<'_>, deobs: &'d [Deobfuscator]) -> Self {
        let mut targets = HashMap::new();
        if !deobs.is_empty() {
            let protos = string_protos(view, &[b"J"]);
            for m in 0..view.method_count() {
                let Ok(mi) = view.method(MethodIdx(m)) else {
                    continue;
                };
                if !protos.contains(&mi.proto.0) {
                    continue;
                }
                let (Some(name), Some(class)) =
                    (str_bytes(view, mi.name), type_bytes(view, mi.class))
                else {
                    continue;
                };
                if let Some(d) = deobs
                    .iter()
                    .find(|d| d.method.as_bytes() == name && d.class.as_bytes() == class)
                {
                    targets.insert(m, d);
                }
            }
        }
        Self { targets }
    }

    /// `true` when `view` never references a known deobfuscator.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Every `getString(<const id>)` call in `code` whose id is a
    /// `const-wide` reaching the invoke along straight-line code (same
    /// basic block, pair untouched in between). Other calls (ids from
    /// parameters, fields, other blocks) are left alone.
    pub fn calls(&self, view: &DexView<'_>, code: &CodeItem<'_>) -> Vec<Call> {
        let mut out = Vec::new();
        if self.targets.is_empty() {
            return out;
        }
        let insns = code.insns_exact();
        let Some(list) = decode_insns(insns, code.insns_size) else {
            return out;
        };
        let mut block_starts: Option<HashSet<u32>> = None;
        for (pos, &(off, _)) in list.iter().enumerate() {
            if is_payload(insns, off) {
                continue;
            }
            let first = unit(insns, off, 0);
            let c = match first as u8 {
                0x71 if first >> 12 == 2 => {
                    let u = unit(insns, off, 2);
                    let c = u & 0xF;
                    if (u >> 4) & 0xF != c + 1 {
                        continue;
                    }
                    c
                }
                0x77 if first >> 8 == 2 => unit(insns, off, 2),
                _ => continue,
            };
            let Some(deob) = self.targets.get(&(unit(insns, off, 1) as u32)) else {
                continue;
            };
            let starts = block_starts.get_or_insert_with(|| leaders(view, code, insns, &list));
            let Some(id) = backtrack(insns, &list, pos, c, starts) else {
                continue;
            };
            let Some(value) = deob.decode(id) else {
                continue;
            };
            let result = list
                .get(pos + 1)
                .filter(|&&(o, _)| !is_payload(insns, o) && unit(insns, o, 0) as u8 == 0x0c)
                .map(|&(o, _)| (unit(insns, o, 0) >> 8) as u8);
            out.push(Call {
                offset: off,
                result,
                value,
            });
        }
        out
    }
}

/// Walks back from the invoke at `list[pos]` to the `const-wide` that
/// defines the pair `c, c+1`, within the invoke's basic block.
fn backtrack(
    insns: &[u8],
    list: &[(u32, u32)],
    pos: usize,
    c: u16,
    leaders: &HashSet<u32>,
) -> Option<i64> {
    if leaders.contains(&list[pos].0) {
        return None;
    }
    for &(off, _) in list[..pos].iter().rev() {
        if is_payload(insns, off) {
            return None;
        }
        if let Some((dst, v)) = const_wide(insns, off)
            && dst == c
        {
            return Some(v);
        }
        if touches_pair(insns, off, c) || leaders.contains(&off) {
            return None;
        }
    }
    None
}
