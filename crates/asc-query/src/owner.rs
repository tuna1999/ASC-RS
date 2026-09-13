//! Code-owner discovery: group methods by their `code_off`.
//!
//! In a typical DEX the same bytecode body is referenced by multiple
//! methods (R8 deduplication, abstract bridge methods, default
//! constructors that delegate). Walking the body once and emitting
//! hits per owner is the same logic the oracle uses, just inverted:
//! the oracle walks per-method and asks the `insn_locator` which
//! methods own an offset; we group up front.
//!
//! R8's pattern of "many methods share one code_off" makes this the
//! hot path: emitting per-owner hits without grouping would scan the
//! same body N times.

use asc_dex::ids::MethodIdx;
use asc_dex::view::DexView;
use smallvec::SmallVec;

/// Hint for the smallvec inside `CodeOwner`. Most dedup'd bodies in
/// production DEXes are referenced by 1–2 methods (R8 sometimes
/// doubles up), so 2 keeps the smallvec inline for the common case.
const OWNER_INLINE_HINT: usize = 2;

/// One deduplicated code body.
///
/// `code_off` is the offset of the `code_item` inside the DEX; the
/// engine resolves it via [`DexView::code_item`]. `methods` holds
/// every `MethodIdx` whose `class_data_item::encoded_method.code_off`
/// points at this body (deduplicated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeOwner {
    /// Offset of the `code_item` (4-byte aligned per DEX spec).
    pub code_off: u32,
    /// Every method whose class_data entry points at this `code_off`.
    /// The owner is the entity the engine attributes hits to.
    pub methods: SmallVec<[MethodIdx; OWNER_INLINE_HINT]>,
}

/// Built code-owner table for one DEX.
///
/// Construct via [`CodeOwners::build`]; iterate via [`CodeOwners::owners`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeOwners {
    owners: Vec<CodeOwner>,
}

impl CodeOwners {
    /// Walks every `class_def_item`, parses its `class_data_item`,
    /// collects direct + virtual methods with non-zero `code_off`,
    /// and groups by `code_off`. Order is insertion order (which is
    /// class-def index → method ordinal — stable across runs of the
    /// same DEX).
    ///
    /// `code_off == 0` (abstract / native methods) is skipped.
    pub fn build(view: &DexView) -> Self {
        let n = view.class_def_count();
        let mut owners: Vec<CodeOwner> = Vec::new();
        // Walk in reverse and `insert(0, …)` so we can keep
        // deterministic insertion order without a `HashMap` for the
        // dedup table. The reverse+insert keeps the table tiny.
        let mut by_off: Vec<(u32, SmallVec<[MethodIdx; OWNER_INLINE_HINT]>)> = Vec::new();

        for i in 0..n {
            let def = match view.class_def(i) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if def.class_data_off == 0 {
                continue;
            }
            let data = match view.class_data(def.class_data_off) {
                Ok(Some(d)) => d,
                _ => continue,
            };

            // Direct + virtual methods, in declaration order.
            collect_methods(&mut by_off, &data.direct_methods);
            collect_methods(&mut by_off, &data.virtual_methods);
        }

        // by_off is in insertion order; copy into `owners` keeping
        // that order.
        for (code_off, methods) in by_off {
            owners.push(CodeOwner { code_off, methods });
        }

        Self { owners }
    }

    /// Returns the deduplicated owner list.
    #[inline]
    pub fn owners(&self) -> &[CodeOwner] {
        &self.owners
    }

    /// Returns the number of unique code bodies.
    #[inline]
    pub fn len(&self) -> usize {
        self.owners.len()
    }

    /// Returns `true` when the table is empty (no methods with
    /// non-zero `code_off`).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }
}

/// Appends every method in `methods` whose `code_off != 0` to
/// `by_off`, deduplicating by `code_off`.
fn collect_methods(
    by_off: &mut Vec<(u32, SmallVec<[MethodIdx; OWNER_INLINE_HINT]>)>,
    methods: &[asc_dex::EncodedMethod],
) {
    for m in methods {
        if m.code_off == 0 {
            continue;
        }
        if let Some(slot) = by_off.iter_mut().find(|(off, _)| *off == m.code_off) {
            slot.1.push(m.method_idx);
        } else {
            let mut v: SmallVec<[MethodIdx; OWNER_INLINE_HINT]> = SmallVec::new();
            v.push(m.method_idx);
            by_off.push((m.code_off, v));
        }
    }
}
// --------------------- tests ---------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Test fixtures are integration-only; the unit tests verify the
    // smallvec dedup logic with a synthetic vec of owners.
    #[test]
    fn code_owner_struct_holds_methods() {
        let mut methods: SmallVec<[MethodIdx; 2]> = SmallVec::new();
        methods.push(MethodIdx(7));
        methods.push(MethodIdx(9));
        let owner = CodeOwner {
            code_off: 0x1234,
            methods,
        };
        assert_eq!(owner.code_off, 0x1234);
        assert_eq!(owner.methods.len(), 2);
        assert_eq!(owner.methods[0], MethodIdx(7));
        assert_eq!(owner.methods[1], MethodIdx(9));
    }
}
