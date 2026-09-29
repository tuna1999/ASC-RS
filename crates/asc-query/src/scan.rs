//! Reference scan: walk code bodies, emit hits.
//!
//! `find_refs` is the single public entry point. It:
//! 1. Resolves the [`crate::Query`] to a [`crate::TargetSets`] (the
//!    per-kind id sets the scan will match against).
//! 2. Short-circuits with an empty report when the target set is
//!    empty (no code body is traversed in that case).
//! 3. Builds a [`crate::CodeOwners`] table (deduplicated by
//!    `code_off`).
//! 4. For every unique code_off, builds a [`asc_bytecode::RefWalker`]
//!    over the body's `insns_exact` slice and emits one
//!    [`RefHit`] per owning method per matched `DexRef`.
//!
//! Errors are recorded as [`SearchError`]. Any error during the scan
//! marks the report [`DexSearchReport::complete`] = `false`; partial
//! hits are preserved.

use asc_bytecode::{BytecodeError, DexRef, RefWalker};
use asc_dex::ids::{FieldIdx, MethodIdx, StringIdx, TypeIdx};
use asc_dex::view::DexView;
use smallvec::SmallVec;

use crate::error::SearchError;
use crate::locator::resolve_target_ids;
use crate::owner::CodeOwners;
use crate::query::Query;

/// Sorted-vec + binary-search membership for each pool kind.
///
/// Built once per call to [`find_refs`] from the [`crate::ResolvedTargets`]
/// the locator returned. Conversion to sorted `Vec<u32>` keeps the
/// scan path branch-free and avoids a third-party hash dependency.
#[derive(Debug, Clone, Default)]
pub struct TargetSets {
    /// Sorted `StringIdx` set.
    pub strings: Vec<StringIdx>,
    /// Sorted `TypeIdx` set.
    pub types: Vec<TypeIdx>,
    /// Sorted `FieldIdx` set.
    pub fields: Vec<FieldIdx>,
    /// Sorted `MethodIdx` set.
    pub methods: Vec<MethodIdx>,
}

impl TargetSets {
    /// Builds a `TargetSets` from a [`crate::ResolvedTargets`],
    /// sorting each kind for `binary_search` membership.
    pub fn from_resolved(r: &crate::query::ResolvedTargets) -> Self {
        let mut strings: Vec<StringIdx> = r.strings.iter().copied().collect();
        strings.sort_unstable();
        strings.dedup();
        let mut types: Vec<TypeIdx> = r.types.iter().copied().collect();
        types.sort_unstable();
        types.dedup();
        let mut fields: Vec<FieldIdx> = r.fields.iter().copied().collect();
        fields.sort_unstable();
        fields.dedup();
        let mut methods: Vec<MethodIdx> = r.methods.iter().copied().collect();
        methods.sort_unstable();
        methods.dedup();
        Self {
            strings,
            types,
            fields,
            methods,
        }
    }

    /// `true` when no id set is populated.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
            && self.types.is_empty()
            && self.fields.is_empty()
            && self.methods.is_empty()
    }

    /// `true` when `r` is one of the targets the scan should emit
    /// a hit for.
    fn matches(&self, r: &DexRef) -> bool {
        match r {
            DexRef::String(idx) => self.strings.binary_search(idx).is_ok(),
            DexRef::Type(idx) => self.types.binary_search(idx).is_ok(),
            DexRef::Field(idx) => self.fields.binary_search(idx).is_ok(),
            DexRef::Method(idx) => self.methods.binary_search(idx).is_ok(),
            // call_site / method_handle / proto: not scanned (matches
            // the oracle's `_IDX_GROUPS` exclusion at
            // `code_item_scan.py:262-263`).
            DexRef::Proto(_) | DexRef::CallSite(_) | DexRef::MethodHandle(_) => false,
        }
    }
}

/// One hit produced by [`find_refs`].
///
/// `method` is the **caller** (the method whose code_off was walked);
/// `offset` is the code-unit offset inside that body; `dex_ref` is
/// the pool reference that matched the query (carried so callers can
/// disambiguate which matched id fired when several ids share a kind).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefHit {
    /// The owning method whose code body contained the match.
    pub method: MethodIdx,
    /// Code-unit offset of the matching instruction in the original
    /// `insns` buffer (byte offset = `offset * 2`).
    pub offset: u32,
    /// The pool reference operand that matched the query.
    pub dex_ref: DexRef,
}

/// Result of one per-DEX [`find_refs`] call.
///
/// `hits` is in arbitrary order (scan order: code_off × offset). The
/// `errors` vec preserves failure context for diagnostics; `complete`
/// is `false` iff at least one error short-circuited the scan.
#[derive(Debug, Default)]
pub struct DexSearchReport {
    /// All hits gathered during the scan.
    pub hits: Vec<RefHit>,
    /// Errors observed during resolution / scan. The engine never
    /// panics; any unrecoverable condition lands here.
    pub errors: Vec<SearchError>,
    /// `true` iff every step of the scan completed without error.
    /// When `false`, `hits` contains the partial results gathered
    /// before the failure.
    pub complete: bool,
}

impl DexSearchReport {
    /// Returns the set of caller method indices that produced at
    /// least one hit, deduplicated and sorted ascending. This is the
    /// "matched method set" the oracle's `matched_methods_sorted`
    /// field in `counts.json` is built from.
    pub fn caller_methods_sorted(&self) -> Vec<MethodIdx> {
        let mut set: SmallVec<[MethodIdx; 8]> = SmallVec::new();
        for h in &self.hits {
            if !set.contains(&h.method) {
                set.push(h.method);
            }
        }
        set.sort_unstable();
        set.into_vec()
    }
}

/// Runs a per-DEX findrefs scan.
///
/// Steps:
///
/// 1. [`resolve_target_ids`] — empty target set short-circuits to an
///    empty `complete = true` report.
/// 2. Build [`CodeOwners`] — one owner per unique `code_off`.
/// 3. For each owner: `code_item` (errors recorded) → `RefWalker`
///    (init / mid-stream errors recorded, scan aborts that body and
///    continues with the next owner).
/// 4. Each matched `primary` / `secondary` becomes one [`RefHit`]
///    per owning method.
///
/// `view` is borrowed; the physical DEX buffer is never copied.
pub fn find_refs(view: &DexView, query: &Query) -> DexSearchReport {
    // --- Step 1: resolve targets ------------------------------------
    let resolved = match resolve_target_ids(view, query) {
        Ok(r) => r,
        Err(e) => {
            return DexSearchReport {
                hits: Vec::new(),
                errors: vec![e],
                complete: false,
            };
        }
    };
    let targets = TargetSets::from_resolved(&resolved);
    if targets.is_empty() {
        return DexSearchReport {
            hits: Vec::new(),
            errors: Vec::new(),
            complete: true,
        };
    }

    // --- Step 2: build code owners ----------------------------------
    let owners = CodeOwners::build(view);

    // --- Step 3: per-owner scan -------------------------------------
    let mut hits: Vec<RefHit> = Vec::new();
    let mut errors: Vec<SearchError> = Vec::new();
    let mut complete = true;

    for owner in owners.owners() {
        let code_off = owner.code_off;
        let ci = match view.code_item(code_off) {
            Ok(Some(ci)) => ci,
            Ok(None) => {
                // Empty offset: should not happen (owners skip code_off=0)
                // but report it defensively.
                errors.push(SearchError::Code {
                    code_off,
                    source: asc_dex::error::DexError::Malformed(
                        "code_off resolved to no code_item",
                    ),
                });
                complete = false;
                continue;
            }
            Err(source) => {
                errors.push(SearchError::Code { code_off, source });
                complete = false;
                continue;
            }
        };

        let insns = ci.insns_exact();
        let mut walker = match RefWalker::new(insns, ci.insns_size) {
            Ok(w) => w,
            Err(source) => {
                errors.push(SearchError::WalkerInit { code_off, source });
                complete = false;
                continue;
            }
        };

        let mut aborted = false;
        for step in walker.by_ref() {
            match step {
                Ok(insn) => {
                    // Per-code-owner fan-out: emit one hit per owner
                    // method for each matched DexRef.
                    if let Some(r) = insn.primary
                        && targets.matches(&r)
                    {
                        for &method in &owner.methods {
                            hits.push(RefHit {
                                method,
                                offset: insn.offset,
                                dex_ref: r,
                            });
                        }
                    }
                    if let Some(r) = insn.secondary
                        && targets.matches(&r)
                    {
                        for &method in &owner.methods {
                            hits.push(RefHit {
                                method,
                                offset: insn.offset,
                                dex_ref: r,
                            });
                        }
                    }
                }
                Err(source) => {
                    errors.push(SearchError::Walker {
                        code_off,
                        insn_offset: insn_offset_of(&source),
                        source,
                    });
                    complete = false;
                    aborted = true;
                    break;
                }
            }
        }
        if aborted {
            // Move on to the next owner; partial hits from this body
            // are already in `hits`.
            continue;
        }
    }

    DexSearchReport {
        hits,
        errors,
        complete,
    }
}

/// Extracts the code-unit offset out of a [`BytecodeError`].
///
/// Every `BytecodeError` variant carries `offset` as the first field;
/// matching keeps the call site readable.
fn insn_offset_of(e: &BytecodeError) -> u32 {
    match *e {
        BytecodeError::LengthMismatch { offset, .. } => offset,
        BytecodeError::TruncatedInstruction { offset, .. } => offset,
        BytecodeError::UnknownOpcode { offset, .. } => offset,
        BytecodeError::MalformedPayload { offset, .. } => offset,
    }
}

// --------------------- tests ---------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::ClassConstraint;
    use asc_dex::ids::MethodIdx;

    #[test]
    fn target_sets_dedup_and_sort() {
        let mut r = crate::query::ResolvedTargets::default();
        r.methods.push(MethodIdx(9));
        r.methods.push(MethodIdx(3));
        r.methods.push(MethodIdx(3));
        r.methods.push(MethodIdx(7));
        let ts = TargetSets::from_resolved(&r);
        assert_eq!(ts.methods, vec![MethodIdx(3), MethodIdx(7), MethodIdx(9)]);
    }

    #[test]
    fn target_sets_is_empty() {
        let ts = TargetSets::default();
        assert!(ts.is_empty());
        let r = crate::query::ResolvedTargets::default();
        let ts = TargetSets::from_resolved(&r);
        assert!(ts.is_empty());
    }

    #[test]
    fn target_sets_matches() {
        let mut r = crate::query::ResolvedTargets::default();
        r.methods.push(MethodIdx(5));
        r.fields.push(FieldIdx(2));
        r.types.push(TypeIdx(11));
        r.strings.push(StringIdx(7));
        let ts = TargetSets::from_resolved(&r);
        assert!(ts.matches(&DexRef::Method(MethodIdx(5))));
        assert!(!ts.matches(&DexRef::Method(MethodIdx(6))));
        assert!(ts.matches(&DexRef::Field(FieldIdx(2))));
        assert!(ts.matches(&DexRef::Type(TypeIdx(11))));
        assert!(ts.matches(&DexRef::String(StringIdx(7))));
        // call_site / proto / method_handle never match.
        assert!(!ts.matches(&DexRef::Proto(asc_bytecode::ProtoIdx(0))));
        assert!(!ts.matches(&DexRef::CallSite(asc_bytecode::CallSiteIdx(0))));
        assert!(!ts.matches(&DexRef::MethodHandle(asc_bytecode::MethodHandleIdx(0))));
    }

    #[test]
    fn caller_methods_sorted_dedup() {
        let report = DexSearchReport {
            hits: vec![
                RefHit {
                    method: MethodIdx(5),
                    offset: 0,
                    dex_ref: DexRef::Method(MethodIdx(1)),
                },
                RefHit {
                    method: MethodIdx(3),
                    offset: 1,
                    dex_ref: DexRef::Method(MethodIdx(1)),
                },
                RefHit {
                    method: MethodIdx(5),
                    offset: 2,
                    dex_ref: DexRef::Method(MethodIdx(2)),
                },
            ],
            errors: Vec::new(),
            complete: true,
        };
        assert_eq!(
            report.caller_methods_sorted(),
            vec![MethodIdx(3), MethodIdx(5)]
        );
    }

    #[test]
    fn empty_query_short_circuits() {
        // Method/Field with neither name nor class is structurally
        // empty: resolve_target_ids returns no ids, find_refs would
        // short-circuit. We exercise the Query::is_empty path and
        // the constructor at the unit-test level (the integration
        // tests confirm end-to-end behavior on real DEX fixtures).
        let q = Query::method(None::<&str>, None);
        assert!(q.is_empty());
        let _ = ClassConstraint::new_exact("Foo");
    }
}
