//! One-hop callee discovery: which methods does `C.m` invoke?
//!
//! This is the fan-out half of a call graph. The fan-in half (who
//! calls `C.m`) is already covered by `find_refs` with a
//! method-scoped query; this module answers the opposite direction
//! by walking only the code bodies of `C.m`'s overloads with a
//! [`RefWalker`] — no global xref table, bounded to one class.
//!
//! ## Completeness (same contract as `find_refs` / `strings_of`)
//!
//! A body that fails mid-walk keeps the callees gathered so far, the
//! failure is recorded in [`CalleesReport::errors`], and `complete`
//! flips to `false` (audit P1).

use std::collections::HashMap;

use asc_bytecode::{DexRef, RefWalker};
use asc_dex::ids::MethodIdx;
use asc_dex::view::DexView;

use crate::error::SearchError;

/// One distinct callee of the scanned method(s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Callee {
    /// `Lcom/foo/Bar;->name` of the invoked method.
    pub target: String,
    /// Number of invoke sites hitting `target` inside the scanned
    /// bodies (overloads of the same name are merged).
    pub sites: usize,
}

/// Render a method id as `Lcom/foo/Bar;->name`.
fn method_label(view: &DexView, idx: MethodIdx) -> Result<String, SearchError> {
    let m = view.method(idx).map_err(|source| SearchError::Locator {
        pool: "method_ids",
        source,
    })?;
    let cls_sidx = view.type_(m.class).map_err(|source| SearchError::Locator {
        pool: "type_ids",
        source,
    })?;
    let cls = view
        .string(cls_sidx)
        .map_err(|source| SearchError::Locator {
            pool: "string_ids",
            source,
        })?;
    let name = view.string(m.name).map_err(|source| SearchError::Locator {
        pool: "string_ids",
        source,
    })?;
    Ok(format!("{}->{}", cls.decode_lossy(), name.decode_lossy()))
}

/// One method-scoped callee scan: the distinct invoked methods plus
/// whether every relevant code body was scanned to completion.
#[derive(Debug)]
pub struct CalleesReport {
    /// Distinct invoked methods, first-encounter order.
    pub callees: Vec<Callee>,
    /// Every failure met while locating the class or walking its
    /// bodies (code item, walker, or method-label resolution).
    pub errors: Vec<SearchError>,
    /// `true` iff every relevant code body was scanned to completion.
    pub complete: bool,
}

/// Collect the distinct methods invoked by every code-bearing
/// overload of `class`'s method `method`, in first-encounter order
/// (stable for a given DEX).
///
/// An empty `callees` with `complete == true` means the class exists
/// but no overload has code (abstract / native). A missing/undecodable
/// class is reported as [`SearchError::Locator`] with `complete ==
/// false` (see [`CalleesReport`]).
pub fn callees_of(view: &DexView, class: &str, method: &str) -> CalleesReport {
    let mut errors: Vec<SearchError> = Vec::new();
    let mut complete = true;
    let Some(code_offs) =
        crate::class_code::code_offs_of(view, class, Some(method), &mut errors, &mut complete)
    else {
        errors.push(SearchError::Locator {
            pool: "class_defs",
            source: asc_dex::error::DexError::Malformed("class not defined in this DEX"),
        });
        return CalleesReport {
            callees: Vec::new(),
            errors,
            complete: false,
        };
    };
    let callees = collect_callees(view, &code_offs, &mut errors, &mut complete);
    CalleesReport {
        callees,
        errors,
        complete,
    }
}

/// Walk every body in `code_offs` and tally the distinct invoked methods.
fn collect_callees(
    view: &DexView,
    code_offs: &[u32],
    errors: &mut Vec<SearchError>,
    complete: &mut bool,
) -> Vec<Callee> {
    let mut out: Vec<Callee> = Vec::new();
    // Dedup index (see `strings_of`: the linear scan was O(distinct²)).
    let mut seen: HashMap<String, usize> = HashMap::new();
    for &code_off in code_offs {
        let ci = match view.code_item(code_off) {
            Ok(Some(ci)) => ci,
            Ok(None) => {
                errors.push(SearchError::Code {
                    code_off,
                    source: asc_dex::error::DexError::Malformed(
                        "code_off resolved to no code_item",
                    ),
                });
                *complete = false;
                continue;
            }
            Err(source) => {
                errors.push(SearchError::Code { code_off, source });
                *complete = false;
                continue;
            }
        };
        let insns = ci.insns_exact();
        let mut walker = match RefWalker::new(insns, ci.insns_size) {
            Ok(walker) => walker,
            Err(source) => {
                errors.push(SearchError::WalkerInit { code_off, source });
                *complete = false;
                continue;
            }
        };
        for step in walker.by_ref() {
            let insn = match step {
                Ok(insn) => insn,
                Err(source) => {
                    errors.push(SearchError::Walker {
                        code_off,
                        insn_offset: crate::scan::insn_offset_of(&source),
                        source,
                    });
                    *complete = false;
                    break;
                }
            };
            for r in [insn.primary, insn.secondary].into_iter().flatten() {
                let DexRef::Method(idx) = r else { continue };
                match method_label(view, idx) {
                    Ok(label) => match seen.get(&label).copied() {
                        Some(slot) => out[slot].sites += 1,
                        None => {
                            seen.insert(label.clone(), out.len());
                            out.push(Callee {
                                target: label,
                                sites: 1,
                            });
                        }
                    },
                    Err(e) => {
                        errors.push(e);
                        *complete = false;
                    }
                }
            }
        }
    }
    out
}
