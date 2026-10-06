//! Class-scoped string inventory: which string literals does a class's
//! own code load? Complements `find_refs` (string fan-in, whole DEX)
//! with the one-class fan-out, bounded to that class's code items —
//! no global xref table.
//!
//! ## Completeness (same contract as `find_refs`)
//!
//! A body that fails mid-walk keeps the strings gathered so far, the
//! failure is recorded in [`ClassStringsReport::errors`], and
//! `complete` flips to `false`. `complete == true` with an empty
//! `errors` is the only report a caller may treat as total — a partial
//! scan must never be presented as complete (audit P1).

use std::collections::HashMap;

use asc_bytecode::{DexRef, RefWalker};
use asc_dex::view::DexView;

use crate::error::SearchError;

/// One distinct string constant referenced by the scanned class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassString {
    /// Decoded string value.
    pub text: String,
    /// Number of reference sites loading it inside the scanned
    /// bodies (all methods of the class are merged).
    pub sites: usize,
}

/// One class-scoped string scan: the distinct constants plus whether
/// every relevant code body was scanned to completion.
#[derive(Debug)]
pub struct ClassStringsReport {
    /// Distinct string constants, first-encounter order.
    pub strings: Vec<ClassString>,
    /// Every failure met while locating the class or walking its
    /// bodies (code item, walker, or string-ref resolution).
    pub errors: Vec<SearchError>,
    /// `true` iff every relevant code body was scanned to completion.
    pub complete: bool,
}

/// Collect the distinct string constants referenced by every
/// code-bearing method of `class`, in first-encounter order (stable
/// for a given DEX).
///
/// An empty `strings` with `complete == true` means the class exists
/// but has no code (or loads no strings). A missing/undecodable class
/// is reported as [`SearchError::Locator`] with `complete == false`
/// (see [`ClassStringsReport`]).
pub fn strings_of_class(view: &DexView, class: &str) -> ClassStringsReport {
    let mut errors: Vec<SearchError> = Vec::new();
    let mut complete = true;
    let mut code_offs: Vec<u32> = Vec::new();
    let mut found_class = false;
    for i in 0..view.class_def_count() {
        let def = match view.class_def(i) {
            Ok(def) => def,
            Err(source) => {
                errors.push(SearchError::Locator {
                    pool: "class_defs",
                    source,
                });
                complete = false;
                continue;
            }
        };
        let cls_sidx = match view.type_(def.class) {
            Ok(sidx) => sidx,
            Err(source) => {
                errors.push(SearchError::Locator {
                    pool: "type_ids",
                    source,
                });
                complete = false;
                continue;
            }
        };
        let desc = match view.string(cls_sidx) {
            Ok(desc) => desc,
            Err(source) => {
                errors.push(SearchError::Locator {
                    pool: "string_ids",
                    source,
                });
                complete = false;
                continue;
            }
        };
        if desc.decode_lossy() != class {
            continue;
        }
        found_class = true;
        if def.class_data_off != 0 {
            match view.class_data(def.class_data_off) {
                Ok(Some(data)) => {
                    for em in data
                        .direct_methods
                        .iter()
                        .chain(data.virtual_methods.iter())
                    {
                        if em.code_off != 0 {
                            code_offs.push(em.code_off);
                        }
                    }
                }
                Ok(None) => {}
                Err(source) => {
                    errors.push(SearchError::Locator {
                        pool: "class_data",
                        source,
                    });
                    complete = false;
                }
            }
        }
        // The descriptor is unique in class_defs; stop early.
        break;
    }
    if !found_class {
        errors.push(SearchError::Locator {
            pool: "class_defs",
            source: asc_dex::error::DexError::Malformed("class not defined in this DEX"),
        });
        return ClassStringsReport {
            strings: Vec::new(),
            errors,
            complete: false,
        };
    }

    let mut out: Vec<ClassString> = Vec::new();
    // Dedup index: first-encounter order lives in `out`, the map only
    // answers "seen already, and at which slot". A linear
    // `out.iter().find` here was O(distinct²) for string-heavy classes.
    let mut seen: HashMap<String, usize> = HashMap::new();
    for code_off in code_offs {
        let ci = match view.code_item(code_off) {
            Ok(Some(ci)) => ci,
            Ok(None) => {
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
            Ok(walker) => walker,
            Err(source) => {
                errors.push(SearchError::WalkerInit { code_off, source });
                complete = false;
                continue;
            }
        };
        for step in walker.by_ref() {
            let insn = match step {
                Ok(insn) => insn,
                Err(source) => {
                    // Partial: keep the strings gathered so far, mark the
                    // report incomplete, and move to the next body.
                    errors.push(SearchError::Walker {
                        code_off,
                        insn_offset: crate::scan::insn_offset_of(&source),
                        source,
                    });
                    complete = false;
                    break;
                }
            };
            for r in [insn.primary, insn.secondary].into_iter().flatten() {
                if let DexRef::String(idx) = r {
                    match view.string(idx) {
                        Ok(s) => {
                            let text = s.decode_lossy().into_owned();
                            match seen.get(&text).copied() {
                                Some(slot) => out[slot].sites += 1,
                                None => {
                                    seen.insert(text.clone(), out.len());
                                    out.push(ClassString { text, sites: 1 });
                                }
                            }
                        }
                        Err(source) => {
                            errors.push(SearchError::StringRef {
                                code_off,
                                insn_offset: insn.offset,
                                index: idx.0,
                                source,
                            });
                            complete = false;
                        }
                    }
                }
            }
        }
    }
    ClassStringsReport {
        strings: out,
        errors,
        complete,
    }
}
