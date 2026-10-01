//! One-hop callee discovery: which methods does `C.m` invoke?
//!
//! This is the fan-out half of a call graph. The fan-in half (who
//! calls `C.m`) is already covered by `find_refs` with a
//! method-scoped query; this module answers the opposite direction
//! by walking only the code bodies of `C.m`'s overloads with a
//! [`RefWalker`] — no global xref table, bounded to one class.

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

/// Collect the distinct methods invoked by every code-bearing
/// overload of `class`'s method `method`, in first-encounter order
/// (stable for a given DEX).
///
/// `Ok(Vec::new())` when the class exists but no overload has code
/// (abstract / native). `Err(SearchError::Locator { pool: "class_defs" })`
/// when the class is not defined in `view`.
pub fn callees_of(view: &DexView, class: &str, method: &str) -> Result<Vec<Callee>, SearchError> {
    let mut code_offs: Vec<u32> = Vec::new();
    let mut found_class = false;
    for i in 0..view.class_def_count() {
        let def = view.class_def(i).map_err(|source| SearchError::Locator {
            pool: "class_defs",
            source,
        })?;
        let cls_sidx = view
            .type_(def.class)
            .map_err(|source| SearchError::Locator {
                pool: "type_ids",
                source,
            })?;
        let desc = view
            .string(cls_sidx)
            .map_err(|source| SearchError::Locator {
                pool: "string_ids",
                source,
            })?;
        if desc.decode_lossy() != class {
            continue;
        }
        found_class = true;
        if def.class_data_off == 0 {
            continue;
        }
        let Some(data) =
            view.class_data(def.class_data_off)
                .map_err(|source| SearchError::Locator {
                    pool: "class_data",
                    source,
                })?
        else {
            continue;
        };
        for em in data
            .direct_methods
            .iter()
            .chain(data.virtual_methods.iter())
        {
            if em.code_off == 0 {
                continue; // abstract / native
            }
            let m = view
                .method(em.method_idx)
                .map_err(|source| SearchError::Locator {
                    pool: "method_ids",
                    source,
                })?;
            let name = view.string(m.name).map_err(|source| SearchError::Locator {
                pool: "string_ids",
                source,
            })?;
            if name.decode_lossy() == method {
                code_offs.push(em.code_off);
            }
        }
        // The descriptor is unique in class_defs; stop early.
        break;
    }
    if !found_class {
        return Err(SearchError::Locator {
            pool: "class_defs",
            source: asc_dex::error::DexError::Malformed("class not defined in this DEX"),
        });
    }

    let mut out: Vec<Callee> = Vec::new();
    for code_off in code_offs {
        let Some(ci) = view
            .code_item(code_off)
            .map_err(|source| SearchError::Code { code_off, source })?
        else {
            continue;
        };
        let insns = ci.insns_exact();
        let mut walker = RefWalker::new(insns, ci.insns_size)
            .map_err(|source| SearchError::WalkerInit { code_off, source })?;
        for step in walker.by_ref() {
            let Ok(insn) = step else { break }; // partial: keep prior hits
            for r in [insn.primary, insn.secondary].into_iter().flatten() {
                if let DexRef::Method(idx) = r
                    && let Ok(label) = method_label(view, idx)
                {
                    match out.iter_mut().find(|c| c.target == label) {
                        Some(c) => c.sites += 1,
                        None => out.push(Callee {
                            target: label,
                            sites: 1,
                        }),
                    }
                }
            }
        }
    }
    Ok(out)
}
