//! Class-scoped string inventory: which string literals does a class's
//! own code load? Complements `find_refs` (string fan-in, whole DEX)
//! with the one-class fan-out, bounded to that class's code items —
//! no global xref table.

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

/// Collect the distinct string constants referenced by every
/// code-bearing method of `class`, in first-encounter order (stable
/// for a given DEX).
///
/// `Ok(Vec::new())` when the class exists but has no code (or loads
/// no strings). `Err(SearchError::Locator { pool: "class_defs" })`
/// when the class is not defined in `view`.
pub fn strings_of_class(view: &DexView, class: &str) -> Result<Vec<ClassString>, SearchError> {
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
            if em.code_off != 0 {
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

    let mut out: Vec<ClassString> = Vec::new();
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
                if let DexRef::String(idx) = r
                    && let Ok(s) = view.string(idx)
                {
                    let text = s.decode_lossy().into_owned();
                    match out.iter_mut().find(|c| c.text == text) {
                        Some(c) => c.sites += 1,
                        None => out.push(ClassString { text, sites: 1 }),
                    }
                }
            }
        }
    }
    Ok(out)
}
