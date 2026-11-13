//! Shared class lookup for the one-class fan-out scans
//! ([`crate::strings_of`], [`crate::callees`]): resolve `class` in the
//! `class_defs` list and collect the `code_off`s of the bodies to walk.
//!
//! `None` means the class has no definition in this DEX — the caller
//! reports that as a locator failure and returns `complete = false`.
//! `Some(vec![])` is different: the class exists but carries no code
//! (abstract / native, or no code-bearing overload of `method`).

use std::borrow::Cow;

use asc_dex::view::DexView;

use crate::error::SearchError;

/// Collect the `code_off`s of `class`'s code-bearing method overloads,
/// or of all its code-bearing methods when `method` is `None`.
///
/// `errors`/`complete` follow the report contract of the callers: every
/// pool failure is recorded and marks the scan incomplete.
pub(crate) fn code_offs_of(
    view: &DexView,
    class: &str,
    method: Option<&str>,
    errors: &mut Vec<SearchError>,
    complete: &mut bool,
) -> Option<Vec<u32>> {
    for i in 0..view.class_def_count() {
        let def = match view.class_def(i) {
            Ok(def) => def,
            Err(source) => {
                errors.push(SearchError::Locator {
                    pool: "class_defs",
                    source,
                });
                *complete = false;
                continue;
            }
        };
        let Some(desc) = descriptor_of(view, def.class, errors, complete) else {
            continue;
        };
        if desc.as_ref() != class {
            continue;
        }
        // The descriptor is unique in class_defs; stop early.
        return Some(match def.class_data_off {
            0 => Vec::new(),
            off => method_code_offs(view, off, method, errors, complete),
        });
    }
    None
}

/// Descriptor of `def_class`, recording a locator failure.
fn descriptor_of<'a>(
    view: &'a DexView,
    def_class: asc_dex::ids::TypeIdx,
    errors: &mut Vec<SearchError>,
    complete: &mut bool,
) -> Option<Cow<'a, str>> {
    let sidx = match view.type_(def_class) {
        Ok(sidx) => sidx,
        Err(source) => {
            errors.push(SearchError::Locator {
                pool: "type_ids",
                source,
            });
            *complete = false;
            return None;
        }
    };
    match view.string(sidx) {
        Ok(desc) => Some(desc.decode_lossy()),
        Err(source) => {
            errors.push(SearchError::Locator {
                pool: "string_ids",
                source,
            });
            *complete = false;
            None
        }
    }
}

/// Collect `code_off`s from one class_data, honouring the `method` filter.
fn method_code_offs(
    view: &DexView,
    class_data_off: u32,
    method: Option<&str>,
    errors: &mut Vec<SearchError>,
    complete: &mut bool,
) -> Vec<u32> {
    let data = match view.class_data(class_data_off) {
        Ok(Some(data)) => data,
        Ok(None) => return Vec::new(),
        Err(source) => {
            errors.push(SearchError::Locator {
                pool: "class_data",
                source,
            });
            *complete = false;
            return Vec::new();
        }
    };
    let mut code_offs = Vec::new();
    for em in data
        .direct_methods
        .iter()
        .chain(data.virtual_methods.iter())
    {
        if em.code_off == 0 {
            continue; // abstract / native
        }
        let Some(method) = method else {
            code_offs.push(em.code_off);
            continue;
        };
        let m = match view.method(em.method_idx) {
            Ok(m) => m,
            Err(source) => {
                errors.push(SearchError::Locator {
                    pool: "method_ids",
                    source,
                });
                *complete = false;
                continue;
            }
        };
        match view.string(m.name) {
            Ok(name) => {
                if name.decode_lossy() == method {
                    code_offs.push(em.code_off);
                }
            }
            Err(source) => {
                errors.push(SearchError::Locator {
                    pool: "string_ids",
                    source,
                });
                *complete = false;
            }
        }
    }
    code_offs
}
