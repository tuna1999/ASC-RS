//! Class-definition queries that need no bytecode scan: `findrefs
//! extends|impl` (who subclasses / implements a type) and `listmethod`
//! (every method a class defines).
//!
//! Both read only `class_def` rows, `type_list`s and `class_data`, over
//! the same DEX walk as `strings` ([`for_each_dex_view`]). A malformed
//! row is reported and skipped; it never ends the walk.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::rc::Rc;

use asc_dex::DexView;
use asc_dex::ids::{StringIdx, TypeIdx};
use serde::Serialize;

use crate::pipeline::CoreError;
use crate::strings::{DexScan, for_each_dex_view};

/// Per-report cap on recorded error lines (the count is not capped).
const MAX_ERRORS: usize = 100;

const BUDGET_EXHAUSTED: &str =
    "work budget exhausted (lists shared across classes?); rest of this DEX skipped";

/// Per-DEX work allowance: entries visited (class rows, interface-list
/// entries, class_data methods) may not exceed the DEX's byte size. A
/// legitimate DEX stays far below it (every class_def costs 32 bytes,
/// every class_data method at least 3); a hostile one that points many
/// rows at one shared type_list or class_data runs out and is reported
/// incomplete instead of buying unbounded work.
struct Budget(usize);

impl Budget {
    fn for_view(view: &DexView<'_>) -> Self {
        Self(view.physical().len())
    }
    fn take(&mut self, n: usize) -> Result<(), String> {
        self.0 = self
            .0
            .checked_sub(n)
            .ok_or_else(|| BUDGET_EXHAUSTED.to_string())?;
        Ok(())
    }
}

/// Decodes each descriptor string once per DEX and shares it.
#[derive(Default)]
struct Descs(HashMap<StringIdx, Rc<str>>);

impl Descs {
    fn get(&mut self, view: &DexView<'_>, idx: TypeIdx) -> Result<Rc<str>, String> {
        let s = view.type_(idx).map_err(|e| e.to_string())?;
        if let Some(d) = self.0.get(&s) {
            return Ok(d.clone());
        }
        let d: Rc<str> = view
            .string(s)
            .map_err(|e| e.to_string())?
            .decode_lossy()
            .into();
        self.0.insert(s, d.clone());
        Ok(d)
    }
}

/// Shared error bookkeeping of both reports.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Issues {
    /// Problems found while scanning (first [`MAX_ERRORS`] only).
    pub errors: Vec<String>,
    /// False when a DEX or a class row could not be read: the result is
    /// then a subset of the real answer.
    pub complete: bool,
}

impl Issues {
    fn new() -> Self {
        Self {
            errors: Vec::new(),
            complete: true,
        }
    }
    fn push(&mut self, failed: bool, msg: String) {
        if failed {
            self.complete = false;
        }
        if self.errors.len() < MAX_ERRORS {
            self.errors.push(msg);
        }
    }
    fn scan(&mut self, name: &str, s: &DexScan<'_, '_>) {
        match s {
            DexScan::View(_) => {}
            DexScan::Skipped(why) => self.push(false, format!("{name}: {why}")),
            DexScan::Failed(why) => self.push(true, format!("{name}: {why}")),
        }
    }
}

/// `findrefs extends` or `findrefs impl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HierarchyKind {
    /// Classes whose superclass is the target.
    Extends,
    /// Classes (and interfaces) listing the target among their interfaces.
    Impl,
}

#[derive(Debug, Clone, Serialize)]
pub struct HierarchyHit {
    /// Logical DEX that defines the class.
    pub dex: String,
    pub class: String,
    /// 1 = names the target directly; deeper only with `transitive`.
    pub depth: u32,
    /// The superclass / interface that links this class into the result
    /// (the target itself at depth 1).
    pub via: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HierarchyReport {
    pub kind: HierarchyKind,
    pub target: String,
    pub transitive: bool,
    pub hits: Vec<HierarchyHit>,
    #[serde(flatten)]
    pub issues: Issues,
}

struct ClassRow {
    dex: Rc<str>,
    class: Rc<str>,
    superclass: Option<Rc<str>>,
    interfaces: Vec<Rc<str>>,
}

/// Classes that extend (`Extends`) or implement (`Impl`) `target`, an
/// `L…;` descriptor, across every DEX. Matching is exact on the
/// descriptor. With `transitive`, the walk continues through the result:
/// `Extends` follows subclasses of subclasses; `Impl` also follows
/// sub-interfaces and subclasses of implementors (anything assignable to
/// the interface that is defined in the APK). Breadth-first, so each
/// class appears once at its shortest depth; DEX order within a depth.
pub fn run_hierarchy(
    path: &Path,
    target: &str,
    kind: HierarchyKind,
    transitive: bool,
) -> Result<HierarchyReport, CoreError> {
    let apk = asc_apk::Apk::open(path)?;
    let mut issues = Issues::new();
    let mut rows: Vec<ClassRow> = Vec::new();
    for_each_dex_view(&apk, |name, scan| {
        issues.scan(name, &scan);
        let DexScan::View(view) = scan else { return };
        let dex: Rc<str> = name.into();
        let mut descs = Descs::default();
        let mut budget = Budget::for_view(view);
        for i in 0..view.class_def_count() {
            let row = (|| -> Result<ClassRow, String> {
                let def = view.class_def(i).map_err(|e| e.to_string())?;
                let list = view.class_interfaces(&def).map_err(|e| e.to_string())?;
                budget.take(1 + list.as_ref().map_or(0, |l| l.len()))?;
                let interfaces = match list {
                    Some(list) => list
                        .iter()
                        .map(|t| descs.get(view, t))
                        .collect::<Result<_, _>>()?,
                    None => Vec::new(),
                };
                Ok(ClassRow {
                    dex: dex.clone(),
                    class: descs.get(view, def.class)?,
                    superclass: def.superclass.map(|t| descs.get(view, t)).transpose()?,
                    interfaces,
                })
            })();
            match row {
                Ok(r) => rows.push(r),
                Err(e) => {
                    issues.push(true, format!("{name}: class_def #{i}: {e}"));
                    if e == BUDGET_EXHAUSTED {
                        break;
                    }
                }
            }
        }
    });

    Ok(HierarchyReport {
        kind,
        target: target.to_string(),
        transitive,
        hits: walk(&rows, target, kind, transitive),
        issues,
    })
}

/// Breadth-first walk of `rows` from `target` (see [`run_hierarchy`]).
fn walk(
    rows: &[ClassRow],
    target: &str,
    kind: HierarchyKind,
    transitive: bool,
) -> Vec<HierarchyHit> {
    // parent descriptor -> rows that name it (superclass edges, plus
    // interface edges for `Impl`).
    let mut children: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, r) in rows.iter().enumerate() {
        let sup = r.superclass.as_deref().filter(|_| {
            // A direct `impl` hit must name the interface; superclass
            // edges only carry the walk past depth 1.
            kind == HierarchyKind::Extends || transitive
        });
        let ifaces = r
            .interfaces
            .iter()
            .map(|s| &**s)
            .filter(|_| kind == HierarchyKind::Impl);
        let mut parents: Vec<&str> = sup.into_iter().chain(ifaces).collect();
        parents.sort_unstable();
        parents.dedup();
        for p in parents {
            children.entry(p).or_default().push(i);
        }
    }

    let mut hits = Vec::new();
    let mut seen: HashSet<usize> = HashSet::new();
    let mut queue: VecDeque<(&str, u32)> = VecDeque::from([(target, 1)]);
    while let Some((parent, depth)) = queue.pop_front() {
        for &i in children.get(parent).into_iter().flatten() {
            let r = &rows[i];
            // Depth 1 of `impl`: superclass edges are never direct hits.
            if depth == 1
                && kind == HierarchyKind::Impl
                && !r.interfaces.iter().any(|x| &**x == parent)
            {
                continue;
            }
            if !seen.insert(i) {
                continue;
            }
            hits.push(HierarchyHit {
                dex: r.dex.to_string(),
                class: r.class.to_string(),
                depth,
                via: parent.to_string(),
            });
            if transitive {
                queue.push_back((&r.class, depth + 1));
            }
        }
    }
    hits
}

/// `<dex> | <class>` per hit; deeper hits add `    # via <parent>`.
pub fn format_hierarchy_text(r: &HierarchyReport) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for h in &r.hits {
        if h.depth > 1 {
            let _ = writeln!(s, "{} | {}    # via {}", h.dex, h.class, h.via);
        } else {
            let _ = writeln!(s, "{} | {}", h.dex, h.class);
        }
    }
    s
}

#[derive(Debug, Clone, Serialize)]
pub struct MethodHit {
    pub dex: String,
    pub class: String,
    pub name: String,
    /// `(params)return`, e.g. `(Landroid/os/Bundle;)V`.
    pub proto: String,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct MethodsReport {
    pub methods: Vec<MethodHit>,
    /// Matches found, ignoring the limit.
    pub total_matched: usize,
    pub truncated: bool,
    /// With a class filter: whether any DEX defines that class.
    #[serde(skip)]
    pub class_found: bool,
    #[serde(flatten)]
    pub issues: Issues,
}

/// Every method *defined* (class_data, direct then virtual, declaration
/// order) by classes across the APK, in DEX / class_def order. `class`
/// keeps one exact `L…;` descriptor; `name` is a case-insensitive
/// substring of the method name. At most `limit` hits are returned.
pub fn run_listmethods(
    path: &Path,
    class: Option<&str>,
    name: Option<&str>,
    limit: usize,
) -> Result<MethodsReport, CoreError> {
    let apk = asc_apk::Apk::open(path)?;
    let needle = name.map(str::to_lowercase);
    let mut issues = Issues::new();
    let mut methods = Vec::new();
    let mut total = 0usize;
    let mut class_found = false;
    for_each_dex_view(&apk, |dex, scan| {
        issues.scan(dex, &scan);
        let DexScan::View(view) = scan else { return };
        let mut budget = Budget::for_view(view);
        let mut descs = Descs::default();
        // Name-filter verdict per name string: a hostile DEX cannot make
        // one long name be decoded once per method.
        let mut name_ok: HashMap<StringIdx, bool> = HashMap::new();
        for i in 0..view.class_def_count() {
            let res = (|| -> Result<(), String> {
                budget.take(1)?;
                let e = |e: asc_dex::DexError| e.to_string();
                let def = view.class_def(i).map_err(e)?;
                let cls = descs.get(view, def.class)?;
                if class.is_some_and(|c| c != &*cls) {
                    return Ok(());
                }
                class_found = true;
                let Some(data) = view.class_data(def.class_data_off).map_err(e)? else {
                    return Ok(());
                };
                budget.take(data.direct_methods.len() + data.virtual_methods.len())?;
                for m in data.direct_methods.iter().chain(&data.virtual_methods) {
                    let id = view.method(m.method_idx).map_err(e)?;
                    if let Some(n) = needle.as_deref() {
                        let ok = match name_ok.get(&id.name) {
                            Some(&ok) => ok,
                            None => {
                                let s = view.string(id.name).map_err(e)?.decode_lossy();
                                let ok = s.to_lowercase().contains(n);
                                name_ok.insert(id.name, ok);
                                ok
                            }
                        };
                        if !ok {
                            continue;
                        }
                    }
                    total += 1;
                    if methods.len() >= limit {
                        continue;
                    }
                    let mname = view.string(id.name).map_err(e)?.decode_lossy().into_owned();
                    let p = view.proto(id.proto).map_err(e)?;
                    let mut proto = String::from("(");
                    for t in p.parameters.iter() {
                        proto.push_str(&descs.get(view, t)?);
                    }
                    proto.push(')');
                    proto.push_str(&descs.get(view, p.return_type)?);
                    methods.push(MethodHit {
                        dex: dex.to_string(),
                        class: cls.to_string(),
                        name: mname,
                        proto,
                        flags: m.access_flags,
                    });
                }
                Ok(())
            })();
            if let Err(e) = res {
                issues.push(true, format!("{dex}: class_def #{i}: {e}"));
                if e == BUDGET_EXHAUSTED {
                    break;
                }
            }
        }
    });
    Ok(MethodsReport {
        truncated: total > methods.len(),
        methods,
        total_matched: total,
        class_found,
        issues,
    })
}

/// One `Lcls;->name(params)ret` line per method.
pub fn format_methods_text(r: &MethodsReport) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for m in &r.methods {
        let _ = writeln!(s, "{}->{}{}", m.class, m.name, m.proto);
    }
    if r.truncated {
        let _ = writeln!(
            s,
            "... truncated: {} matches, limit {} (raise --limit or filter with --class/--name)",
            r.total_matched,
            r.methods.len()
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(class: &str, sup: &str, ifaces: &[&str]) -> ClassRow {
        ClassRow {
            dex: "classes.dex".into(),
            class: class.into(),
            superclass: Some(sup.into()),
            interfaces: ifaces.iter().map(|&s| s.into()).collect(),
        }
    }

    fn names(h: &[HierarchyHit]) -> Vec<(&str, u32, &str)> {
        h.iter()
            .map(|h| (h.class.as_str(), h.depth, h.via.as_str()))
            .collect()
    }

    #[test]
    fn walk_follows_the_requested_edges() {
        const O: &str = "Ljava/lang/Object;";
        let rows = [
            row("LA;", "LBase;", &[]),
            row("LB;", "LA;", &["LI;"]),
            row("LC;", "LB;", &[]),
            row("LI;", O, &[]),
            row("LJ;", O, &["LI;"]), // sub-interface
            row("LK;", O, &["LJ;"]),
            row("LLoop1;", "LLoop2;", &[]), // hostile cycle
            row("LLoop2;", "LLoop1;", &[]),
        ];
        let w = |t, k, tr| {
            names(&walk(&rows, t, k, tr))
                .into_iter()
                .map(|(a, b, c)| (a.to_string(), b, c.to_string()))
                .collect::<Vec<_>>()
        };
        let v = |x: &[(&str, u32, &str)]| {
            x.iter()
                .map(|(a, b, c)| (a.to_string(), *b, c.to_string()))
                .collect::<Vec<_>>()
        };
        use HierarchyKind::*;
        assert_eq!(w("LBase;", Extends, false), v(&[("LA;", 1, "LBase;")]));
        assert_eq!(
            w("LBase;", Extends, true),
            v(&[("LA;", 1, "LBase;"), ("LB;", 2, "LA;"), ("LC;", 3, "LB;")])
        );
        // Direct impl: only classes naming the interface, never a subclass.
        assert_eq!(
            w("LI;", Impl, false),
            v(&[("LB;", 1, "LI;"), ("LJ;", 1, "LI;")])
        );
        assert_eq!(
            w("LI;", Impl, true),
            v(&[
                ("LB;", 1, "LI;"),
                ("LJ;", 1, "LI;"),
                ("LC;", 2, "LB;"),
                ("LK;", 2, "LJ;")
            ])
        );
        // A superclass cycle terminates and lists each class once.
        assert_eq!(
            w("LLoop1;", Extends, true),
            v(&[("LLoop2;", 1, "LLoop1;"), ("LLoop1;", 2, "LLoop2;")])
        );
        assert!(w("LNope;", Extends, true).is_empty());
    }
}
