//! `asc-rs resources`: read-only view of `resources.arsc` (package/type
//! inventory, lookup by resource ID, substring search over key names and
//! string values). Nothing here interprets or resolves resources beyond
//! what the table states; unresolved references keep their raw ID.

use std::fmt::Write as _;
use std::path::Path;

use asc_apk::{Apk, InflateLimits};
use asc_resources::{Entry, Package, Res, Table, Value, describe_config};
use serde::Serialize;

use crate::pipeline::CoreError;

const ARSC_CAP: usize = 256 << 20;
/// Bag items rendered per hit.
const BAG_PREVIEW: usize = 8;
/// Characters of a value shown in text output.
const TEXT_VALUE_CHARS: usize = 300;

#[derive(Debug, Clone)]
pub struct ResourcesQuery {
    /// Only this resource ID (every config variant is listed).
    pub id: Option<u32>,
    /// Case-sensitive substring over key names and string values.
    pub pattern: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypeCount {
    pub name: String,
    pub entries: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageSummary {
    pub id: u32,
    pub name: String,
    pub type_id_offset: u32,
    pub entries: usize,
    pub configs: usize,
    pub types: Vec<TypeCount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceHit {
    pub id: String,
    pub package: String,
    pub type_name: String,
    pub key: String,
    pub config: String,
    /// `id`, `key` or `value`: what matched.
    pub matched: &'static str,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourcesReport {
    pub input: String,
    /// `false` when the APK has no `resources.arsc` entry.
    pub arsc_present: bool,
    pub global_strings: usize,
    pub packages: Vec<PackageSummary>,
    pub total_matches: usize,
    pub truncated: bool,
    pub hits: Vec<ResourceHit>,
    pub skipped_chunks: usize,
    pub diagnostics: Vec<String>,
    pub complete: bool,
}

fn string_of(t: &Table, r: Res) -> Option<&str> {
    (r.data_type == 0x03)
        .then(|| t.strings.get(r.data as usize))
        .flatten()
        .map(String::as_str)
}

fn value_matches(t: &Table, e: &Entry, pat: &str) -> bool {
    match &e.value {
        Value::Simple(r) => string_of(t, *r).is_some_and(|s| s.contains(pat)),
        Value::Bag { items, .. } => items
            .iter()
            .any(|(_, r)| string_of(t, *r).is_some_and(|s| s.contains(pat))),
    }
}

fn render_value(t: &Table, e: &Entry) -> String {
    match &e.value {
        Value::Simple(r) => t.render(*r),
        Value::Bag { parent, items } => {
            let mut s = format!("bag parent=@0x{parent:08x} [");
            for (i, (name, r)) in items.iter().take(BAG_PREVIEW).enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                let _ = write!(s, "@0x{name:08x}={}", t.render(*r));
            }
            if items.len() > BAG_PREVIEW {
                let _ = write!(s, ", … {} more", items.len() - BAG_PREVIEW);
            }
            s.push(']');
            s
        }
    }
}

fn hit(t: &Table, p: &Package, e: &Entry, matched: &'static str) -> ResourceHit {
    ResourceHit {
        id: format!("0x{:08x}", e.id),
        package: p.name.clone(),
        type_name: p.type_name(e.type_id),
        key: p.key_name(e).to_string(),
        config: describe_config(&p.configs[e.config as usize]),
        matched,
        value: render_value(t, e),
    }
}

fn summarize(p: &Package) -> PackageSummary {
    let mut types: Vec<TypeCount> = Vec::new();
    for e in &p.entries {
        let name = p.type_name(e.type_id);
        match types.iter_mut().find(|t| t.name == name) {
            Some(t) => t.entries += 1,
            None => types.push(TypeCount { name, entries: 1 }),
        }
    }
    PackageSummary {
        id: p.id,
        name: p.name.clone(),
        type_id_offset: p.type_id_offset,
        entries: p.entries.len(),
        configs: p.configs.len(),
        types,
    }
}

pub fn run_resources(path: &Path, q: &ResourcesQuery) -> Result<ResourcesReport, CoreError> {
    let apk = Apk::open(path)?;
    if apk.is_raw_dex() {
        return Err(CoreError::Usage(
            "input is a raw DEX; 'resources' requires an APK".into(),
        ));
    }
    let mut rep = ResourcesReport {
        input: path.display().to_string(),
        arsc_present: false,
        global_strings: 0,
        packages: Vec::new(),
        total_matches: 0,
        truncated: false,
        hits: Vec::new(),
        skipped_chunks: 0,
        diagnostics: Vec::new(),
        complete: true,
    };
    let Some(entry) = apk.entry("resources.arsc") else {
        return Ok(rep);
    };
    rep.arsc_present = true;
    let limits = InflateLimits::with_max_output(ARSC_CAP).unwrap_or_default();
    let bytes = apk.read_entry_with_limits(&entry, limits)?;
    let table = asc_resources::parse(bytes.as_slice())
        .map_err(|e| CoreError::Usage(format!("resources.arsc: {e}")))?;

    rep.global_strings = table.strings.len();
    rep.packages = table.packages.iter().map(summarize).collect();
    rep.skipped_chunks = table.skipped_chunks;
    rep.diagnostics = table.diagnostics.clone();
    rep.complete = table.complete;

    let filtered = q.id.is_some() || q.pattern.is_some();
    if filtered {
        for p in &table.packages {
            for e in &p.entries {
                let matched = match (q.id, &q.pattern) {
                    (Some(id), _) => (e.id == id).then_some("id"),
                    (None, Some(pat)) if p.key_name(e).contains(pat.as_str()) => Some("key"),
                    (None, Some(pat)) if value_matches(&table, e, pat) => Some("value"),
                    _ => None,
                };
                let Some(m) = matched else { continue };
                rep.total_matches += 1;
                if rep.hits.len() < q.limit {
                    rep.hits.push(hit(&table, p, e, m));
                } else {
                    rep.truncated = true;
                }
            }
        }
    }
    Ok(rep)
}

pub fn format_resources_text(r: &ResourcesReport, filtered: bool) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "input: {}", r.input);
    if !r.arsc_present {
        s.push_str("resources.arsc: no such entry in this APK\n");
        return s;
    }
    let _ = writeln!(s, "global strings: {}", r.global_strings);
    for p in &r.packages {
        let _ = writeln!(
            s,
            "package 0x{:02x} {:?}: {} entries, {} configs, typeIdOffset {}",
            p.id, p.name, p.entries, p.configs, p.type_id_offset
        );
        for t in &p.types {
            let _ = writeln!(s, "  {}: {}", t.name, t.entries);
        }
    }
    if filtered {
        let _ = writeln!(s, "matches: {}", r.total_matches);
        for h in &r.hits {
            let v: String = h.value.chars().take(TEXT_VALUE_CHARS).collect();
            let cut = if h.value.chars().count() > TEXT_VALUE_CHARS {
                "…"
            } else {
                ""
            };
            let _ = writeln!(
                s,
                "{} {}/{} [{}] ({}) = {v}{cut}",
                h.id, h.type_name, h.key, h.config, h.matched
            );
        }
        if r.truncated {
            let _ = writeln!(
                s,
                "… truncated at {} of {} matches",
                r.hits.len(),
                r.total_matches
            );
        }
    }
    if r.skipped_chunks > 0 {
        let _ = writeln!(s, "skipped unknown chunks: {}", r.skipped_chunks);
    }
    for d in &r.diagnostics {
        let _ = writeln!(s, "diagnostic: {d}");
    }
    if !r.complete {
        s.push_str("INCOMPLETE: some structures were malformed and skipped\n");
    }
    s
}
