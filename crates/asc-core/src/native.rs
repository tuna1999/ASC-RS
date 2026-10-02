//! `asc-rs native`: `.so` inventory + DEX native-method inventory, joined
//! by JNI export *name*.
//!
//! A name match is a candidate link, not proof of runtime linkage. Zero
//! matches only means "not bound by name": `RegisterNatives` (dynamic
//! registration) is possible but is neither detected nor resolved here.
//! Libraries stay in memory, one at a time; nothing is written to disk.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;

use asc_apk::elf::{ElfPath, parse_elf};
use asc_apk::{Apk, InflateLimits};
use asc_dex::DexView;
use asc_dex::ids::TypeIdx;
use serde::Serialize;

use crate::pipeline::{CoreError, logical_dex_name};

/// Per-library / per-DEX read cap.
const FILE_CAP: usize = 64 << 20;
const MAX_ERRORS: usize = 100;
const ACC_NATIVE: u32 = 0x100;

#[derive(Debug, Clone, Serialize)]
pub struct ElfSummary {
    pub bits: u8,
    pub endian: &'static str,
    pub machine: u16,
    pub machine_name: &'static str,
    /// `sections`, `dynamic` or `none` (no readable symbol table).
    pub symbol_source: &'static str,
    pub symbols_seen: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct LibInfo {
    pub name: String,
    /// Directory after `lib/` (not trusted over `e_machine`).
    pub abi_dir: Option<String>,
    pub size: u64,
    pub elf: Option<ElfSummary>,
    /// `Some(true)` when `abi_dir` contradicts `e_machine`.
    pub abi_mismatch: Option<bool>,
    pub jni_onload: bool,
    pub jni_onunload: bool,
    pub export_count: usize,
    pub java_export_count: usize,
    /// Native methods whose short/long JNI name this library exports.
    pub matched_methods: usize,
    pub complete: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeMethod {
    pub dex: String,
    pub class: String,
    pub name: String,
    pub params: Vec<String>,
    pub ret: String,
    /// `direct` or `virtual` (class_data list).
    pub kind: &'static str,
    pub access_flags: u32,
    pub code_off: u32,
    pub short_jni: String,
    pub long_jni: String,
    /// Libraries exporting `short_jni` or `long_jni` (candidate link only).
    pub matched_libs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeReport {
    pub input: String,
    pub libs: Vec<LibInfo>,
    pub methods: Vec<NativeMethod>,
    pub direct_count: usize,
    pub virtual_count: usize,
    pub matched_methods: usize,
    pub unbound_methods: usize,
    pub note: Option<String>,
    pub errors: Vec<String>,
    pub complete: bool,
}

/// JNI name escaping (JNI spec, "Resolving Native Method Names"): ASCII
/// alphanumerics kept, `/`→`_`, `_`→`_1`, `;`→`_2`, `[`→`_3`, any other
/// UTF-16 unit → `_0` + 4 lowercase hex digits.
pub fn jni_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for u in s.encode_utf16() {
        match u {
            0x30..=0x39 | 0x41..=0x5A | 0x61..=0x7A => o.push(u as u8 as char),
            0x2F => o.push('_'),
            0x5F => o.push_str("_1"),
            0x3B => o.push_str("_2"),
            0x5B => o.push_str("_3"),
            _ => {
                let _ = write!(o, "_0{u:04x}");
            }
        }
    }
    o
}

/// `(short, long)` JNI symbol names. `class` is a descriptor (`Lp/C;`);
/// `params` are parameter descriptors (return type is not part of either).
pub fn jni_names(class: &str, name: &str, params: &[String]) -> (String, String) {
    let internal = class
        .strip_prefix('L')
        .and_then(|c| c.strip_suffix(';'))
        .unwrap_or(class);
    let short = format!("Java_{}_{}", jni_escape(internal), jni_escape(name));
    let long = format!("{short}__{}", jni_escape(&params.concat()));
    (short, long)
}

fn machine_name(m: u16) -> &'static str {
    match m {
        3 => "x86",
        8 => "mips",
        40 => "arm",
        62 => "x86_64",
        183 => "aarch64",
        243 => "riscv",
        _ => "other",
    }
}

fn abi_machine(abi: &str) -> Option<u16> {
    match abi {
        "armeabi-v7a" | "armeabi" => Some(40),
        "arm64-v8a" => Some(183),
        "x86" => Some(3),
        "x86_64" => Some(62),
        _ => None,
    }
}

fn desc(view: &DexView<'_>, t: TypeIdx) -> Option<String> {
    let s = view.type_(t).ok()?;
    Some(view.string(s).ok()?.decode_lossy().into_owned())
}

/// Native methods of one logical view, direct list then virtual list.
fn walk_view(
    view: &DexView<'_>,
    dex: &str,
    out: &mut Vec<NativeMethod>,
    err: &mut impl FnMut(String),
) -> bool {
    let mut complete = true;
    for i in 0..view.class_def_count() {
        let Ok(def) = view.class_def(i) else {
            err(format!("{dex}: class_def {i} unreadable"));
            complete = false;
            continue;
        };
        if def.class_data_off == 0 {
            continue;
        }
        let data = match view.class_data(def.class_data_off) {
            Ok(Some(d)) => d,
            Ok(None) => continue,
            Err(e) => {
                err(format!("{dex}: class_data of class_def {i}: {e}"));
                complete = false;
                continue;
            }
        };
        let lists = [
            ("direct", &data.direct_methods),
            ("virtual", &data.virtual_methods),
        ];
        for (kind, list) in lists {
            for m in list.iter().filter(|m| m.access_flags & ACC_NATIVE != 0) {
                let built = (|| {
                    let id = view.method(m.method_idx).ok()?;
                    let proto = view.proto(id.proto).ok()?;
                    let params = proto
                        .parameters
                        .iter()
                        .map(|t| desc(view, t))
                        .collect::<Option<Vec<_>>>()?;
                    let name = view.string(id.name).ok()?.decode_lossy().into_owned();
                    Some((
                        desc(view, id.class)?,
                        name,
                        params,
                        desc(view, proto.return_type)?,
                    ))
                })();
                let Some((class, name, params, ret)) = built else {
                    err(format!(
                        "{dex}: native method_idx {} unresolvable",
                        m.method_idx.0
                    ));
                    complete = false;
                    continue;
                };
                let (short_jni, long_jni) = jni_names(&class, &name, &params);
                out.push(NativeMethod {
                    dex: dex.to_string(),
                    class,
                    name,
                    params,
                    ret,
                    kind,
                    access_flags: m.access_flags,
                    code_off: m.code_off,
                    short_jni,
                    long_jni,
                    matched_libs: Vec::new(),
                });
            }
        }
    }
    complete
}

fn is_lib_entry(name: &str) -> bool {
    (name.starts_with("lib/") || name.starts_with("assets/"))
        && name.to_ascii_lowercase().ends_with(".so")
}

/// Inventory native libraries and native methods of `path` (APK or DEX).
pub fn run_native(path: &Path) -> Result<NativeReport, CoreError> {
    let apk = Apk::open(path)?;
    let mut errors: Vec<String> = Vec::new();
    let mut err = |e: String| {
        if errors.len() < MAX_ERRORS {
            errors.push(e);
        }
    };
    let mut complete = true;
    let cap = InflateLimits::with_max_output(FILE_CAP).unwrap_or_default();

    // Libraries, one buffer at a time; keep only `Java_*` export names.
    let mut libs = Vec::new();
    let mut bound: HashMap<String, Vec<usize>> = HashMap::new();
    for e in apk.entries().filter(|e| is_lib_entry(&e.name)) {
        let abi_dir = e
            .name
            .strip_prefix("lib/")
            .and_then(|r| r.split_once('/'))
            .map(|(a, _)| a.to_string());
        let mut lib = LibInfo {
            name: e.name.clone(),
            abi_dir,
            size: e.uncompressed_size,
            elf: None,
            abi_mismatch: None,
            jni_onload: false,
            jni_onunload: false,
            export_count: 0,
            java_export_count: 0,
            matched_methods: 0,
            complete: false,
            notes: Vec::new(),
        };
        if e.uncompressed_size as usize > FILE_CAP {
            lib.notes
                .push(format!("exceeds {} MiB cap; not parsed", FILE_CAP >> 20));
        } else {
            match apk.read_entry_with_limits(&e, cap) {
                Err(x) => lib.notes.push(format!("read failed: {x}")),
                Ok(bytes) => match parse_elf(bytes.as_slice()) {
                    Err(x) => lib.notes.push(format!("ELF parse failed: {x}")),
                    Ok(elf) => {
                        let idx = libs.len();
                        lib.jni_onload = elf.exports.iter().any(|n| n == "JNI_OnLoad");
                        lib.jni_onunload = elf.exports.iter().any(|n| n == "JNI_OnUnload");
                        lib.export_count = elf.exports.len();
                        for n in elf.exports.iter().filter(|n| n.starts_with("Java_")) {
                            lib.java_export_count += 1;
                            let v = bound.entry(n.clone()).or_default();
                            if v.last() != Some(&idx) {
                                v.push(idx);
                            }
                        }
                        lib.abi_mismatch = lib
                            .abi_dir
                            .as_deref()
                            .and_then(abi_machine)
                            .map(|m| m != elf.machine);
                        lib.elf = Some(ElfSummary {
                            bits: elf.bits,
                            endian: if elf.little_endian { "little" } else { "big" },
                            machine: elf.machine,
                            machine_name: machine_name(elf.machine),
                            symbol_source: match elf.path {
                                ElfPath::Sections => "sections",
                                ElfPath::Dynamic => "dynamic",
                                ElfPath::None => "none",
                            },
                            symbols_seen: elf.symbols_seen,
                        });
                        lib.complete = elf.complete;
                        lib.notes.extend(elf.notes);
                    }
                },
            }
        }
        if !lib.complete {
            complete = false;
            err(format!("{}: {}", lib.name, lib.notes.join("; ")));
        }
        libs.push(lib);
    }

    // Native methods across every logical DEX.
    let mut methods = Vec::new();
    for e in apk.dex_entries() {
        if e.uncompressed_size as usize > FILE_CAP {
            err(format!("{}: exceeds {} MiB cap", e.name, FILE_CAP >> 20));
            complete = false;
            continue;
        }
        let bytes = match apk.read_entry_with_limits(&e, cap) {
            Ok(b) => b,
            Err(x) => {
                err(format!("{}: read failed: {x}", e.name));
                complete = false;
                continue;
            }
        };
        let b = bytes.as_slice();
        let offsets = if b.starts_with(b"dex\n041\0") {
            DexView::logical_header_offsets(b).ok()
        } else {
            Some(vec![0])
        };
        let Some(offsets) = offsets else {
            err(format!("{}: DEX-041 container unreadable", e.name));
            complete = false;
            continue;
        };
        for (i, off) in offsets.iter().enumerate() {
            let name = logical_dex_name(&e.name, offsets.len(), i);
            match DexView::parse_at(b, *off) {
                Ok(v) => complete &= walk_view(&v, &name, &mut methods, &mut err),
                Err(x) => {
                    err(format!("{name}: parse failed: {x}"));
                    complete = false;
                }
            }
        }
    }

    for m in &mut methods {
        for n in [&m.short_jni, &m.long_jni] {
            for &i in bound.get(n).into_iter().flatten() {
                let l = &libs[i].name;
                if !m.matched_libs.contains(l) {
                    m.matched_libs.push(l.clone());
                    libs[i].matched_methods += 1;
                }
            }
        }
        m.matched_libs.sort();
    }
    let matched = methods
        .iter()
        .filter(|m| !m.matched_libs.is_empty())
        .count();
    let direct_count = methods.iter().filter(|m| m.kind == "direct").count();
    let note = if methods.is_empty() {
        None
    } else if matched == 0 {
        Some(
            "no native method is bound by an exported Java_* name; dynamic registration \
             (RegisterNatives) is possible but not verified"
                .to_string(),
        )
    } else if matched < methods.len() {
        Some(format!(
            "{} of {} native methods have no name-matched export; dynamic registration \
             is possible for those (not verified)",
            methods.len() - matched,
            methods.len()
        ))
    } else {
        None
    };
    // ABI splits means "native code may be missing", not "no native
    // code". Augment the note instead of overriding it.
    let libs_empty = libs.is_empty();
    let mut split_note: Option<String> = None;
    if libs_empty
        && !apk.is_raw_dex()
        && let Ok(m) = asc_manifest::parse_from_apk(path)
    {
        let requires = m
            .required_split_types
            .as_deref()
            .is_some_and(|v| v.contains("abi"))
            || m.split_types.as_deref().is_some_and(|v| v.contains("abi"))
            || m.application.meta_data.iter().any(|md| {
                md.name == "com.android.vending.splits.required"
                    && md.value.as_deref() == Some("true")
            });
        if requires {
            split_note = Some(
                "no lib/*.so in this APK, but the manifest requires ABI split(s); \
                 native libraries likely live in split APKs that were not provided"
                    .to_string(),
            );
        }
    }
    let note = match (note, split_note) {
        (Some(a), Some(b)) => Some(format!("{a}; {b}")),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };
    Ok(NativeReport {
        input: path.display().to_string(),
        libs,
        direct_count,
        virtual_count: methods.len() - direct_count,
        matched_methods: matched,
        unbound_methods: methods.len() - matched,
        methods,
        note,
        errors,
        complete,
    })
}

pub fn format_native_text(r: &NativeReport) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "input: {}\nnative libraries: {}\nnative methods: {} ({} direct, {} virtual), name-matched {}, unbound {}\ncomplete: {}",
        r.input,
        r.libs.len(),
        r.methods.len(),
        r.direct_count,
        r.virtual_count,
        r.matched_methods,
        r.unbound_methods,
        r.complete
    );
    if let Some(n) = &r.note {
        let _ = writeln!(s, "note: {n}");
    }
    for l in &r.libs {
        let elf = l.elf.as_ref().map_or_else(
            || "ELF unreadable".to_string(),
            |e| {
                format!(
                    "ELF{} {} e_machine={} ({}), symbols from {}",
                    e.bits, e.endian, e.machine, e.machine_name, e.symbol_source
                )
            },
        );
        let _ = writeln!(
            s,
            "lib {} ({} B, abi_dir {}{}): {elf}; JNI_OnLoad={}, exports {} (Java_* {}), matched methods {}{}",
            l.name,
            l.size,
            l.abi_dir.as_deref().unwrap_or("-"),
            if l.abi_mismatch == Some(true) {
                ", MISMATCH with e_machine"
            } else {
                ""
            },
            l.jni_onload,
            l.export_count,
            l.java_export_count,
            l.matched_methods,
            if l.complete { "" } else { " [INCOMPLETE]" },
        );
        for n in &l.notes {
            let _ = writeln!(s, "  note: {n}");
        }
    }
    for m in &r.methods {
        let link = if m.matched_libs.is_empty() {
            "unbound".to_string()
        } else {
            format!("name-match: {}", m.matched_libs.join(", "))
        };
        let _ = writeln!(
            s,
            "method {}.{}({}){} [{}, code_off={}] {link}",
            m.class,
            m.name,
            m.params.concat(),
            m.ret,
            m.kind,
            m.code_off
        );
    }
    for e in &r.errors {
        let _ = writeln!(s, "error: {e}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jni_spec_examples() {
        // JNI spec: `Java_p_q_r_A_f` / overloaded long name `__ILjava_lang_String_2`,
        // `_` in identifiers → `_1`, non-ASCII → `_0xxxx`.
        let (s, l) = jni_names("Lp/q/r/A;", "f", &["I".into(), "Ljava/lang/String;".into()]);
        assert_eq!(s, "Java_p_q_r_A_f");
        assert_eq!(l, "Java_p_q_r_A_f__ILjava_lang_String_2");
        let (s, l) = jni_names("Lp/My_Cls;", "a_b", &["[I".into()]);
        assert_eq!(s, "Java_p_My_1Cls_a_1b");
        assert_eq!(l, "Java_p_My_1Cls_a_1b___3I");
        assert_eq!(jni_escape("é"), "_000e9");
        let (_, l) = jni_names("LC;", "m", &[]);
        assert_eq!(l, "Java_C_m__");
    }
}
