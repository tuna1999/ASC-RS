//! `asc-rs xapk`: inventory of XAPK (or any ZIP-of-APKs) containers.
//!
//! Lists every `*.apk` member and analyzes each one IN ISOLATION —
//! manifest, DEX class counts, native libraries — within per-member
//! resource caps. Provenance is never merged: each member keeps its own
//! counts and errors. A member's role (base vs split) comes from its
//! manifest `android:split` attribute ONLY; filenames are never used to
//! infer it. Missing manifest, failed manifest parse and unreadable
//! member are three distinct reported states.
//!
//! No extraction to disk; nested ZIPs are parsed in memory (`ZipView`),
//! bounded by the per-member read cap and the inflate limit.

use std::fmt::Write as _;
use std::path::Path;

use asc_apk::{Apk, InflateLimits, ZipView};
use serde::Serialize;

use crate::pipeline::CoreError;

/// Largest member APK read in full.
const MEMBER_CAP: usize = 256 << 20;
/// Largest single entry inside a member.
const INNER_CAP: usize = 256 << 20;
/// Cap on recorded per-member native-lib names.
const MAX_LIBS: usize = 500;

#[derive(Debug, Clone, Serialize)]
pub struct MemberDex {
    pub name: String,
    /// Class-def count of every logical DEX (0 when parse failed).
    pub classes: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemberManifest {
    pub package: Option<String>,
    pub version_code: Option<u32>,
    /// The member's own `android:split` attribute; `None` on a base APK.
    pub split: Option<String>,
    pub split_types: Option<String>,
    pub required_split_types: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemberApk {
    pub name: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    /// `base` (manifest without `android:split`), `split` (with), or
    /// `unknown` (no readable manifest — never guessed from the name).
    pub role: &'static str,
    pub manifest: Option<MemberManifest>,
    pub manifest_error: Option<String>,
    pub dex: Vec<MemberDex>,
    /// `lib/<abi>/*.so` entry names (capped).
    pub native_libs: Vec<String>,
    pub abi_dirs: Vec<String>,
    /// `false` when the member ZIP could not be traversed at all or a
    /// DEX entry could not be READ (cap exceeded, inflate failure) —
    /// the inventory is then partial. A DEX whose bytes parse fine but
    /// yield a corrupt header is a per-DEX `error`, not incompleteness.
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct XapkReport {
    pub file: String,
    /// Analyzed `*.apk` members, central-directory order.
    pub members: Vec<MemberApk>,
    /// Container-level failures (unreadable member, cap exceeded).
    /// `complete` is false for those OR any member whose own traversal
    /// failed (unreadable member ZIP, DEX read failure). Per-DEX
    /// content errors and manifest states stay member-level.
    pub errors: Vec<String>,
    pub complete: bool,
}

fn count_classes(bytes: &[u8]) -> Result<usize, String> {
    let offsets = if bytes.starts_with(b"dex\n041\0") {
        asc_dex::DexView::logical_header_offsets(bytes).map_err(|e| e.to_string())?
    } else {
        vec![0usize]
    };
    let mut total = 0usize;
    for off in offsets {
        let view = asc_dex::DexView::parse_at(bytes, off).map_err(|e| e.to_string())?;
        total += view.class_def_count() as usize;
    }
    Ok(total)
}

/// Analyze one member APK buffer: manifest, DEX entries, native libs.
/// Public bytes-level API (fuzz target drives it directly, no
/// filesystem or outer-ZIP wrapper).
pub fn analyze_member(name: &str, compressed: u64, uncompressed: u64, bytes: &[u8]) -> MemberApk {
    let mut m = MemberApk {
        name: name.to_string(),
        compressed_size: compressed,
        uncompressed_size: uncompressed,
        role: "unknown",
        manifest: None,
        manifest_error: None,
        dex: Vec::new(),
        native_libs: Vec::new(),
        abi_dirs: Vec::new(),
        complete: true,
    };
    let inner_cap = InflateLimits::with_max_output(INNER_CAP);
    let view = match ZipView::parse(bytes) {
        Ok(v) => v,
        Err(e) => {
            m.manifest_error = Some(format!("member is not a readable ZIP: {e}"));
            m.complete = false;
            return m;
        }
    };
    // Manifest: parsed in isolation; three states kept apart.
    match view.entry("AndroidManifest.xml") {
        Some(entry) => match view.read_entry_with_limits(&entry, inner_cap.unwrap_or_default()) {
            Ok(b) => match asc_manifest::parse_manifest(b.as_slice()) {
                Ok(mi) => {
                    m.role = if mi.split.is_some() { "split" } else { "base" };
                    m.manifest = Some(MemberManifest {
                        package: mi.package,
                        version_code: mi.version_code,
                        split: mi.split,
                        split_types: mi.split_types,
                        required_split_types: mi.required_split_types,
                    });
                }
                Err(e) => m.manifest_error = Some(format!("manifest decode failed: {e}")),
            },
            Err(e) => m.manifest_error = Some(format!("manifest unreadable: {e}")),
        },
        None => m.manifest_error = Some("no AndroidManifest.xml entry".into()),
    }
    let mut abis: Vec<String> = Vec::new();
    for e in view.entries() {
        // Oversized NON-DEX entries (huge assets) are simply skipped:
        // they are not part of the DEX inventory and never counted in
        // `dex`. Only oversized DEX entries make the inventory partial.
        if e.name.starts_with("lib/") && e.name.ends_with(".so") {
            if m.native_libs.len() < MAX_LIBS {
                m.native_libs.push(e.name.clone());
            }
            if let Some(abi) = e
                .name
                .strip_prefix("lib/")
                .and_then(|r| r.split('/').next())
                && !abis.iter().any(|a| a == abi)
                && abis.len() < 32
            {
                abis.push(abi.to_string());
            }
        }
    }
    m.abi_dirs = abis;
    let inner_cap = InflateLimits::with_max_output(INNER_CAP);
    for e in view.dex_entries() {
        if e.uncompressed_size as usize > INNER_CAP {
            m.dex.push(MemberDex {
                name: e.name.clone(),
                classes: 0,
                error: Some(format!("exceeds {} MiB cap", INNER_CAP >> 20)),
            });
            m.complete = false;
            continue;
        }
        let (classes, error, readable) =
            match view.read_entry_with_limits(&e, inner_cap.unwrap_or_default()) {
                Ok(b) => match count_classes(b.as_slice()) {
                    Ok(n) => (n, None, true),
                    // Corrupt DEX content: the bytes were read; this is a
                    // per-DEX data error, not a traversal failure.
                    Err(why) => (0, Some(why), true),
                },
                Err(x) => (0, Some(format!("read failed: {x}")), false),
            };
        m.complete &= readable;
        m.dex.push(MemberDex {
            name: e.name.clone(),
            classes,
            error,
        });
    }
    m
}

/// Inventory every `*.apk` member of an XAPK-style container.
pub fn run_xapk(path: &Path) -> Result<XapkReport, CoreError> {
    let apk = Apk::open(path)?;
    let mut report = XapkReport {
        file: path.display().to_string(),
        members: Vec::new(),
        errors: Vec::new(),
        complete: true,
    };
    let cap = InflateLimits::with_max_output(MEMBER_CAP);
    for e in apk.entries() {
        if !e.name.ends_with(".apk") {
            continue;
        }
        if e.uncompressed_size as usize > MEMBER_CAP {
            report
                .errors
                .push(format!("{}: exceeds {} MiB cap", e.name, MEMBER_CAP >> 20));
            report.complete = false;
            continue;
        }
        let bytes = match apk.read_entry_with_limits(&e, cap.unwrap_or_default()) {
            Ok(b) => b,
            Err(x) => {
                report.errors.push(format!("{}: read failed: {x}", e.name));
                report.complete = false;
                continue;
            }
        };
        let member = analyze_member(
            &e.name,
            e.compressed_size,
            e.uncompressed_size,
            bytes.as_slice(),
        );
        if !member.complete {
            report.complete = false;
        }
        report.members.push(member);
    }
    Ok(report)
}

/// Text rendering: one header block per member, never merged.
pub fn format_xapk_text(r: &XapkReport) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "container: {} ({} apk members)", r.file, r.members.len());
    for m in &r.members {
        let _ = writeln!(
            s,
            "{}: role={} size={}/{} dex={} classes={} native-libs={} abis={}{}",
            m.name,
            m.role,
            m.compressed_size,
            m.uncompressed_size,
            m.dex.len(),
            m.dex.iter().map(|d| d.classes).sum::<usize>(),
            m.native_libs.len(),
            m.abi_dirs.join(","),
            if m.complete { "" } else { " (incomplete)" }
        );
        if let Some(man) = &m.manifest {
            let _ = writeln!(
                s,
                "  manifest: package={} versionCode={} split={} splitTypes={} required={}",
                man.package.as_deref().unwrap_or("-"),
                man.version_code
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into()),
                man.split.as_deref().unwrap_or("-"),
                man.split_types.as_deref().unwrap_or("-"),
                man.required_split_types.as_deref().unwrap_or("-"),
            );
        }
        if let Some(e) = &m.manifest_error {
            let _ = writeln!(s, "  manifest: {e}");
        }
        for d in &m.dex {
            match &d.error {
                Some(e) => {
                    let _ = writeln!(s, "  dex {}: error: {e}", d.name);
                }
                None => {
                    let _ = writeln!(s, "  dex {}: {} classes", d.name, d.classes);
                }
            }
        }
    }
    for e in &r.errors {
        let _ = writeln!(s, "error: {e}");
    }
    if !r.complete {
        let _ = writeln!(s, "report incomplete");
    }
    s
}
