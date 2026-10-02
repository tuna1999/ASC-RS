//! `inspect`: bounded inventory + packer-signal report for an APK or raw DEX.
//!
//! Everything here is *observation*. Entropy comes from a capped prefix
//! (never integrity-checked), DEX tail bytes are only reported when the
//! DEX map yields an exact extent, and a packer is named only when at
//! least two independent, packer-specific signals agree. High entropy or
//! trailing bytes alone never name a packer.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::Path;

use asc_apk::{Apk, Compression, InflateLimits};
use asc_dex::DexView;
use asc_dex::map::DataEnd;
use serde::Serialize;
use sha1::{Digest, Sha1};

use crate::pipeline::{CoreError, collect_classes_from_bytes};

/// Prefix sampled per entry for entropy / magic.
const SAMPLE_CAP: usize = 1 << 20;
/// Largest DEX read in full for coverage / checksums.
const DEX_CAP: usize = 64 << 20;
/// Uncovered bytes above which a payload candidate is flagged.
const TAIL_FLAG: u64 = 64 << 10;
/// Cap on recorded per-entry errors.
const MAX_ERRORS: usize = 100;

/// One archive entry.
#[derive(Debug, Clone, Serialize)]
pub struct EntryInfo {
    /// Entry name.
    pub name: String,
    /// `stored` | `deflated`.
    pub method: &'static str,
    /// Compressed size.
    pub compressed_size: u64,
    /// Declared uncompressed size.
    pub uncompressed_size: u64,
    /// `dex` | `elf` | `zip` | `other` (from magic).
    pub kind: &'static str,
    /// Shannon entropy (bits/byte) of the sampled prefix.
    pub entropy: Option<f64>,
    /// Bytes sampled.
    pub sample_bytes: usize,
    /// Prefix covered the whole entry.
    pub sample_complete: bool,
    /// Always `false`: prefix sampling checks neither CRC nor stream tail.
    pub integrity_checked: bool,
}

/// One `classes*.dex` entry (or the raw DEX).
#[derive(Debug, Clone, Serialize)]
pub struct DexInfo {
    /// Entry name.
    pub name: String,
    /// Bytes read.
    pub size: usize,
    /// Header `file_size` (first logical header).
    pub header_file_size: Option<u32>,
    /// Adler-32 matches header (`None` when not checkable).
    pub checksum_ok: Option<bool>,
    /// SHA-1 matches header (`None` when not checkable).
    pub sha1_ok: Option<bool>,
    /// Classes defined.
    pub class_count: usize,
    /// Offset where declared content ends, when exactly known.
    pub data_end: Option<usize>,
    /// Why `data_end` is unknown.
    pub coverage_note: Option<String>,
    /// Bytes past `data_end`; `None` when coverage is unknown.
    pub tail_bytes: Option<u64>,
    /// Entropy of (up to 1 MiB of) the tail.
    pub tail_entropy: Option<f64>,
}

/// Manifest vs DEX cross-check.
#[derive(Debug, Clone, Serialize)]
pub struct ManifestCheck {
    /// `package` attribute.
    pub package: Option<String>,
    /// Declared activities/services/receivers/providers.
    pub components_total: usize,
    /// Of those, how many have no class in any DEX.
    pub components_missing_from_dex: usize,
    /// Up to 10 missing class names.
    pub missing_examples: Vec<String>,
}

/// Hermes bytecode entry (`assets/index.android.bundle` and friends).
/// Header fields per `hermes/BytecodeFileFormat.h`: magic u64, version
/// u32 at 8, sourceHash[20], fileLength u32 at 32.
#[derive(Debug, Clone, Serialize)]
pub struct HermesInfo {
    /// Entry name.
    pub name: String,
    /// Bytecode version (e.g. 96).
    pub version: u32,
    /// Declared `fileLength` ("until the end of the BytecodeFileFooter").
    pub file_length: u32,
    /// Actual uncompressed entry size.
    pub size: u64,
}

/// Split-APK markers from the manifest, plus what this APK actually
/// contains. Lets consumers distinguish "no native code" from "the
/// native code lives in a split that was not provided".
#[derive(Debug, Clone, Serialize)]
pub struct SplitStatus {
    /// This APK's own plain `split` attribute; `None` = base/standalone.
    pub split: Option<String>,
    /// `android:splitTypes` (e.g. `base__abi`).
    pub split_types: Option<String>,
    /// `android:requiredSplitTypes` (e.g. `base__abi,base__density`).
    pub required_split_types: Option<String>,
    /// meta-data `com.android.vending.splits.required == "true"`.
    pub play_splits_required: bool,
    /// Whether any `lib/<abi>/*.so` entry exists in this APK.
    pub has_native_libs: bool,
}

impl SplitStatus {
    /// True when ABI split(s) are required but no native library lives
    /// in this APK — the usual "analyze the base APK only" trap.
    /// Observation, not proof: the app may genuinely have no native
    /// code, or the split may carry it.
    pub fn abi_split_missing(&self) -> bool {
        let requires_abi = [
            self.required_split_types.as_deref(),
            self.split_types.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|v| v.contains("abi"));
        (requires_abi || self.play_splits_required) && !self.has_native_libs
    }
}

/// Packer conclusion.
#[derive(Debug, Clone, Serialize)]
pub struct PackerVerdict {
    /// Packer name when >= 2 signals agree.
    pub packed: Option<&'static str>,
    /// Signals observed (also listed when below the naming threshold).
    pub signals: Vec<String>,
}

/// Full report.
#[derive(Debug, Clone, Serialize)]
pub struct InspectReport {
    /// `apk` | `dex`.
    pub input: &'static str,
    /// Archive entries.
    pub entry_count: usize,
    /// Per-entry inventory.
    pub entries: Vec<EntryInfo>,
    /// Root DEX analysis.
    pub dex: Vec<DexInfo>,
    /// Manifest cross-check (APK only, when the manifest parses).
    /// Hermes bytecode entries (header metadata only).
    pub hermes: Vec<HermesInfo>,
    /// Split-APK status (APK only, when the manifest parses).
    pub split: Option<SplitStatus>,
    /// Manifest cross-check (APK only, when the manifest parses).
    pub manifest: Option<ManifestCheck>,
    /// Packer verdict.
    pub packer: PackerVerdict,
    /// Generic anomalies (uncertain by nature).
    pub anomalies: Vec<String>,
    /// Non-fatal problems while inspecting.
    pub errors: Vec<String>,
    /// `false` when any metric could not be computed.
    pub complete: bool,
}

/// Shannon entropy in bits/byte, rounded to 3 decimals.
fn entropy(data: &[u8]) -> Option<f64> {
    if data.is_empty() {
        return None;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let h: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum();
    Some((h * 1000.0).round() / 1000.0)
}

fn kind_of(b: &[u8]) -> &'static str {
    if b.starts_with(b"dex\n") {
        "dex"
    } else if b.starts_with(b"\x7fELF") {
        "elf"
    } else if b.starts_with(b"PK\x03\x04") {
        "zip"
    } else if b.starts_with(&HERMES_MAGIC) {
        "hermes"
    } else {
        "other"
    }
}

/// `0x1F1903C103BC1FC6` little-endian (Meta
/// `include/hermes/BCGen/HBC/BytecodeFileFormat.h`), verified against a
/// real `assets/index.android.bundle`.
const HERMES_MAGIC: [u8; 8] = [0xC6, 0x1F, 0xBC, 0x03, 0xC1, 0x03, 0x19, 0x1F];

fn is_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `Lv<hex>/l<hex>;` with the same hex on both sides (Virbox stub).
fn is_virbox_stub(desc: &str) -> bool {
    let inner = desc
        .strip_prefix("Lv")
        .and_then(|s| s.split(';').next())
        .and_then(|s| s.split_once("/l"));
    // Inner classes carry `$suffix` after the hex.
    matches!(inner, Some((a, b)) if is_hex(a) && b.split('$').next() == Some(a))
}

/// Number of distinct ABIs in an `assets/l<hex>_{a32,a64,x86,x64}.so` family.
fn virbox_asset_abis(names: &[String]) -> usize {
    let mut abis = HashSet::new();
    for n in names {
        let Some(rest) = n.strip_prefix("assets/l") else {
            continue;
        };
        let Some(stem) = rest.strip_suffix(".so") else {
            continue;
        };
        if let Some((hex, abi)) = stem.split_once('_')
            && is_hex(hex)
            && matches!(abi, "a32" | "a64" | "x86" | "x64")
        {
            abis.insert((hex.to_string(), abi.to_string()));
        }
    }
    abis.len()
}

fn component_descriptor(pkg: Option<&str>, name: &str) -> String {
    let full = match (name.starts_with('.'), name.contains('.'), pkg) {
        (true, _, Some(p)) => format!("{p}{name}"),
        (false, false, Some(p)) => format!("{p}.{name}"),
        _ => name.to_string(),
    };
    format!("L{};", full.replace('.', "/"))
}

fn analyze_dex(name: &str, bytes: &[u8], names: &mut Vec<String>) -> DexInfo {
    let before = names.len();
    // A class-collection failure is not cosmetic: the descriptors left
    // in `names` are then an unknown subset, so every downstream
    // manifest cross-check built on them is unsound. Surface it as a
    // coverage note (audit F05).
    let mut pairs = Vec::new();
    let collect_err = collect_classes_from_bytes(bytes, None, name, &mut pairs).err();
    names.extend(pairs.into_iter().map(|(d, _)| d));
    let mut info = DexInfo {
        name: name.to_string(),
        size: bytes.len(),
        header_file_size: None,
        checksum_ok: None,
        sha1_ok: None,
        class_count: names.len() - before,
        data_end: None,
        coverage_note: collect_err.map(|e| format!("class collection incomplete: {e}")),
        tail_bytes: None,
        tail_entropy: None,
    };
    let Ok(view) = DexView::parse(bytes) else {
        info.coverage_note = Some("header did not parse".into());
        return info;
    };
    let h = view.header();
    info.header_file_size = Some(h.file_size);
    let fs = h.file_size as usize;
    if (0x20..=bytes.len()).contains(&fs) {
        let sum = adler2::adler32(&bytes[0x0C..fs]).unwrap_or(0);
        info.checksum_ok = Some(sum == h.checksum);
        let sig: [u8; 20] = Sha1::digest(&bytes[0x20..fs]).into();
        info.sha1_ok = Some(sig == h.signature);
    }
    match view.data_end() {
        DataEnd::Known(end) => {
            info.data_end = Some(end);
            info.tail_bytes = Some((bytes.len() - end) as u64);
            let tail = &bytes[end..];
            info.tail_entropy = entropy(&tail[..tail.len().min(SAMPLE_CAP)]);
        }
        // Do not overwrite a class-collection failure: that one makes
        // the manifest cross-check unsound, which is the stronger claim.
        DataEnd::Unknown(why) => {
            info.coverage_note.get_or_insert_with(|| why.to_string());
        }
    }
    info
}

/// Inspect `path` (APK/ZIP or raw DEX).
pub fn run_inspect(path: &Path) -> Result<InspectReport, CoreError> {
    let apk = Apk::open(path)?;
    let mut errors: Vec<String> = Vec::new();
    let mut err = |e: String| {
        if errors.len() < MAX_ERRORS {
            errors.push(e);
        }
    };

    let mut entries = Vec::new();
    let mut names = Vec::new();
    let mut hermes = Vec::new();
    let mut has_native_libs = false;
    for e in apk.entries() {
        let mut info = EntryInfo {
            name: e.name.clone(),
            method: match e.method {
                Compression::Stored => "stored",
                Compression::Deflated => "deflated",
            },
            compressed_size: e.compressed_size,
            uncompressed_size: e.uncompressed_size,
            kind: "other",
            entropy: None,
            sample_bytes: 0,
            sample_complete: false,
            integrity_checked: false,
        };
        match apk.read_entry_prefix(&e, SAMPLE_CAP) {
            Ok((b, complete)) => {
                let s = b.as_slice();
                info.kind = kind_of(s);
                info.entropy = entropy(s);
                info.sample_bytes = s.len();
                info.sample_complete = complete;
                if info.kind == "hermes" && s.len() >= 36 {
                    hermes.push(HermesInfo {
                        name: e.name.clone(),
                        version: u32::from_le_bytes(s[8..12].try_into().expect("4 bytes")),
                        file_length: u32::from_le_bytes(s[32..36].try_into().expect("4 bytes")),
                        size: e.uncompressed_size,
                    });
                }
            }
            Err(x) => err(format!("{}: sample failed: {x}", e.name)),
        }
        if e.name.starts_with("lib/") && e.name.ends_with(".so") {
            has_native_libs = true;
        }
        names.push(e.name.clone());
        entries.push(info);
    }

    let mut dex = Vec::new();
    let mut descriptors: Vec<String> = Vec::new();
    let mut virbox_string = false;
    let cap = InflateLimits::with_max_output(DEX_CAP);
    for e in apk.dex_entries() {
        if e.uncompressed_size as usize > DEX_CAP {
            err(format!("{}: exceeds {} MiB DEX cap", e.name, DEX_CAP >> 20));
            continue;
        }
        let bytes = match apk.read_entry_with_limits(&e, cap.unwrap_or_default()) {
            Ok(b) => b,
            Err(x) => {
                err(format!("{}: read failed: {x}", e.name));
                continue;
            }
        };
        let b = bytes.as_slice();
        virbox_string |= b.windows(6).any(|w| w == b"Virbox");
        let info = analyze_dex(&e.name, b, &mut descriptors);
        // A partial class collection is a hard error for this report:
        // `complete` must not stay true and the manifest cross-check
        // must not present an unknown subset as a definite "missing
        // component" (audit F05).
        if let Some(note) = info
            .coverage_note
            .as_deref()
            .filter(|n| n.starts_with("class collection incomplete: "))
        {
            err(format!("{}: {note}", e.name));
        }
        dex.push(info);
    }

    let mut manifest = None;
    let mut split_status = None;
    if !apk.is_raw_dex() {
        match asc_manifest::parse_from_apk(path) {
            Ok(m) => {
                let have: HashSet<&str> = descriptors.iter().map(String::as_str).collect();
                let comps = m
                    .activities
                    .iter()
                    .map(|c| &c.name)
                    .chain(m.services.iter().map(|c| &c.name))
                    .chain(m.receivers.iter().map(|c| &c.name))
                    .chain(m.providers.iter().map(|c| &c.name));
                let mut total = 0;
                let mut missing = Vec::new();
                for n in comps {
                    total += 1;
                    if !have.contains(component_descriptor(m.package.as_deref(), n).as_str()) {
                        missing.push(n.clone());
                    }
                }
                manifest = Some(ManifestCheck {
                    package: m.package.clone(),
                    components_total: total,
                    components_missing_from_dex: missing.len(),
                    missing_examples: missing.iter().take(10).cloned().collect(),
                });
                let play_splits_required = m.application.meta_data.iter().any(|md| {
                    md.name == "com.android.vending.splits.required"
                        && md.value.as_deref() == Some("true")
                });
                split_status = Some(SplitStatus {
                    split: m.split.clone(),
                    split_types: m.split_types.clone(),
                    required_split_types: m.required_split_types.clone(),
                    play_splits_required,
                    has_native_libs,
                });
            }
            Err(x) => err(format!("manifest: {x}")),
        }
    }

    // ---- packer signals (Virbox only: the sole rule verified on a sample) ----
    let mut signals = Vec::new();
    if descriptors.iter().any(|d| is_virbox_stub(d)) {
        signals.push("stub class Lv<hex>/l<hex>;".to_string());
    }
    let abis = virbox_asset_abis(&names);
    if abis >= 2 {
        signals.push(format!("assets/l<hex>_<abi>.so family ({abis} ABIs)"));
    }
    if virbox_string {
        signals.push("DEX contains the string \"Virbox\"".to_string());
    }
    let packer = PackerVerdict {
        packed: (signals.len() >= 2).then_some("virbox"),
        signals,
    };

    // ---- generic anomalies ----
    let mut anomalies = Vec::new();
    for d in &dex {
        if let Some(t) = d.tail_bytes
            && t > TAIL_FLAG
        {
            anomalies.push(format!(
                "{}: {t} bytes past declared DEX content (appended-payload candidate; not proof of a packer)",
                d.name
            ));
        }
        if d.checksum_ok == Some(false) || d.sha1_ok == Some(false) {
            anomalies.push(format!(
                "{}: header checksum/SHA-1 mismatch (adler ok={:?}, sha1 ok={:?})",
                d.name, d.checksum_ok, d.sha1_ok
            ));
        }
        if d.header_file_size.is_some_and(|f| f as usize != d.size) {
            anomalies.push(format!(
                "{}: header file_size {} != actual {}",
                d.name,
                d.header_file_size.unwrap_or(0),
                d.size
            ));
        }
    }
    if let Some(sp) = &split_status
        && sp.abi_split_missing()
    {
        anomalies.push(
            "no lib/*.so in this APK, but the manifest requires split APKs \
             (requiredSplitTypes/play splits metadata); native code may live \
             in splits that were not provided — this is not evidence the app \
             has no native code"
                .to_string(),
        );
    }
    for h in &hermes {
        if u64::from(h.file_length) != h.size {
            anomalies.push(format!(
                "{}: hermes fileLength {} != actual {}",
                h.name, h.file_length, h.size
            ));
        }
        if h.version > 10_000 {
            anomalies.push(format!(
                "{}: implausible hermes version {}",
                h.name, h.version
            ));
        }
    }
    if let Some(m) = &manifest
        && m.components_total > 0
        && m.components_missing_from_dex == m.components_total
    {
        anomalies.push(format!(
            "0/{} manifest components have a class in the DEX",
            m.components_total
        ));
    }

    let complete = errors.is_empty()
        && dex.iter().all(|d| d.tail_bytes.is_some())
        && entries
            .iter()
            .all(|e| e.entropy.is_some() || e.sample_bytes == 0);
    Ok(InspectReport {
        input: if apk.is_raw_dex() { "dex" } else { "apk" },
        entry_count: entries.len(),
        entries,
        dex,
        hermes,
        split: split_status,
        manifest,
        packer,
        anomalies,
        errors,
        complete,
    })
}

/// Human-readable rendering. Lists DEX/ELF/nested-ZIP entries only; use
/// `--format json` for the full inventory.
pub fn format_inspect_text(r: &InspectReport) -> String {
    let opt = |v: Option<String>| v.unwrap_or_else(|| "unknown".into());
    let mut s = String::new();
    let _ = writeln!(s, "input: {} ({} entries)", r.input, r.entry_count);
    match r.packer.packed {
        Some(p) => {
            let _ = writeln!(s, "packer: {p}");
        }
        None => {
            let _ = writeln!(s, "packer: none identified");
        }
    }
    for sig in &r.packer.signals {
        let _ = writeln!(s, "  signal: {sig}");
    }
    for d in &r.dex {
        let _ = writeln!(
            s,
            "dex {}: {} bytes, {} classes, adler ok={}, sha1 ok={}, declared content ends at {}, tail bytes {}{}",
            d.name,
            d.size,
            d.class_count,
            opt(d.checksum_ok.map(|b| b.to_string())),
            opt(d.sha1_ok.map(|b| b.to_string())),
            opt(d.data_end.map(|v| v.to_string())),
            opt(d.tail_bytes.map(|v| v.to_string())),
            d.coverage_note
                .as_deref()
                .map(|n| format!(" (coverage unknown: {n})"))
                .unwrap_or_default(),
        );
        if let Some(e) = d.tail_entropy {
            let _ = writeln!(s, "  tail entropy (<=1 MiB sample): {e}");
        }
    }
    for h in &r.hermes {
        let _ = writeln!(
            s,
            "hermes {}: version {}, fileLength {}, size {} (inventoried only; bytecode not decompiled)",
            h.name, h.version, h.file_length, h.size
        );
    }
    if let Some(sp) = &r.split {
        let mut parts = Vec::new();
        if let Some(v) = &sp.split {
            parts.push(format!("split={v}"));
        }
        if let Some(v) = &sp.split_types {
            parts.push(format!("splitTypes={v}"));
        }
        if let Some(v) = &sp.required_split_types {
            parts.push(format!("requiredSplitTypes={v}"));
        }
        if sp.play_splits_required {
            parts.push("play-splits-required".into());
        }
        parts.push(format!("native_libs_present={}", sp.has_native_libs));
        let _ = writeln!(s, "split: {}", parts.join(" "));
    }
    if let Some(m) = &r.manifest {
        let _ = writeln!(
            s,
            "manifest: package {}, {}/{} components missing from DEX",
            m.package.as_deref().unwrap_or("-"),
            m.components_missing_from_dex,
            m.components_total
        );
        for n in &m.missing_examples {
            let _ = writeln!(s, "  missing: {n}");
        }
    }
    let high = r
        .entries
        .iter()
        .filter(|e| e.entropy.is_some_and(|x| x >= 7.5))
        .count();
    let _ = writeln!(
        s,
        "entries with sampled entropy >= 7.5: {high} (compressed media is normally high; prefix only, unverified)"
    );
    for e in r.entries.iter().filter(|e| e.kind != "other") {
        let _ = writeln!(
            s,
            "  {} [{}] {}B ({}) entropy {}",
            e.name,
            e.kind,
            e.uncompressed_size,
            e.method,
            opt(e.entropy.map(|v| v.to_string())),
        );
    }
    for a in &r.anomalies {
        let _ = writeln!(s, "anomaly: {a}");
    }
    for e in &r.errors {
        let _ = writeln!(s, "error: {e}");
    }
    let _ = writeln!(s, "complete: {}", r.complete);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), None);
        assert_eq!(entropy(&[7; 100]), Some(0.0));
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(entropy(&all), Some(8.0));
    }

    #[test]
    fn virbox_stub_requires_matching_hex() {
        assert!(is_virbox_stub("Lv1296851e/l1296851e;"));
        assert!(is_virbox_stub("Lv1296851e/l1296851e$jntm;"));
        assert!(!is_virbox_stub("Lv1296851e/l0000000a;"));
        assert!(!is_virbox_stub("Lcom/foo/Bar;"));
    }

    #[test]
    fn asset_family_needs_distinct_abis() {
        let n = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(virbox_asset_abis(&n(&["assets/l12ab_a32.so"])), 1);
        assert_eq!(
            virbox_asset_abis(&n(&[
                "assets/l12ab_a32.so",
                "assets/l12ab_x64.so",
                "assets/x.so"
            ])),
            2
        );
    }

    #[test]
    fn component_names_resolve_like_android() {
        assert_eq!(component_descriptor(Some("a.b"), ".Main"), "La/b/Main;");
        assert_eq!(component_descriptor(Some("a.b"), "Main"), "La/b/Main;");
        assert_eq!(component_descriptor(Some("a.b"), "c.d.Main"), "Lc/d/Main;");
    }
}
