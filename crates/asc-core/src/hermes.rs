//! `asc-rs hermes`: structured string-table extraction from Hermes
//! bytecode bundles (React Native `index.android.bundle` etc.).
//!
//! Detection: 8-byte magic `0x1F1903C103BC1FC6` (LE). Extraction follows
//! `hermes/BCGen/HBC/BytecodeFileFormat.h` segment order:
//! header → function headers → string kinds (RLE) → identifier hashes →
//! small string table → overflow string table → string storage.
//!
//! Only the layout of bytecode **version 96** is verified (against a real
//! bundle and the upstream header definition); any other version is
//! reported as `supported=false` with its strings NOT guessed. No
//! bytecode is interpreted, no JavaScript executed. Bounded: per-entry
//! read cap, per-string length cap, emitted-string cap.

use std::fmt::Write as _;
use std::path::Path;

use asc_apk::{Apk, InflateLimits};
use serde::Serialize;

use crate::pipeline::CoreError;

/// The single Hermes bytecode version whose segment layout is verified.
pub const SUPPORTED_VERSION: u32 = 96;
/// Largest bundle read in full (same cap as `inspect`).
const FILE_CAP: usize = 64 << 20;
/// Default and hard maximum number of emitted strings.
pub const MAX_STRINGS: usize = 100_000;
/// Per-string byte-length cap (longer entries are truncated with a note).
const MAX_STRING_BYTES: usize = 1 << 20;

/// `"Hermes"` in ancient Greek, UTF-16BE truncated to 8 bytes (LE on disk).
const MAGIC: [u8; 8] = [0xC6, 0x1F, 0xBC, 0x03, 0xC1, 0x03, 0x19, 0x1F];

#[derive(Debug, Clone)]
pub struct HermesOptions {
    /// Substring filter (case-sensitive), like `findrefs string`.
    pub pattern: Option<String>,
    /// Emission cap; hard ceiling `MAX_STRINGS`.
    pub limit: usize,
}

impl Default for HermesOptions {
    fn default() -> Self {
        Self {
            pattern: None,
            limit: MAX_STRINGS,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HermesString {
    pub index: u32,
    /// `"string"` / `"identifier"` / `"unknown"` (RLE did not cover it).
    pub kind: &'static str,
    pub is_utf16: bool,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleInfo {
    pub name: String,
    pub size: usize,
    pub version: u32,
    pub supported: bool,
    pub declared_string_count: u32,
    pub identifier_count: u32,
    /// Structured (string-table) extraction; NOT raw printable strings.
    pub strings: Vec<HermesString>,
    pub truncated: bool,
    /// Why strings are absent when `supported == false`.
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HermesReport {
    pub bundles: Vec<BundleInfo>,
    /// Bundles detected but not decoded (cap/read failure). Partial.
    pub errors: Vec<String>,
    pub complete: bool,
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Scan every APK entry for Hermes bundles and extract their string
/// tables (version 96 only; other versions are reported unsupported).
pub fn run_hermes(path: &Path, opts: &HermesOptions) -> Result<HermesReport, CoreError> {
    let apk = Apk::open(path)?;
    let mut report = HermesReport {
        bundles: Vec::new(),
        errors: Vec::new(),
        complete: true,
    };
    let cap = InflateLimits::with_max_output(FILE_CAP);
    let limit = opts.limit.min(MAX_STRINGS);
    for e in apk.entries() {
        if e.uncompressed_size as usize > FILE_CAP {
            report
                .errors
                .push(format!("{}: exceeds {} MiB cap", e.name, FILE_CAP >> 20));
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
        let b = bytes.as_slice();
        if b.len() < 36 || b[..8] != MAGIC {
            continue;
        }
        let version = u32_at(b, 8).unwrap_or(0);
        let mut info = BundleInfo {
            name: e.name.clone(),
            size: b.len(),
            version,
            supported: false,
            declared_string_count: 0,
            identifier_count: 0,
            strings: Vec::new(),
            truncated: false,
            note: None,
        };
        if version != SUPPORTED_VERSION {
            info.note = Some(format!(
                "unsupported hermes version {version} (supported: {SUPPORTED_VERSION}); strings not decoded"
            ));
            report.complete = false;
            report.bundles.push(info);
            continue;
        }
        info.declared_string_count = u32_at(b, 52).unwrap_or(0);
        info.identifier_count = u32_at(b, 48).unwrap_or(0);
        match extract_strings(b, opts, limit) {
            Ok((strings, truncated)) => {
                info.strings = strings;
                info.truncated = truncated;
                info.supported = true;
            }
            Err(why) => {
                info.note = Some(format!("decode failed: {why}"));
                report.complete = false;
            }
        }
        report.bundles.push(info);
    }
    Ok(report)
}

/// Decode every string of a v96 bundle (bounded by `limit` after the
/// pattern filter). Returns `(strings, truncated_by_limit)`.
fn extract_strings(
    b: &[u8],
    opts: &HermesOptions,
    limit: usize,
) -> Result<(Vec<HermesString>, bool), String> {
    let layout = table_layout(b)?;
    let storage = &b[layout.storage_off..layout.storage_off + layout.storage_size];
    let mut out = Vec::new();
    let mut matched = 0usize;
    let mut truncated = false;
    for i in 0..layout.string_count as usize {
        let entry = decode_entry(b, &layout, i)?;
        let slice = storage
            .get(entry.off..entry.off.checked_add(entry.len).ok_or("extent overflow")?)
            .ok_or("string outside storage")?;
        let truncated_len = slice.len() > MAX_STRING_BYTES;
        let slice = &slice[..slice.len().min(MAX_STRING_BYTES)];
        let text = decode_text(slice, entry.is_utf16, truncated_len);
        if let Some(p) = &opts.pattern
            && !text.contains(p.as_str())
        {
            continue;
        }
        matched += 1;
        if out.len() >= limit {
            truncated = true;
            break;
        }
        out.push(HermesString {
            index: i as u32,
            kind: layout.kinds.get(i).copied().unwrap_or("unknown"),
            is_utf16: entry.is_utf16,
            text,
        });
    }
    let _ = matched;
    Ok((out, truncated))
}

struct Layout {
    string_count: u32,
    kinds: Vec<&'static str>,
    small_off: usize,
    overflow_off: usize,
    storage_off: usize,
    storage_size: usize,
}

fn table_layout(b: &[u8]) -> Result<Layout, String> {
    let function_count = u32_at(b, 40).ok_or("truncated header")?;
    let string_kind_count = u32_at(b, 44).ok_or("truncated header")?;
    let identifier_count = u32_at(b, 48).ok_or("truncated header")?;
    let string_count = u32_at(b, 52).ok_or("truncated header")?;
    let overflow_count = u32_at(b, 56).ok_or("truncated header")?;
    let storage_size = u32_at(b, 60).ok_or("truncated header")? as usize;
    if string_count > 4_000_000 || storage_size > FILE_CAP {
        return Err("unreasonable table size".into());
    }
    const HEADER_SIZE: usize = 128;
    let kinds_off = HEADER_SIZE
        .checked_add(function_count as usize * 16)
        .ok_or("function table overflow")?;
    let small_off = kinds_off
        .checked_add(string_kind_count as usize * 4)
        .and_then(|o| o.checked_add(identifier_count as usize * 4))
        .ok_or("kind/hash table overflow")?;
    let overflow_off = small_off
        .checked_add(string_count as usize * 4)
        .ok_or("string table overflow")?;
    let storage_off = overflow_off
        .checked_add(overflow_count as usize * 8)
        .ok_or("overflow table overflow")?;
    let storage_end = storage_off
        .checked_add(storage_size)
        .ok_or("storage overflow")?;
    if storage_end > b.len() {
        return Err(format!(
            "string storage overruns bundle ({storage_end} > {})",
            b.len()
        ));
    }
    // String kinds: RLE u32 entries (kind in the top bit, count low 31).
    let mut kinds = vec!["unknown"; string_count as usize];
    let mut idx = 0usize;
    for i in 0..string_kind_count as usize {
        let d = u32_at(b, kinds_off + i * 4).ok_or("truncated string kinds")?;
        let kind = if d & 0x8000_0000 != 0 {
            "identifier"
        } else {
            "string"
        };
        let count = (d & 0x7FFF_FFFF) as usize;
        if idx
            .checked_add(count)
            .map(|e| e > kinds.len())
            .unwrap_or(true)
        {
            return Err("string-kind RLE overruns string count".into());
        }
        for k in &mut kinds[idx..idx + count] {
            *k = kind;
        }
        idx += count;
    }
    Ok(Layout {
        string_count,
        kinds,
        small_off,
        overflow_off,
        storage_off,
        storage_size,
    })
}

struct Entry {
    off: usize,
    len: usize,
    is_utf16: bool,
}

fn decode_entry(b: &[u8], l: &Layout, i: usize) -> Result<Entry, String> {
    let e = u32_at(b, l.small_off + i * 4).ok_or("truncated string table")?;
    let is_utf16 = e & 1 != 0;
    let off = ((e >> 1) & 0x7F_FFFF) as usize;
    let len = ((e >> 24) & 0xFF) as usize;
    if len == 0xFF {
        let oo = l
            .overflow_off
            .checked_add(off * 8)
            .ok_or("overflow index overflow")?;
        let o = u32_at(b, oo).ok_or("truncated overflow table")? as usize;
        let n = u32_at(b, oo + 4).ok_or("truncated overflow table")? as usize;
        Ok(Entry {
            off: o,
            len: n,
            is_utf16,
        })
    } else {
        Ok(Entry { off, len, is_utf16 })
    }
}

fn decode_text(slice: &[u8], is_utf16: bool, truncated: bool) -> String {
    let mut text = if is_utf16 {
        let units: Vec<u16> = slice
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(slice).into_owned()
    };
    if truncated {
        text.push('…');
    }
    // Keep text output one-line: mask ASCII control characters.
    text.chars()
        .map(|c| {
            if (c as u32) < 0x20 || c as u32 == 0x7F {
                '·'
            } else {
                c
            }
        })
        .collect()
}

/// Text rendering: per-bundle header, then `<bundle> #<index> <kind> <text>`.
pub fn format_hermes_text(r: &HermesReport) -> String {
    let mut s = String::new();
    for b in &r.bundles {
        let _ = writeln!(
            s,
            "{}: hermes v{} ({} bytes, {} strings declared, {} identifiers){}",
            b.name,
            b.version,
            b.size,
            b.declared_string_count,
            b.identifier_count,
            match &b.note {
                Some(n) => format!(" — {n}"),
                None => String::new(),
            }
        );
        for st in &b.strings {
            let _ = writeln!(s, "{} #{} {} {}", b.name, st.index, st.kind, st.text);
        }
        if b.truncated {
            let _ = writeln!(s, "{}: output truncated by limit", b.name);
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
