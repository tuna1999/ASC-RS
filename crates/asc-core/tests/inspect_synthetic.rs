//! Synthetic, corpus-free tests for `run_inspect`.
//!
//! Every DEX here is built byte by byte so the expected report can be
//! derived from the bytes themselves (checksums, map extents, class
//! counts), never from the oracle or from a real APK.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use asc_core::run_inspect;
use sha1::Digest as _;

// ---------------------------------------------------------------- DEX builder
//
// Sections are laid out back to back, one class_def per `Spec::classes`
// entry (no proto/field/method ids, no class_data, no code):
//
//   0x0000 header (0x70)
//   0x0070 string_ids   n * 4   -> string_data offsets
//          type_ids     n * 4   -> string indices
//          class_defs   n * 32
//          string_data  per class: uleb + "L<name>;" + NUL
//          map_list

const HEADER_SIZE: usize = 0x70;
const STRING_IDS_OFF: usize = 0x70;

/// `map_item` types used by the builder.
const TYPE_HEADER_ITEM: u16 = 0x0000;
const TYPE_CLASS_DEF_ITEM: u16 = 0x0006;
const TYPE_MAP_LIST: u16 = 0x1000;
const TYPE_STRING_DATA: u16 = 0x2002;
const TYPE_CODE_ITEM: u16 = 0x2001;
const TYPE_STRING_ID_ITEM: u16 = 0x0001;

fn p16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn p32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

/// Shape of the `map_list` the builder writes.
#[derive(Default, Clone, Copy)]
enum MapShape {
    /// Every section declared; the `map_list` item is last, so its extent
    /// (4 + count*12 bytes) is exact.
    #[default]
    Exact,
    /// The last item by offset is a `code_item`, whose extent is
    /// variable-size and therefore not computable from the map.
    VariableExtent,
}

/// What the built DEX should look like once inspected.
#[derive(Default)]
struct Spec {
    /// Class descriptors, one per class_def.
    classes: Vec<String>,
    /// `map_list` shape.
    map: MapShape,
    /// Declares an extra `string_id_item` map entry of `n` bytes at the last
    /// offset, past the bytes the builder really writes, and lifts the
    /// header's file_size to cover it. The map extent stays computable but
    /// ends before file_size.
    oversize_map_item: Option<u32>,
    /// Extra raw bytes appended past the declared DEX extent.
    tail: Vec<u8>,
    /// Value stored in the adler32 field (`None` = the real one).
    checksum: Option<u32>,
    /// Value stored in the SHA-1 signature field (`None` = the real one).
    signature: Option<[u8; 20]>,
}

impl Spec {
    /// A DEX whose single class is `class`.
    fn one(class: &str) -> Self {
        Self {
            classes: vec![class.to_string()],
            ..Self::default()
        }
    }

    /// A DEX with `classes` class_defs, in order.
    fn with(classes: &[&str]) -> Self {
        Self {
            classes: classes.iter().map(|c| (*c).to_string()).collect(),
            ..Self::default()
        }
    }
}

/// Builds a DEX with one class_def per [`Spec::classes`].
fn build_dex(spec: &Spec) -> Vec<u8> {
    let n_usize = spec.classes.len();
    let n = u32::try_from(n_usize).unwrap();
    // Every section is a whole number of 4-byte words, so no padding is
    // needed anywhere.
    let type_ids_off = STRING_IDS_OFF + n_usize * 4;
    let class_defs_off = type_ids_off + n_usize * 4;
    let data_off = align4(class_defs_off + n_usize * 32);
    let string_data_len: usize = spec.classes.iter().map(|c| c.len() + 3).sum();
    let string_data_off = data_off;
    let map_off = align4(string_data_off + string_data_len);
    let map_items: usize = if spec.oversize_map_item.is_some() {
        5
    } else {
        4
    };
    // The map may claim a larger extent than the bytes written; the header's
    // file_size covers both the claim and the real bytes.
    let claim_end = spec.oversize_map_item.map_or(0, |n| map_off + n as usize);
    let file_size = align4(claim_end.max(map_off + 4 + map_items * 12));

    // The tail is reserved but never written here: it stays outside the
    // header's file_size and outside every map item.
    let mut b = vec![0u8; file_size + spec.tail.len()];
    b[..8].copy_from_slice(b"dex\n035\0");
    p32(&mut b, 0x20, file_size as u32);
    p32(&mut b, 0x24, HEADER_SIZE as u32);
    p32(&mut b, 0x28, 0x1234_5678);
    p32(&mut b, 0x34, map_off as u32);
    p32(&mut b, 0x38, n);
    p32(&mut b, 0x3C, STRING_IDS_OFF as u32);
    p32(&mut b, 0x40, n);
    p32(&mut b, 0x44, type_ids_off as u32);
    p32(&mut b, 0x60, n);
    p32(&mut b, 0x64, class_defs_off as u32);
    p32(&mut b, 0x68, string_data_len as u32);
    p32(&mut b, 0x6C, data_off as u32);

    // string_ids / type_ids / string_data.
    let mut sd = string_data_off;
    for (i, c) in spec.classes.iter().enumerate() {
        p32(&mut b, STRING_IDS_OFF + i * 4, sd as u32);
        p32(&mut b, type_ids_off + i * 4, i as u32);
        b[sd] = (c.len() as u8) | 0x80; // 2-byte uleb128 (descriptors < 128 B)
        b[sd + 1] = (c.len() >> 7) as u8;
        b[sd + 2..sd + 2 + c.len()].copy_from_slice(c.as_bytes());
        sd += c.len() + 3;
    }
    assert!(sd <= map_off, "string data must end before the map");

    // class_defs: class_idx = i, no superclass, no interfaces, no data.
    for i in 0..n_usize {
        let o = class_defs_off + i * 32;
        p32(&mut b, o, i as u32);
        p32(&mut b, o + 8, 0xFFFF_FFFF);
        p32(&mut b, o + 16, 0xFFFF_FFFF);
    }

    // map_list: items are declared in ascending offset order, so the last
    // one is also the one with the largest offset (what data_end keys on).
    let mut mo = map_off;
    p32(&mut b, mo, map_items as u32);
    mo += 4;
    for (ty, size, off) in [
        (TYPE_HEADER_ITEM, 1u32, 0u32),
        (TYPE_CLASS_DEF_ITEM, n, class_defs_off as u32),
        (TYPE_STRING_DATA, n, string_data_off as u32),
        match spec.map {
            // A code_item is variable-size: its length is not derivable.
            MapShape::VariableExtent => (TYPE_CODE_ITEM, 1, map_off as u32),
            MapShape::Exact => (TYPE_MAP_LIST, 1, map_off as u32),
        },
    ] {
        p16(&mut b, mo, ty);
        p16(&mut b, mo + 2, 0);
        p32(&mut b, mo + 4, size);
        p32(&mut b, mo + 8, off);
        mo += 12;
    }
    if claim_end > 0 {
        // Declared last (and at the largest offset) so it decides the extent.
        p16(&mut b, mo, TYPE_STRING_ID_ITEM);
        p16(&mut b, mo + 2, 0);
        // `size` is the item count; the extent is size * 4 bytes.
        p32(&mut b, mo + 4, ((claim_end - map_off) / 4) as u32);
        p32(&mut b, mo + 8, map_off as u32);
        mo += 12;
    }
    assert_eq!(mo, map_off + 4 + map_items * 12);
    assert!(mo <= file_size);

    // SHA-1 covers [0x20, file_size) and must be written first: the signature
    // lives inside the adler32 range, which covers [0x0C, file_size).
    let sig: [u8; 20] = sha1::Sha1::digest(&b[0x20..file_size]).into();
    b[0x0C..0x20].copy_from_slice(&spec.signature.unwrap_or(sig));
    let adler = adler2::adler32(&b[0x0C..file_size]).unwrap();
    p32(&mut b, 0x08, spec.checksum.unwrap_or(adler));
    b
}

fn align4(x: usize) -> usize {
    (x + 3) & !3
}

// ---------------------------------------------------------------- temp files

static SEQ: AtomicU32 = AtomicU32::new(0);

fn temp_path(tag: &str) -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("asc_inspect_{tag}_{}_{n}", std::process::id()))
}

fn write_dex(tag: &str, bytes: &[u8]) -> PathBuf {
    let p = temp_path(tag);
    fs::write(&p, bytes).unwrap();
    p
}

fn write_apk(tag: &str, files: &[(&str, &[u8])]) -> PathBuf {
    let p = temp_path(tag);
    let mut w = zip::ZipWriter::new(fs::File::create(&p).unwrap());
    let opts =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, bytes) in files {
        w.start_file(*name, opts).unwrap();
        std::io::Write::write_all(&mut w, bytes).unwrap();
    }
    w.finish().unwrap();
    p
}

fn remove(p: &Path) {
    let _ = fs::remove_file(p);
}

// ---------------------------------------------------------------------- tests

#[test]
fn raw_dex_report_matches_the_bytes_built() {
    let bytes = build_dex(&Spec::one("Lcom/example/Probe;"));
    let path = write_dex("raw", &bytes);
    let r = run_inspect(&path).unwrap();
    remove(&path);

    assert_eq!(r.input, "dex");
    // A bare DEX maps to one virtual STORED entry spanning the file.
    assert_eq!(r.entry_count, 1);
    assert_eq!(r.entries.len(), 1);
    assert_eq!(
        r.entries[0].name,
        path.file_name().unwrap().to_str().unwrap()
    );
    assert_eq!(r.entries[0].kind, "dex");
    assert_eq!(r.entries[0].method, "stored");
    assert_eq!(r.entries[0].uncompressed_size, bytes.len() as u64);
    assert!(r.entries[0].sample_complete);
    assert!(!r.entries[0].integrity_checked);

    assert_eq!(r.dex.len(), 1);
    let d = &r.dex[0];
    assert_eq!(d.name, path.file_name().unwrap().to_str().unwrap());
    assert_eq!(d.size, bytes.len());
    assert_eq!(d.class_count, 1);
    assert_eq!(d.header_file_size, Some(bytes.len() as u32));
    assert_eq!(d.checksum_ok, Some(true));
    assert_eq!(d.sha1_ok, Some(true));
    // The map's last-by-offset item is the map_list itself; its extent is
    // 4 + count*12 bytes, ending exactly at the end of the file.
    assert_eq!(d.data_end, Some(bytes.len()));
    assert_eq!(d.coverage_note, None);
    assert_eq!(d.tail_bytes, Some(0));
    assert_eq!(d.tail_entropy, None); // no tail -> nothing to measure

    assert_eq!(r.packer.packed, None);
    assert!(r.packer.signals.is_empty());
    assert!(r.anomalies.is_empty(), "{:?}", r.anomalies);
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert!(r.complete);
}

#[test]
fn appended_bytes_are_counted_exactly_and_flagged_as_a_candidate() {
    // Above TAIL_FLAG (64 KiB) so inspect names it an appended-payload
    // candidate; far below the 1 MiB sample cap.
    let spec = Spec {
        tail: (0..96_000).map(|i| (i % 251) as u8).collect(),
        ..Spec::one("Lcom/example/Probe;")
    };
    let tail_len = spec.tail.len();
    let bytes = build_dex(&spec);
    let path = write_dex("tail", &bytes);
    let r = run_inspect(&path).unwrap();
    remove(&path);

    let d = &r.dex[0];
    assert_eq!(d.data_end, Some(bytes.len() - tail_len));
    assert_eq!(d.tail_bytes, Some(tail_len as u64));
    assert!(d.tail_entropy.is_some());
    assert_eq!(d.coverage_note, None);
    // Entropy and trailing bytes alone never name a packer.
    assert_eq!(r.packer.packed, None);

    let anomaly = r
        .anomalies
        .iter()
        .find(|a| a.contains("appended-payload candidate"))
        .unwrap_or_else(|| panic!("no appended-payload anomaly: {:?}", r.anomalies));
    assert!(anomaly.contains(&tail_len.to_string()), "{anomaly}");
    // Appending also makes the header's file_size disagree with the entry.
    let fs_anomaly = r
        .anomalies
        .iter()
        .find(|a| a.contains("header file_size"))
        .unwrap_or_else(|| panic!("no file_size anomaly: {:?}", r.anomalies));
    assert!(
        fs_anomaly.contains(&bytes.len().to_string()),
        "{fs_anomaly}"
    );
}

#[test]
fn inexact_map_extent_reports_unknown_coverage_not_zero() {
    // The last item by offset is a `code_item`, whose size is a method
    // count rather than a byte length, so no exact extent can be derived.
    let spec = Spec {
        map: MapShape::VariableExtent,
        ..Spec::one("Lcom/example/Probe;")
    };
    let bytes = build_dex(&spec);
    let path = write_dex("unknown", &bytes);
    let r = run_inspect(&path).unwrap();
    remove(&path);

    let d = &r.dex[0];
    assert_eq!(d.data_end, None);
    assert_eq!(d.tail_bytes, None);
    assert_eq!(d.tail_entropy, None);
    assert!(d.coverage_note.is_some(), "coverage_note must explain why");
    // The rest of the analysis is unaffected.
    assert_eq!(d.class_count, 1);
    assert_eq!(d.checksum_ok, Some(true));
    assert!(
        !r.complete,
        "unknown coverage must not report a complete survey"
    );
    // The file ends exactly at its declared extent, yet coverage stays
    // unknown instead of being reported as 0 tail bytes.
    assert!(
        !r.anomalies
            .iter()
            .any(|a| a.contains("bytes past declared"))
    );
}

#[test]
fn data_end_is_the_map_extent_not_the_header_file_size() {
    // The map claims 128 string_id entries at the last offset — a byte
    // extent the builder does not write — so the exact extent ends before
    // the header's file_size. The 40 bytes of padding the header declares
    // are real content, the 64 appended bytes are not: tail_bytes counts
    // the map extent, not file_size.
    let spec = Spec {
        oversize_map_item: Some(128),
        tail: vec![0xAB; 64],
        ..Spec::one("Lcom/example/Probe;")
    };
    let bytes = build_dex(&spec);
    let map_off = 176; // constant for a one-class DEX
    let path = write_dex("overclaim", &bytes);
    let r = run_inspect(&path).unwrap();
    remove(&path);

    let d = &r.dex[0];
    assert_eq!(
        d.data_end,
        Some(map_off + 128),
        "note={:?}",
        d.coverage_note
    );
    assert_eq!(d.header_file_size, Some((bytes.len() - 64) as u32));
    assert_eq!(d.size, bytes.len());
    assert_eq!(d.tail_bytes, Some(64));
    assert_eq!(d.coverage_note, None);
}

/// Both halves of the stub descriptor carry the same hex.
const VIRBOX_STUB: &str = "Lv1296851e/l1296851e;";
/// The literal marker string; inspect scans the DEX bytes for it.
const VIRBOX_MARKER: &str = "Virbox";

#[test]
fn virbox_stub_apk_with_a_single_asset_does_not_name_the_packer() {
    // Stub class + one ABI + the marker string the stub class itself
    // contributes: one real signal, the string is a consequence of the
    // stub. Still below the naming threshold.
    let dex = build_dex(&Spec::with(&["Lcom/example/Probe;", VIRBOX_STUB]));
    let path = write_apk(
        "stub-one-abi",
        &[
            ("classes.dex", &dex),
            ("assets/l1296851e_a32.so", b"\x7fELF arm32"),
        ],
    );
    let r = run_inspect(&path).unwrap();
    remove(&path);

    assert_eq!(r.dex[0].class_count, 2);
    assert!(r.packer.packed.is_none(), "{:?}", r.packer.signals);
    assert!(
        !r.packer.signals.iter().any(|s| s.contains("ABIs")),
        "one ABI is not an asset family: {:?}",
        r.packer.signals
    );
}

#[test]
fn apk_with_two_virbox_signals_names_virbox() {
    // Two independent signals: the stub class, and an `l<hex>_<abi>.so`
    // family spanning two ABIs. The marker string travels along.
    let spec = Spec::with(&["Lcom/example/Probe;", VIRBOX_STUB, VIRBOX_MARKER]);
    let dex = build_dex(&spec);
    assert!(
        dex.windows(VIRBOX_MARKER.len())
            .any(|w| w == VIRBOX_MARKER.as_bytes())
    );
    let path = write_apk(
        "virbox",
        &[
            ("classes.dex", &dex),
            ("assets/l1296851e_a32.so", b"\x7fELF fake arm32"),
            ("assets/l1296851e_a64.so", b"\x7fELF fake arm64"),
        ],
    );
    let r = run_inspect(&path).unwrap();
    remove(&path);

    assert_eq!(r.input, "apk");
    assert_eq!(r.entry_count, 3);
    assert_eq!(r.dex.len(), 1);
    assert_eq!(r.dex[0].class_count, 3);
    assert_eq!(r.dex[0].checksum_ok, Some(true));
    assert_eq!(r.dex[0].sha1_ok, Some(true));
    assert_eq!(r.dex[0].tail_bytes, Some(0));

    assert_eq!(r.packer.packed, Some("virbox"));
    assert!(
        r.packer.signals.len() >= 2,
        "expected >=2 signals, got {:?}",
        r.packer.signals
    );
    // No AndroidManifest.xml here: the cross-check is skipped, not passed.
    assert!(r.manifest.is_none());
    assert!(
        r.errors.iter().any(|e| e.starts_with("manifest:")),
        "{:?}",
        r.errors
    );
}

#[test]
fn a_single_virbox_signal_never_names_the_packer() {
    // Marker string only, in an otherwise ordinary APK.
    let dex = build_dex(&Spec::with(&["Lcom/example/Probe;", VIRBOX_MARKER]));
    let path = write_apk("one-signal", &[("classes.dex", &dex)]);
    let r = run_inspect(&path).unwrap();
    remove(&path);

    assert_eq!(r.dex.len(), 1);
    assert_eq!(r.dex[0].class_count, 2);
    assert_eq!(
        r.packer.signals.len(),
        1,
        "the marker string alone is the only signal: {:?}",
        r.packer.signals
    );
    assert_eq!(r.packer.packed, None);
}

#[test]
fn corrupted_checksum_is_reported_and_sha1_still_verifies() {
    // Byte-for-byte valid DEX, except for the stored adler32.
    let good = build_dex(&Spec::one("Lcom/example/Probe;"));
    let real = adler2::adler32(&good[0x0C..]).unwrap();
    let spec = Spec {
        checksum: Some(real ^ 0xFFFF_FFFF),
        ..Spec::one("Lcom/example/Probe;")
    };
    let bytes = build_dex(&spec);
    let path = write_dex("badsig", &bytes);
    let r = run_inspect(&path).unwrap();
    remove(&path);

    let d = &r.dex[0];
    assert_eq!(d.class_count, 1);
    assert_eq!(d.checksum_ok, Some(false));
    // The signature covers [0x20, file_size) and is untouched, so it must
    // still verify: the failure is localised, not blanket.
    assert_eq!(d.sha1_ok, Some(true));
    assert_eq!(d.tail_bytes, Some(0));
    assert!(
        r.anomalies
            .iter()
            .any(|a| a.contains("checksum/SHA-1 mismatch")),
        "{:?}",
        r.anomalies
    );
    // A bad checksum is not packer evidence.
    assert_eq!(r.packer.packed, None);
}

/// A `class_def` whose `class_idx` points past the type pool. The DEX
/// parses, but class collection fails partway — the descriptors it did
/// collect are an unknown subset, so `inspect` must not present the
/// manifest cross-check built on them as definite (audit F05).
#[test]
fn partial_class_collection_marks_the_report_incomplete() {
    let n = 3usize;
    let type_ids_off = STRING_IDS_OFF + n * 4;
    let class_defs_off = type_ids_off + n * 4;
    // The first class_def is the one we damage, so `class_count == 0`
    // is the *observed* count; the point of the test is that a zero
    // here can never be read as "this DEX defines no classes".
    let mut broken = build_dex(&Spec::with(&[
        "Lcom/example/A;",
        "Lcom/example/B;",
        "Lcom/example/C;",
    ]));
    broken[class_defs_off..class_defs_off + 4].copy_from_slice(&0xFFFFu32.to_le_bytes());
    let path = write_apk("partial_classes", &[("classes.dex", &broken)]);
    let r = run_inspect(&path).unwrap();
    remove(&path);

    let dex = &r.dex[0];
    assert_eq!(dex.class_count, 0, "no class_def is readable");
    let note = dex
        .coverage_note
        .as_deref()
        .expect("partial class collection must be reported");
    assert!(
        note.contains("class collection incomplete"),
        "coverage_note must name the failure, got {note:?}"
    );
    assert!(
        r.errors
            .iter()
            .any(|e| e.contains("class collection incomplete")),
        "the aggregated error list must carry it too: {:?}",
        r.errors
    );
    assert!(
        !r.complete,
        "a partial class list cannot be a complete survey"
    );
}

#[test]
fn garbage_input_never_panics() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("short", b"dex\n035".to_vec()),
        ("no-checksum", b"dex\n035\0\x00\x00\x00\x00".to_vec()),
        ("header-only", {
            let mut b = vec![0u8; 0x70];
            b[..8].copy_from_slice(b"dex\n035\0");
            b
        }),
        ("bad-magic", b"NOTADEX!".to_vec()),
        (
            "truncated-tail",
            build_dex(&Spec::one("Lcom/example/Probe;"))[..200].to_vec(),
        ),
        ("zip-header-only", b"PK\x03\x04".to_vec()),
    ];

    for (name, bytes) in cases {
        let p = write_dex(name, &bytes);
        match run_inspect(&p) {
            Ok(r) => {
                assert!(!r.complete, "{name}: garbage cannot be a complete survey");
                // Whatever could not be read must say so on the DEX row.
                assert!(
                    r.dex
                        .iter()
                        .all(|d| d.data_end.is_some() || d.coverage_note.is_some()),
                    "{name}: unexplained coverage"
                );
            }
            Err(e) => {
                assert!(!e.to_string().is_empty(), "{name}: empty error message");
            }
        }
        remove(&p);
    }
}

// ------------------------------------------------------------------ hermes

/// Verified against the Meta header (`BytecodeFileFormat.h`,
/// MAGIC = 0x1F1903C103BC1FC6 little-endian) and a real
/// `assets/index.android.bundle`.
const HERMES_MAGIC: [u8; 8] = [0xC6, 0x1F, 0xBC, 0x03, 0xC1, 0x03, 0x19, 0x1F];

fn hermes_blob(version: u32, file_length: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&HERMES_MAGIC);
    b.extend_from_slice(&version.to_le_bytes());
    b.extend_from_slice(&[0u8; 20]); // sourceHash
    b.extend_from_slice(&file_length.to_le_bytes());
    b.extend_from_slice(&[0x55u8; 128]); // body
    b
}

#[test]
fn hermes_entry_is_classified_and_header_fields_read() {
    let blob = hermes_blob(96, 164);
    let apk = write_apk("hermes_ok", &[("assets/index.android.bundle", &blob)]);
    let r = run_inspect(&apk).expect("inspect");
    let entry = r
        .entries
        .iter()
        .find(|e| e.name == "assets/index.android.bundle")
        .expect("entry present");
    assert_eq!(entry.kind, "hermes");
    let h = r.hermes.first().expect("hermes info recorded");
    assert_eq!(h.version, 96);
    assert_eq!(h.file_length, 164);
    assert_eq!(h.size, 164);
    assert!(
        !r.anomalies.iter().any(|a| a.contains("hermes fileLength")),
        "matching fileLength must not be an anomaly: {:?}",
        r.anomalies
    );
    // No manifest in this synthetic APK: the report honestly stays
    // incomplete (errors non-empty); completeness is not asserted.
}

#[test]
fn hermes_file_length_mismatch_is_an_anomaly() {
    let blob = hermes_blob(96, 4096); // declares 4096, actually 160
    let apk = write_apk("hermes_bad", &[("assets/hbc.bundle", &blob)]);
    let r = run_inspect(&apk).expect("inspect");
    assert!(
        r.anomalies
            .iter()
            .any(|a| a.contains("hermes fileLength 4096 != actual 164")),
        "{:?}",
        r.anomalies
    );
    remove(&apk);
}

// -------------------------------------------------- split awareness (corpus)

fn corpus_locket() -> Option<PathBuf> {
    let p =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus/apk/com.locket.Locket.apk");
    p.exists().then_some(p)
}

/// Locket is distributed as split APKs: the base requires
/// `base__abi` + `base__density` and ships no `lib/*.so`. `inspect`
/// must flag that absence-of-evidence trap, and `native` must note it.
#[test]
fn split_requirement_without_libs_is_flagged_on_locket() {
    let Some(path) = corpus_locket() else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let r = run_inspect(&path).expect("inspect");
    let sp = r.split.as_ref().expect("split status present");
    assert_eq!(
        sp.required_split_types.as_deref(),
        Some("base__abi,base__density")
    );
    assert!(!sp.has_native_libs, "base APK ships no native libs");
    assert!(sp.abi_split_missing());
    assert!(
        r.anomalies
            .iter()
            .any(|a| a.contains("native code may live")),
        "{:?}",
        r.anomalies
    );
    // The hermes bundle must be inventoried with the version verified
    // against the real file (96).
    assert!(
        r.hermes
            .iter()
            .any(|h| h.name == "assets/index.android.bundle" && h.version == 96),
        "{:?}",
        r.hermes
    );

    let n = crate_run_native(&path);
    assert!(
        n.note
            .as_deref()
            .is_some_and(|t| t.contains("split APKs that were not provided")),
        "native note: {:?}",
        n.note
    );
}

fn crate_run_native(path: &Path) -> asc_core::NativeReport {
    asc_core::run_native(path).expect("native")
}
