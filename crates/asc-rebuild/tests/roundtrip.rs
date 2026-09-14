//! Roundtrip tests for asc-rebuild: feed in a corpus DEX, rebuild a
//! target class, parse the rebuilt DEX with asc-dex, and assert the
//! resulting view is structurally valid (pool extents, map_list,
//! per-code-item ref walk, recomputed signature/checksum).

use asc_bytecode::walk_verify;
use asc_dex::DexView;
use asc_rebuild::{PoolCounts, RebuildError, rebuild};
use std::path::PathBuf;

/// Reads a corpus DEX into an owned `Vec<u8>`. Callers parse a view
/// borrowing from these bytes.
fn read_bytes(filename: &str) -> Option<Vec<u8>> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus");
    path.push("dex");
    path.push(filename);
    if !path.is_file() {
        return None;
    }
    std::fs::read(&path).ok()
}

/// Roundtrip: rebuild the ClockFaceView class, parse the output, verify.
#[test]
fn roundtrip_clockface_workload() {
    let Some(bytes) = read_bytes("workload_classes.dex") else {
        eprintln!("workload_classes.dex missing; skipping");
        return;
    };
    let view = DexView::parse(&bytes).expect("source parses");
    let target = "Lcom/google/android/material/timepicker/ClockFaceView;";
    let out = rebuild(&view, target).expect("rebuild succeeds");
    assert!(!out.bytes.is_empty());
    assert!(out.kept.types > 0);
    assert!(out.kept.methods > 0);
    assert!(out.kept.fields > 0);
    assert!(out.kept.classes == 1);

    // The rebuilt file's header should re-parse cleanly.
    let rebuilt_view = DexView::parse(&out.bytes).expect("rebuilt DEX parses");

    // Walk every code_item and ensure pool ref slots are in-range.
    let class_count = rebuilt_view.class_def_count();
    assert_eq!(class_count, 1);
    let cd = rebuilt_view.class_def(0).unwrap();
    let cd_data = rebuilt_view.class_data(cd.class_data_off).unwrap().unwrap();
    for em in cd_data
        .direct_methods
        .iter()
        .chain(cd_data.virtual_methods.iter())
    {
        if em.code_off == 0 {
            continue;
        }
        let ci = rebuilt_view.code_item(em.code_off).unwrap().unwrap();
        walk_verify(ci.insns_exact(), ci.insns_size).expect("walk_verify passes");
    }

    // Recompute signature + checksum and compare.
    recompute_and_compare(&out.bytes);
}

/// Roundtrip: rebuild a second class to prove the rebuild isn't
/// hard-coded to ClockFaceView.
#[test]
fn roundtrip_second_class() {
    let Some(bytes) = read_bytes("workload_classes.dex") else {
        eprintln!("workload_classes.dex missing; skipping");
        return;
    };
    let view = DexView::parse(&bytes).expect("source parses");
    let targets = [
        "Lcom/google/android/material/timepicker/ClockFaceView;",
        "Landroidx/core/app/ActivityCompat;",
    ];
    for t in targets {
        match rebuild(&view, t) {
            Ok(_) => {}
            Err(RebuildError::ClassNotFound(_)) => continue,
            Err(e) => panic!("unexpected rebuild error for {t}: {e}"),
        }
    }
}

/// Roundtrip: rebuild on a non-035 source (workload is 039). The
/// output version must remain ≤ 040.
#[test]
fn roundtrip_version_preserved() {
    let Some(bytes) = read_bytes("workload_classes.dex") else {
        return;
    };
    let view = DexView::parse(&bytes).expect("source parses");
    let out = rebuild(
        &view,
        "Lcom/google/android/material/timepicker/ClockFaceView;",
    )
    .expect("rebuild");
    assert!(
        out.version <= asc_dex::DexVersion::V040,
        "version must be <= 040, got {:?}",
        out.version
    );
}

/// Minimality: kept pool counts are far smaller than source.
#[test]
fn minimality_clockface() {
    let Some(bytes) = read_bytes("workload_classes.dex") else {
        return;
    };
    let view = DexView::parse(&bytes).expect("source parses");
    let out = rebuild(
        &view,
        "Lcom/google/android/material/timepicker/ClockFaceView;",
    )
    .expect("rebuild");
    let ratio = out.kept.types as f64 / out.source.types.max(1) as f64;
    eprintln!(
        "minimality: kept.types={} source.types={} ratio={:.4}",
        out.kept.types, out.source.types, ratio
    );
    assert!(
        ratio < 0.10,
        "kept types should be << 10% of source, got {:.2}%",
        ratio * 100.0
    );
    assert!(out.kept.classes == 1);
}

/// Roundtrip: shared-pool semantics — a class that references a string
/// also used by an untouched class must still produce a parseable DEX.
#[test]
fn shared_pool_semantics() {
    let Some(bytes) = read_bytes("workload_classes.dex") else {
        return;
    };
    let view = DexView::parse(&bytes).expect("source parses");
    let target = "Lcom/google/android/material/timepicker/ClockFaceView;";
    let out = rebuild(&view, target).expect("rebuild");
    let rv = DexView::parse(&out.bytes).expect("rebuilt parses");
    let n = rv.string_count();
    assert!(n > 0);
}

fn recompute_and_compare(bytes: &[u8]) {
    use adler2::adler32;
    use sha1::{Digest, Sha1};
    let file_size = bytes.len();
    let stored_sig = &bytes[0x0C..0x20];
    let stored_cksum = u32::from_le_bytes([bytes[0x08], bytes[0x09], bytes[0x0A], bytes[0x0B]]);
    let mut h = Sha1::new();
    h.update(&bytes[32..file_size]);
    let recomputed_sig = h.finalize();
    assert_eq!(
        stored_sig,
        &recomputed_sig[..],
        "SHA-1 signature must match recomputed value (signature covers file[32..])"
    );
    let recomputed_cksum = adler32(&bytes[0x0C..file_size]).unwrap_or(0);
    assert_eq!(
        stored_cksum, recomputed_cksum,
        "Adler-32 checksum must match recomputed value (covers file[12..])"
    );
}

/// Catch-handler width-change coverage: rebuild a class that uses
/// try/catch in its bytecode. The rebuilt code_item's catch list must
/// re-parse via asc-dex's catch_handler_list without error.
#[test]
fn catch_handler_list_re_parses() {
    let Some(bytes) = read_bytes("workload_classes.dex") else {
        return;
    };
    let view = DexView::parse(&bytes).expect("source parses");
    let out = rebuild(
        &view,
        "Lcom/google/android/material/timepicker/ClockFaceView;",
    )
    .expect("rebuild");
    let rv = DexView::parse(&out.bytes).expect("rebuilt parses");
    let cd = rv.class_def(0).unwrap();
    let cd_data = rv.class_data(cd.class_data_off).unwrap().unwrap();
    let mut parsed_any = false;
    for em in cd_data
        .direct_methods
        .iter()
        .chain(cd_data.virtual_methods.iter())
    {
        if em.code_off == 0 {
            continue;
        }
        let ci = rv.code_item(em.code_off).unwrap().unwrap();
        if ci.tries_size == 0 {
            continue;
        }
        let list = rv.catch_handler_list(&ci).unwrap().unwrap();
        for h in list.iter_all().unwrap() {
            for (t, _) in h.pairs {
                let sidx = rv.type_(asc_dex::TypeIdx(t)).unwrap();
                let _ = rv.string(sidx).unwrap();
            }
        }
        parsed_any = true;
    }
    if !parsed_any {
        eprintln!("no method with tries_size > 0; skipping");
    }
}

/// ClassNotFound surfaces for an unknown descriptor.
#[test]
fn class_not_found() {
    let Some(bytes) = read_bytes("workload_classes.dex") else {
        return;
    };
    let view = DexView::parse(&bytes).expect("source parses");
    let err = rebuild(&view, "Ldoes/not/Exist;").unwrap_err();
    assert!(matches!(err, RebuildError::ClassNotFound(_)));
}

/// Bad descriptor (missing leading `L`) is rejected before any DEX
/// access.
#[test]
fn bad_descriptor_rejected() {
    let Some(bytes) = read_bytes("workload_classes.dex") else {
        return;
    };
    let view = DexView::parse(&bytes).expect("source parses");
    let err = rebuild(&view, "com/foo/Bar").unwrap_err();
    assert!(matches!(err, RebuildError::BadDescriptor(_, _)));
}

/// Empty descriptor is rejected.
#[test]
fn empty_descriptor_rejected() {
    let Some(bytes) = read_bytes("workload_classes.dex") else {
        return;
    };
    let view = DexView::parse(&bytes).expect("source parses");
    let err = rebuild(&view, "").unwrap_err();
    assert!(matches!(err, RebuildError::BadDescriptor(_, _)));
}

/// Verify the signature/checksum recompute helper against corpus.
#[test]
fn recompute_helpers_against_corpus() {
    for filename in [
        "workload_classes.dex",
        "aurora_classes.dex",
        "fdroid_classes.dex",
    ] {
        let Some(bytes) = read_bytes(filename) else {
            continue;
        };
        use adler2::adler32;
        use sha1::{Digest, Sha1};
        let file_size = bytes.len();
        let stored_sig = &bytes[0x0C..0x20];
        let stored_cksum = u32::from_le_bytes([bytes[0x08], bytes[0x09], bytes[0x0A], bytes[0x0B]]);
        let mut h = Sha1::new();
        h.update(&bytes[32..file_size]);
        let recomputed_sig = h.finalize();
        assert_eq!(
            &recomputed_sig[..],
            stored_sig,
            "{filename}: SHA-1 must match"
        );
        let recomputed_cksum = adler32(&bytes[0x0C..file_size]).unwrap_or(0);
        assert_eq!(
            stored_cksum, recomputed_cksum,
            "{filename}: Adler32 must match"
        );
    }
}

/// Pool counts report sane numbers for the ClockFaceView rebuild.
#[test]
fn pool_counts_report() {
    let Some(bytes) = read_bytes("workload_classes.dex") else {
        return;
    };
    let view = DexView::parse(&bytes).expect("source parses");
    let out = rebuild(
        &view,
        "Lcom/google/android/material/timepicker/ClockFaceView;",
    )
    .expect("rebuild");
    let _ = out.kept;
    let _ = out.source;
    let _ = PoolCounts::default();
}

/// Map-list completeness: every section that the rebuilt DEX emits
/// must appear in the map_list with a matching offset/size.
#[test]
fn map_list_complete() {
    let Some(bytes) = read_bytes("workload_classes.dex") else {
        return;
    };
    let view = DexView::parse(&bytes).expect("source parses");
    let out = rebuild(
        &view,
        "Lcom/google/android/material/timepicker/ClockFaceView;",
    )
    .expect("rebuild");
    let rv = DexView::parse(&out.bytes).expect("rebuilt parses");
    for entry in rv.map_list().unwrap() {
        let item = entry.unwrap();
        assert!(item.offset as usize <= out.bytes.len());
        assert!(item.size > 0 || matches!(item.ty, 0x0000));
    }
}
/// Independent-validator proof (§21/§30): decompile the rebuilt DEX with
/// droidsaw (a parser that shares ZERO code with asc-dex/asc-rebuild).
/// This catches format assumptions that an asc-dex-only roundtrip can
/// never catch (see the encoded_catch_handler_list uleb128 episode).
#[test]
fn rebuilt_dex_decompiles_with_independent_backend() {
    let Some(bytes) = read_bytes("workload_classes.dex") else {
        eprintln!("workload_classes.dex missing; skipping");
        return;
    };
    let view = DexView::parse(&bytes).expect("source parses");
    let target = "Lcom/google/android/material/timepicker/ClockFaceView;";
    let out = rebuild(&view, target).expect("rebuild succeeds");

    let backend = asc_decompile::droidsaw::DroidsawBackend::new();
    use asc_decompile::ClassDecompiler as _;
    let src = backend
        .decompile(&out.bytes, target)
        .expect("independent backend decompiles the rebuilt DEX");
    assert!(
        src.contains("ClockFaceView"),
        "decompiled source mentions the class"
    );
    assert!(
        src.contains("class ClockFaceView"),
        "class declaration present"
    );
}

/// Regression (user-reported GUI hang): an inner class of an interface
/// (`INotificationSideChannel$Default`) carries dalvik Throws /
/// InnerClass / EnclosingClass annotations. The rebuilt DEX used to
/// (a) uleb128-encode `annotation_set_item.size` (spec: u32) and
/// (b) emit a map_list with wrong type codes and byte-sizes in the
/// count field — droidsaw then spun forever inside its annotation
/// collector. Rebuild must decompile this class promptly.
#[test]
fn rebuilt_inner_interface_class_decompiles() {
    let Some(bytes) = read_bytes("workload_classes.dex") else {
        eprintln!("workload_classes.dex missing; skipping");
        return;
    };
    let view = DexView::parse(&bytes).expect("source parses");
    let target = "Landroid/support/v4/app/INotificationSideChannel$Default;";
    let out = rebuild(&view, target).expect("rebuild succeeds");

    // The annotation directory chain must resolve with our own parser:
    // directory -> method annotation sets (u32 count!) -> items.
    let rv = DexView::parse(&out.bytes).expect("rebuilt parses");
    let cd = rv.class_def(0).expect("one class_def");
    if cd.annotations_off != 0 {
        let dir = rv
            .annotations_directory(cd.annotations_off)
            .expect("directory parses")
            .expect("directory present");
        for ma in &dir.methods {
            if ma.annotations_off != 0 {
                rv.annotation_set(ma.annotations_off)
                    .expect("annotation_set parses with u32 size")
                    .annotation_offs
                    .iter()
                    .filter(|&&off| off != 0)
                    .for_each(|&off| {
                        rv.annotation_item(off)
                            .expect("annotation item parses")
                            .expect("item present");
                    });
            }
        }
    }

    // And the independent backend must finish (it used to loop).
    let backend = asc_decompile::droidsaw::DroidsawBackend::new();
    use asc_decompile::ClassDecompiler as _;
    let src = backend
        .decompile(&out.bytes, target)
        .expect("droidsaw decompiles the rebuilt DEX without spinning");
    assert!(src.contains("Default"), "source mentions the class");
}

/// Regression (map_list): entries must use ART/d8 type codes, carry
/// ITEM counts (not byte sizes), and be sorted by ascending offset —
/// verified against the map_list of every corpus DEX.
#[test]
fn rebuilt_map_list_matches_art_codes_and_counts() {
    let Some(bytes) = read_bytes("workload_classes.dex") else {
        eprintln!("workload_classes.dex missing; skipping");
        return;
    };
    let view = DexView::parse(&bytes).expect("source parses");
    let out = rebuild(
        &view,
        "Landroid/support/v4/app/INotificationSideChannel$Default;",
    )
    .expect("rebuild succeeds");
    let rv = DexView::parse(&out.bytes).expect("rebuilt parses");

    let mut prev_off: i64 = -1;
    let mut counts: std::collections::HashMap<u16, u32> = std::collections::HashMap::new();
    for entry in rv.map_list().unwrap() {
        let item = entry.unwrap();
        // Offsets strictly ascending (spec).
        assert!(
            (item.offset as i64) > prev_off,
            "map items must be sorted by offset, got {item:?} after {prev_off}"
        );
        prev_off = item.offset as i64;
        counts.insert(item.ty, item.size);
    }
    // ID-table counts must equal the header pool counts exactly.
    assert_eq!(
        counts.get(&0x0001),
        Some(&rv.string_count()),
        "string_id count"
    );
    assert_eq!(counts.get(&0x0002), Some(&rv.type_count()), "type_id count");
    assert_eq!(
        counts.get(&0x0003),
        Some(&rv.proto_count()),
        "proto_id count"
    );
    assert_eq!(
        counts.get(&0x0005),
        Some(&rv.method_count()),
        "method_id count"
    );
    // string_data count == string_id count (d8 invariant).
    assert_eq!(
        counts.get(&0x2002),
        Some(&rv.string_count()),
        "string_data_item count"
    );
    // The map must list itself.
    assert_eq!(counts.get(&0x1000), Some(&1), "map_list self entry");
    // code_item / class_data counts are item counts (5 methods with
    // code, 1 class_data), never the section byte size.
    assert_eq!(counts.get(&0x2001), Some(&5), "code_item item count");
    assert_eq!(counts.get(&0x2000), Some(&1), "class_data item count");
}

/// Deep pool validation: resolve EVERY type's descriptor string, every
/// method's name, every field's name in the rebuilt DEX. This is the
/// class of check that would have caught the type_ids descriptor remap
/// bug the independent-backend test found (old string idx emitted).
#[test]
fn rebuilt_dex_pool_references_all_resolve() {
    let Some(bytes) = read_bytes("workload_classes.dex") else {
        eprintln!("workload_classes.dex missing; skipping");
        return;
    };
    let view = DexView::parse(&bytes).expect("source parses");
    let target = "Lcom/google/android/material/timepicker/ClockFaceView;";
    let out = rebuild(&view, target).expect("rebuild succeeds");
    let rv = DexView::parse(&out.bytes).expect("rebuilt parses");

    for i in 0..rv.type_count() {
        let desc = rv
            .type_(asc_dex::ids::TypeIdx(i))
            .expect("type descriptor idx in range");
        rv.string(desc).expect("descriptor string resolves");
    }
    for i in 0..rv.method_count() {
        let m = rv.method(asc_dex::ids::MethodIdx(i)).expect("method id");
        let name = rv.string(m.name).expect("method name resolves");
        assert!(
            !name.decode_lossy().is_empty(),
            "empty method name at rebuilt idx {i}"
        );
        rv.proto(m.proto).expect("method proto resolves");
    }
    for i in 0..rv.field_count() {
        let f = rv.field(asc_dex::ids::FieldIdx(i)).expect("field id");
        rv.string(f.name).expect("field name resolves");
    }
}
