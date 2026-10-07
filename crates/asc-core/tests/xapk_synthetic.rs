//! Synthetic XAPK tests: a container ZIP holding two member APKs
//! (a DEX-less `config.arm64_v8a` split carrying one `.so`, and a member
//! whose `classes.dex` is garbage) — plus the corpus Locket XAPK when
//! present. CI-relevant semantics: role comes from the manifest (absent
//! here → `unknown`, never guessed), provenance stays per-member, and a
//! bad DEX is a member-level error, not a container failure.

use std::io::Write as _;

fn zip_bytes(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in entries {
        w.start_file(*name, opts).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn write_zip(path: &std::path::Path, entries: &[(&str, Vec<u8>)]) {
    std::fs::write(path, zip_bytes(entries)).unwrap();
}

/// Same, but every entry is DEFLATE-compressed (the payloads used with
/// this are highly compressible, so the container stays tiny on disk).
fn zip_bytes_deflated(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, data) in entries {
        w.start_file(*name, opts).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// Rewrite every central-directory record's declared uncompressed size.
/// Used to manufacture members whose header lies about the payload size
/// (both `Apk` and `ZipView` trust the central directory for it).
fn override_cd_uncompressed_size(bytes: &mut [u8], value: u32) {
    let mut i = 0usize;
    while i + 46 <= bytes.len() {
        if bytes[i..i + 4] == *b"PK\x01\x02" {
            bytes[i + 24..i + 28].copy_from_slice(&value.to_le_bytes());
            let name_len = u16::from_le_bytes([bytes[i + 28], bytes[i + 29]]) as usize;
            let extra_len = u16::from_le_bytes([bytes[i + 30], bytes[i + 31]]) as usize;
            let comment_len = u16::from_le_bytes([bytes[i + 32], bytes[i + 33]]) as usize;
            i += 46 + name_len + extra_len + comment_len;
        } else {
            i += 1;
        }
    }
}

/// A minimal member APK: one stored (non-DEX) `classes.dex`.
fn member_apk() -> Vec<u8> {
    zip_bytes(&[("classes.dex", b"not a dex".to_vec())])
}

#[test]
fn synthetic_xapk_member_isolation() {
    // Member A: split-style APK with one native lib, no manifest.
    let mut split = std::io::Cursor::new(Vec::new());
    {
        let mut w = zip::ZipWriter::new(&mut split);
        let opts =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        w.start_file("lib/arm64-v8a/libfoo.so", opts).unwrap();
        w.write_all(b"\x7fELFfake").unwrap();
        w.finish().unwrap();
    }
    // Member B: APK whose only DEX is garbage (member-level error).
    let mut broken = std::io::Cursor::new(Vec::new());
    {
        let mut w = zip::ZipWriter::new(&mut broken);
        let opts =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        w.start_file("classes.dex", opts).unwrap();
        w.write_all(b"not a dex").unwrap();
        w.finish().unwrap();
    }
    let xapk = std::env::temp_dir().join("asc-xapk-synthetic.zip");
    write_zip(
        &xapk,
        &[
            ("config.arm64_v8a.apk", split.into_inner()),
            ("broken.apk", broken.into_inner()),
            ("manifest.json", b"{}".to_vec()), // ignored: not an APK
        ],
    );
    let r = asc_core::xapk::run_xapk(&xapk).expect("run");
    assert_eq!(r.members.len(), 2, "manifest.json is not a member");
    assert!(r.complete, "errors: {:?}", r.errors);
    let split = &r.members[0];
    // No manifest entry → role unknown, NEVER inferred from the filename.
    assert_eq!(split.role, "unknown");
    assert!(split.manifest.is_none());
    assert!(split.manifest_error.is_some());
    assert_eq!(split.native_libs, ["lib/arm64-v8a/libfoo.so"]);
    assert_eq!(split.abi_dirs, ["arm64-v8a"]);
    assert!(split.dex.is_empty());
    let broken = &r.members[1];
    assert_eq!(broken.role, "unknown");
    assert_eq!(broken.dex.len(), 1);
    assert_eq!(broken.dex[0].classes, 0);
    assert!(broken.dex[0].error.is_some());
    // Corrupt DEX content is a per-DEX data error, NOT a traversal
    // failure: both the member and the container stay complete.
    assert!(broken.complete);
    let _ = std::fs::remove_file(&xapk);
}

/// F03: an oversized NON-DEX entry must not appear as a `MemberDex`.
/// The huge asset is DEFLATED (300 MiB uncompressed, tiny on disk) and
/// never inflated at all.
#[test]
fn oversized_non_dex_asset_is_not_a_dex() {
    let mut member = std::io::Cursor::new(Vec::new());
    {
        let mut w = zip::ZipWriter::new(&mut member);
        let opts =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        w.start_file("assets/huge.bin", opts).unwrap();
        let zeros = vec![0u8; 1 << 20];
        for _ in 0..300 {
            w.write_all(&zeros).unwrap();
        }
        w.finish().unwrap();
    }
    let xapk = std::env::temp_dir().join("asc-xapk-huge-asset.zip");
    write_zip(&xapk, &[("config.asset.apk", member.into_inner())]);
    let r = asc_core::xapk::run_xapk(&xapk).expect("run");
    assert!(r.complete, "errors: {:?}", r.errors);
    let m = &r.members[0];
    assert!(
        m.dex.is_empty(),
        "oversized asset leaked into dex: {:?}",
        m.dex
    );
    assert!(m.complete);
    let text = asc_core::xapk::format_xapk_text(&r);
    assert!(!text.contains("assets/huge.bin"));
    let _ = std::fs::remove_file(&xapk);
}

/// F04: a member that is not a readable ZIP makes the report partial
/// (exit 2 at the CLI), with the reason kept distinct from a missing
/// manifest or a bad DEX.
#[test]
fn unreadable_member_makes_report_incomplete() {
    let xapk = std::env::temp_dir().join("asc-xapk-unreadable.zip");
    write_zip(
        &xapk,
        &[
            ("garbage.apk", b"definitely not a zip".to_vec()),
            ("manifest.json", b"{}".to_vec()),
        ],
    );
    let r = asc_core::xapk::run_xapk(&xapk).expect("run");
    assert!(!r.complete, "unreadable member must be partial");
    let m = &r.members[0];
    assert!(!m.complete);
    assert!(m.manifest.is_none());
    assert!(m.dex.is_empty());
    let why = m.manifest_error.as_deref().unwrap();
    assert!(why.contains("not a readable ZIP"), "got: {why}");
    let text = asc_core::xapk::format_xapk_text(&r);
    assert!(text.contains("garbage.apk"));
    assert!(text.contains("(incomplete)"));
    assert!(text.contains("report incomplete"));
    let _ = std::fs::remove_file(&xapk);
}

/// Corpus-gated: the real Locket XAPK (base + 3 config splits). Skips
/// silently when the dev-only fixture is absent.
#[test]
fn locket_xapk_end_to_end() {
    let xapk = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/apk/Locket Widget_1.216.0_APKPure.xapk");
    if !xapk.exists() {
        eprintln!("skipping: corpus fixture missing");
        return;
    }
    let r = asc_core::xapk::run_xapk(&xapk).expect("run");
    assert!(r.complete, "errors: {:?}", r.errors);
    assert_eq!(
        r.members.len(),
        4,
        "{:?}",
        r.members.iter().map(|m| &m.name).collect::<Vec<_>>()
    );
    let base = r
        .members
        .iter()
        .find(|m| m.name == "com.locket.Locket.apk")
        .expect("base member");
    assert_eq!(base.role, "base");
    let man = base.manifest.as_ref().expect("base manifest");
    assert_eq!(man.package.as_deref(), Some("com.locket.Locket"));
    assert!(man.split.is_none());
    assert!(base.dex.iter().all(|d| d.error.is_none()));
    assert!(base.dex.iter().map(|d| d.classes).sum::<usize>() > 1000);
    let abi = r
        .members
        .iter()
        .find(|m| m.name == "config.arm64_v8a.apk")
        .expect("abi split");
    assert_eq!(abi.role, "split");
    assert_eq!(abi.abi_dirs, ["arm64-v8a"]);
    assert!(!abi.native_libs.is_empty());
}

/// Aggregate work budget: once total uncompressed member bytes exceed
/// the budget, the container stops analyzing further members and
/// reports partial — without reading them.
#[test]
fn aggregate_budget_stops_and_reports_partial() {
    let member = || {
        let mut m = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut m);
            let opts = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            w.start_file("classes.dex", opts).unwrap();
            w.write_all(b"not a dex").unwrap();
            w.finish().unwrap();
        }
        m.into_inner()
    };
    let payload = member();
    let two = 2 * payload.len();
    let xapk = std::env::temp_dir().join("asc-xapk-budget.zip");
    write_zip(
        &xapk,
        &[
            ("a.apk", payload.clone()),
            ("b.apk", payload.clone()),
            ("c.apk", payload),
        ],
    );
    // Budget covers a.apk + b.apk exactly; c.apk must be skipped.
    let r = asc_core::xapk::run_xapk_with_budget(&xapk, two).expect("run");
    assert!(!r.complete);
    assert_eq!(r.members.len(), 2, "third member must be skipped");
    assert!(
        r.errors
            .iter()
            .any(|e| e.contains("aggregate budget exceeded") && e.contains("c.apk"))
    );
    let _ = std::fs::remove_file(&xapk);
}

/// A read that FAILS must still consume the aggregate budget. Otherwise a
/// container full of malformed members makes the inflater churn while the
/// counter barely moves, bypassing the work bound entirely.
#[test]
fn failed_read_still_consumes_aggregate_budget() {
    let one_mib = 1usize << 20;
    // Every member's central record DECLARES 1 MiB while the stored data
    // is tiny, so each read fails (SizeMismatch) — a malformed member.
    let mut container = zip_bytes(&[
        ("a.apk", member_apk()),
        ("b.apk", member_apk()),
        ("c.apk", member_apk()),
    ]);
    override_cd_uncompressed_size(&mut container, one_mib as u32);
    let xapk = std::env::temp_dir().join("asc-xapk-failed-budget.zip");
    std::fs::write(&xapk, &container).unwrap();
    // 1.5 MiB: the first failed attempt consumes 1 MiB, leaving too little
    // for the second member.
    let r = asc_core::xapk::run_xapk_with_budget(&xapk, one_mib + (1 << 19)).expect("run");
    assert!(!r.complete);
    assert_eq!(r.members.len(), 0, "no member reads successfully");
    assert!(
        r.errors
            .iter()
            .any(|e| e.contains("aggregate budget exceeded")),
        "the failed attempt must have consumed budget: {:?}",
        r.errors
    );
    assert_eq!(
        r.errors
            .iter()
            .filter(|e| e.contains("read failed"))
            .count(),
        1,
        "exactly one failed read before the budget stops traversal: {:?}",
        r.errors
    );
    let _ = std::fs::remove_file(&xapk);
}

/// The aggregate budget is a *work* bound, not only an output bound.
///
/// Every member here declares 0 uncompressed bytes in the central directory
/// while holding a 512 KiB DEFLATE payload. The charge must cover what the
/// read can actually cost — the declared output (+1 byte) *and* the
/// compressed input a DEFLATE decoder may walk without producing output —
/// otherwise a container of N such members buys N payloads' worth of
/// decoding against a budget that barely moves.
#[test]
fn under_declared_deflate_members_cannot_buy_uncharged_work() {
    const MEMBERS: usize = 4;
    let owned: Vec<(String, Vec<u8>)> = (0..MEMBERS)
        .map(|i| (format!("m{i}.apk"), vec![0u8; 512 * 1024]))
        .collect();
    let entries: Vec<(&str, Vec<u8>)> =
        owned.iter().map(|(n, d)| (n.as_str(), d.clone())).collect();
    let mut container = zip_bytes_deflated(&entries);
    // Every member now claims 0 uncompressed bytes.
    override_cd_uncompressed_size(&mut container, 0);
    let xapk = std::env::temp_dir().join("asc-xapk-underdeclared.zip");
    std::fs::write(&xapk, &container).unwrap();

    // What one member must cost: declared (0) + the compressed input.
    let charge = {
        let apk = asc_apk::Apk::open(&xapk).expect("open");
        let e = apk.entry("m0.apk").expect("member entry");
        assert_eq!(e.uncompressed_size, 0, "the lie must be in place");
        assert!(
            e.compressed_size > 0 && (e.compressed_size as usize) < 512 * 1024,
            "fixture must be a small payload that expands hugely, got {}",
            e.compressed_size
        );
        e.compressed_size as usize
    };

    // (a) One byte short of that charge: the member is never read at all.
    let r = asc_core::xapk::run_xapk_with_budget(&xapk, charge - 1).expect("run");
    assert!(r.members.is_empty());
    assert_eq!(
        r.errors
            .iter()
            .filter(|e| e.contains("read failed"))
            .count(),
        0,
        "an unaffordable member must not be inflated: {:?}",
        r.errors
    );
    assert!(
        r.errors
            .iter()
            .any(|e| e.contains("aggregate budget exceeded") && e.contains("m0.apk")),
        "the charge must cover the compressed input the decoder walks: {:?}",
        r.errors
    );

    // (b) With every charge paid, each attempt still stops exactly one byte
    //     past its declaration (the inflater bound, independently).
    let r = asc_core::xapk::run_xapk_with_budget(&xapk, MEMBERS * charge + MEMBERS).expect("run");
    let failed: Vec<&String> = r
        .errors
        .iter()
        .filter(|e| e.contains("read failed"))
        .collect();
    assert_eq!(
        failed.len(),
        MEMBERS,
        "every member is attempted: {:?}",
        r.errors
    );
    for e in &failed {
        assert!(
            e.contains("declared 0, produced 1"),
            "an under-declared member must stop one byte past its declaration, got {e}"
        );
    }
    assert!(r.members.is_empty(), "no member can be analyzed");
    let _ = std::fs::remove_file(&xapk);
}

/// The tighter stop point must not disturb a truthful DEFLATE member:
/// it still inflates to exactly its declared size and gets analyzed.
#[test]
fn deflated_member_still_reads_at_its_declared_size() {
    let payload = member_apk();
    let container = zip_bytes_deflated(&[("base.apk", payload)]);
    let xapk = std::env::temp_dir().join("asc-xapk-true-deflate.zip");
    std::fs::write(&xapk, &container).unwrap();
    let r = asc_core::xapk::run_xapk_with_budget(&xapk, 1 << 20).expect("run");
    assert!(r.complete, "errors: {:?}", r.errors);
    assert_eq!(r.members.len(), 1, "the member is analyzed");
    assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
    let _ = std::fs::remove_file(&xapk);
}

/// The aggregate-budget error must name the CALLER's budget, not the
/// 1024 MiB default the two values used to be conflated with.
#[test]
fn custom_budget_message_names_the_caller_value() {
    let mut container = zip_bytes(&[("big.apk", member_apk())]);
    override_cd_uncompressed_size(&mut container, 64 << 20);
    let xapk = std::env::temp_dir().join("asc-xapk-custom-budget.zip");
    std::fs::write(&xapk, &container).unwrap();
    let r = asc_core::xapk::run_xapk_with_budget(&xapk, 32 << 20).expect("run");
    assert!(!r.complete);
    assert!(r.members.is_empty());
    let msg = r
        .errors
        .iter()
        .find(|e| e.contains("aggregate budget exceeded"))
        .unwrap_or_else(|| panic!("no budget error: {:?}", r.errors));
    assert!(
        msg.contains("(32 MiB)"),
        "must name the caller's budget: {msg}"
    );
    assert!(
        !msg.contains("1024 MiB"),
        "must not name the default: {msg}"
    );
    let _ = std::fs::remove_file(&xapk);
}
