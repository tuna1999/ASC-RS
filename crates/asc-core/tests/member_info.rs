//! `run_member_info` flags + signature against a real corpus DEX.

use asc_core::{DisasmJob, DisasmOptions, MemberInfoJob, run_disasm, run_member_info};

fn dex() -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/dex/aurora_classes.dex");
    if !p.exists() {
        eprintln!("skipping: {} not present", p.display());
    }
    p.exists().then_some(p)
}

#[test]
fn public_method_reports_public_and_its_proto() {
    let Some(p) = dex() else { return };
    let job = MemberInfoJob::new(&p, "Landroidx/constraintlayout/widget/d;", "i");
    let info = run_member_info(&job).expect("info");
    assert!(info.flag_names.contains(&"public"), "{:?}", info.flag_names);
    assert!(info.proto.starts_with('('), "proto is descriptor form");
    assert!(
        info.proto.ends_with(")V"),
        "void renderer method returns V, got {}",
        info.proto
    );
}

#[test]
fn absent_method_is_reported_not_guessed() {
    let Some(p) = dex() else { return };
    let job = MemberInfoJob::new(&p, "Landroidx/constraintlayout/widget/d;", "nope_xyz");
    let err = run_member_info(&job).expect_err("missing method");
    assert!(format!("{err}").contains("nope_xyz"), "{err}");
}

/// Two-member DEX-041 container built from one real DEX: member 1 is
/// the DEX with `class_defs_size = 0`; member 2 is a fresh header plus
/// copies of the six id sections. Member 2's data offsets stay absolute
/// and point into member 1 (shared data), as DEX-041 allows.
fn shared_data_041(b: &[u8]) -> Vec<u8> {
    const MAGIC: &[u8; 8] = b"dex\n041\0";
    let rd = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize;
    let put = |v: &mut [u8], o: usize, x: usize| {
        v[o..o + 4].copy_from_slice(&(x as u32).to_le_bytes());
    };
    let mut out = b.to_vec();
    out[..8].copy_from_slice(MAGIC);
    put(&mut out, 0x60, 0); // member 1 declares no classes
    let base = out.len();
    let mut hdr = b[..0x70].to_vec();
    hdr[..8].copy_from_slice(MAGIC);
    let mut body = Vec::new();
    // (size field, offset field, element size) of the six id sections.
    for (sz, off, el) in [
        (0x38, 0x3C, 4),
        (0x40, 0x44, 4),
        (0x48, 0x4C, 12),
        (0x50, 0x54, 8),
        (0x58, 0x5C, 8),
        (0x60, 0x64, 32),
    ] {
        let (n, o) = (rd(sz), rd(off));
        put(
            &mut hdr,
            off,
            if n == 0 { 0 } else { base + 0x70 + body.len() },
        );
        body.extend_from_slice(&b[o..o + n * el]);
    }
    put(&mut hdr, 0x20, 0x70 + body.len());
    for o in [0x2C, 0x30, 0x34, 0x68, 0x6C] {
        put(&mut hdr, o, 0); // no link/map/data section of its own
    }
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&body);
    out
}

/// The class lives only in member 2 of a DEX-041 container. droidsaw
/// parses from offset 0 with a 0x70 header and a checksum, so the engine
/// must normalise the member like the oracle (`normalize_dex041_logical`).
/// Before the fix `member` handed droidsaw the whole entry (member 1 →
/// "not found"/checksum error) and `disasm` sliced the member, breaking
/// its absolute offsets.
#[test]
fn class_in_second_041_member_is_resolved() {
    let Some(p) = dex() else { return };
    let container = shared_data_041(&std::fs::read(&p).unwrap());
    let path = std::env::temp_dir().join(format!("asc_member_041_{}.dex", std::process::id()));
    std::fs::write(&path, &container).unwrap();
    let class = "Landroidx/constraintlayout/widget/d;";
    let info = run_member_info(&MemberInfoJob::new(&path, class, "i"));
    let listing = run_disasm(
        &DisasmJob::new(&path, class, Some("i")),
        &DisasmOptions::default(),
    );
    let _ = std::fs::remove_file(&path);
    let info = info.expect("member: class in the second logical member");
    assert!(info.proto.ends_with(")V"), "{}", info.proto);
    let listing = listing.expect("disasm: class in the second logical member");
    assert!(
        listing.dex_name.ends_with("classes2.dex"),
        "{}",
        listing.dex_name
    );
    assert!(
        listing.listing.contains(".method public final i("),
        "{}",
        listing.listing
    );
}
