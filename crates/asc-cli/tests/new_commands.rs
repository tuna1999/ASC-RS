//! Exit-code and safety tests for the `strings`, `extract` and `axml`
//! subcommands.
//!
//! Security-critical paths covered:
//! - `extract` never derives an output path that escapes the cwd
//!   (entry names are attacker-controlled): traversal prefixes are
//!   stripped to the basename, and basename-less names are refused;
//! - `extract --verify-crc` fails on corrupted stored data;
//! - `strings` reports per-DEX pools with source and index.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_asc-rs");

fn target_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("asc_new_cmd_{tag}_{}", std::process::id()))
}

/// STORED APK writer (hand-rolled: the `zip` crate fixes CRCs, but the
/// corruption test needs the stored CRC to disagree with the data).
fn write_stored_apk(path: &std::path::Path, entries: &[(&str, &[u8])]) {
    let mut z: Vec<u8> = Vec::new();
    let mut centrals: Vec<u8> = Vec::new();
    let mut offsets = Vec::new();
    for (name, data) in entries {
        offsets.push(z.len() as u32);
        let crc = crc32fast::hash(data);
        z.extend_from_slice(b"PK\x03\x04");
        z.extend_from_slice(&20u16.to_le_bytes()); // version needed
        z.extend_from_slice(&0u16.to_le_bytes()); // flags
        z.extend_from_slice(&0u16.to_le_bytes()); // stored
        z.extend_from_slice(&0u16.to_le_bytes()); // time
        z.extend_from_slice(&0u16.to_le_bytes()); // date
        z.extend_from_slice(&crc.to_le_bytes());
        z.extend_from_slice(&(data.len() as u32).to_le_bytes());
        z.extend_from_slice(&(data.len() as u32).to_le_bytes());
        z.extend_from_slice(&(name.len() as u16).to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // extra
        z.extend_from_slice(name.as_bytes());
        z.extend_from_slice(data);
        let central_at = centrals.len();
        centrals.extend_from_slice(b"PK\x01\x02");
        centrals.extend_from_slice(&20u16.to_le_bytes()); // version made by
        centrals.extend_from_slice(&20u16.to_le_bytes()); // version needed
        centrals.extend_from_slice(&0u16.to_le_bytes()); // flags
        centrals.extend_from_slice(&0u16.to_le_bytes()); // method
        centrals.extend_from_slice(&0u16.to_le_bytes()); // time
        centrals.extend_from_slice(&0u16.to_le_bytes()); // date
        centrals.extend_from_slice(&crc.to_le_bytes());
        centrals.extend_from_slice(&(data.len() as u32).to_le_bytes());
        centrals.extend_from_slice(&(data.len() as u32).to_le_bytes());
        centrals.extend_from_slice(&(name.len() as u16).to_le_bytes());
        centrals.extend_from_slice(&0u16.to_le_bytes()); // extra
        centrals.extend_from_slice(&0u16.to_le_bytes()); // comment
        centrals.extend_from_slice(&0u16.to_le_bytes()); // disk start
        centrals.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        centrals.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        centrals.extend_from_slice(&0u32.to_le_bytes()); // local offset (patched)
        centrals.extend_from_slice(name.as_bytes());
        // local-header-offset field sits 4 bytes before the name.
        let at = central_at + 42;
        centrals[at..at + 4].copy_from_slice(&offsets[offsets.len() - 1].to_le_bytes());
    }
    let central_off = z.len() as u32;
    z.extend_from_slice(&centrals);
    let central_size = z.len() as u32 - central_off;
    z.extend_from_slice(b"PK\x05\x06");
    z.extend_from_slice(&0u16.to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes());
    z.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    z.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    z.extend_from_slice(&central_size.to_le_bytes());
    z.extend_from_slice(&central_off.to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes());
    std::fs::File::create(path).unwrap().write_all(&z).unwrap();
}

fn run_cli(args: &[&str]) -> std::process::Output {
    Command::new(BIN).args(args).output().expect("spawn asc-rs")
}

fn corpus(name: &str) -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(name);
    p.exists().then_some(p)
}

#[test]
fn extract_derived_output_is_always_the_basename() {
    let apk = target_dir("derive");
    write_stored_apk(&apk, &[("assets/deep/data.txt", b"hello")]);
    let cwd = std::env::current_dir().unwrap();
    let out = run_cli(&["extract", apk.to_str().unwrap(), "assets/deep/data.txt"]);
    assert!(out.status.success(), "{out:?}");
    // The file must land as ./data.txt (basename only), never under
    // assets/deep/.
    assert!(cwd.join("data.txt").exists(), "basename not written");
    assert!(!cwd.join("assets/deep/data.txt").exists(), "path derived!");
    let _ = std::fs::remove_file(cwd.join("data.txt"));
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn extract_refuses_basenameless_entry_without_dash_o() {
    // An entry literally named ".." has no safe basename and no -o was
    // given: refuse rather than write somewhere unexpected.
    let apk = target_dir("dotdot");
    write_stored_apk(&apk, &[("..", b"payload")]);
    let out = run_cli(&["extract", apk.to_str().unwrap(), ".."]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn extract_verify_crc_fails_on_corrupted_stored_data() {
    // Build a STORED APK, then flip one payload byte: the stored CRCs
    // still describe the original data, so --verify-crc must fail.
    let apk = target_dir("crc");
    write_stored_apk(&apk, &[("blob.bin", b"UNIQUEPAYLOAD1234567890")]);
    let mut bytes = std::fs::read(&apk).unwrap();
    let at = bytes
        .windows(9)
        .position(|w| w == b"UNIQUEPAY".as_slice())
        .expect("payload found");
    bytes[at] = b'X';
    std::fs::write(&apk, &bytes).unwrap();
    let out = run_cli(&[
        "extract",
        apk.to_str().unwrap(),
        "blob.bin",
        "--verify-crc",
        "-o",
        "corrupted-dump.bin",
    ]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(!std::path::Path::new("corrupted-dump.bin").exists());
    // Without --verify-crc the same read succeeds (the bytes come back
    // modified; only integrity is unverifiable).
    let out2 = run_cli(&[
        "extract",
        apk.to_str().unwrap(),
        "blob.bin",
        "-o",
        "corrupted-dump.bin",
    ]);
    assert!(out2.status.success(), "{out2:?}");
    let _ = std::fs::remove_file("corrupted-dump.bin");
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn extract_missing_entry_is_exit_1() {
    let apk = target_dir("missing");
    write_stored_apk(&apk, &[("a.txt", b"x")]);
    let out = run_cli(&["extract", apk.to_str().unwrap(), "nope.txt"]);
    assert_eq!(out.status.code(), Some(1));
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn axml_and_strings_work_on_corpus_workload() {
    let Some(apk) = corpus("apk/com.aurora.store_60.apk") else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let apk = apk.to_string_lossy().into_owned();
    let out = run_cli(&["axml", &apk, "AndroidManifest.xml"]);
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("<manifest"),
        "axml output should contain the root element: {text}"
    );

    let Some(workload) = corpus("apk/workload.apk") else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let workload = workload.to_string_lossy().into_owned();
    let out = run_cli(&[
        "strings",
        &workload,
        "--substring",
        "ClockFace",
        "--limit",
        "3",
    ]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("classes.dex #"),
        "strings should name the source DEX: {text}"
    );
    assert!(text.contains("ClockFace"));

    let out = run_cli(&[
        "strings",
        &workload,
        "--substring",
        "zzz-no-such",
        "--format",
        "json",
    ]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid json");
    assert!(v["total_matched"] == 0, "{v}");
}
