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

/// `true` when the fixture basename matches an entry of the
/// comma-separated `ASC_REQUIRE_CORPUS` list (CI sets it after
/// recreating the corpus fixtures it guarantees; a listed fixture that
/// is still missing must fail, not silently skip).
fn require_corpus(var: &str, p: &std::path::Path) -> bool {
    std::env::var(var).is_ok_and(|req| {
        req.split(',').any(|f| {
            let f = f.trim();
            !f.is_empty()
                && p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(f))
        })
    })
}
fn corpus(name: &str) -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(name);
    if !p.exists() && require_corpus("ASC_REQUIRE_CORPUS", &p) {
        panic!(
            "ASC_REQUIRE_CORPUS is set but fixture missing: {}",
            p.display()
        );
    }
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

#[test]
fn strings_skips_non_dex_entry_without_failing() {
    // A classes*.dex entry that is not a DEX is deliberately skipped
    // (findrefs F06 policy): warning on stderr, but exit 0 — the scan
    // itself did not fail.
    let apk = target_dir("strskip");
    write_stored_apk(&apk, &[("classes.dex", b"not a dex at all")]);
    let out = run_cli(&["strings", apk.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("skipped"),
        "stderr must carry the skip warning: {:?}",
        out.stderr
    );
    let _ = std::fs::remove_file(&apk);
}

/// `findrefs extends|impl` and `listmethod` against counts cross-checked
/// with androguard 4.1.3 on workload.apk (Fragment subclasses 3, Runnable
/// implementors 193, defined methods 47934).
#[test]
fn hierarchy_and_listmethod_match_androguard_on_workload() {
    let Some(apk) = corpus("apk/workload.apk") else {
        eprintln!("skipping: corpus/apk/workload.apk missing");
        return;
    };
    let a = apk.to_str().unwrap();
    let lines = |args: &[&str]| {
        let out = run_cli(args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    let ext = lines(&["findrefs", a, "extends", "androidx.fragment.app.Fragment"]);
    assert_eq!(ext.len(), 3, "{ext:?}");
    assert!(
        ext.contains(&"classes.dex | Landroidx/fragment/app/DialogFragment;".to_string()),
        "{ext:?}"
    );
    assert_eq!(
        lines(&["findrefs", a, "impl", "Ljava/lang/Runnable;"]).len(),
        193
    );
    let tr = lines(&[
        "findrefs",
        a,
        "extends",
        "androidx.fragment.app.Fragment",
        "--transitive",
    ]);
    assert!(
        tr.len() > 3 && tr[3..].iter().all(|l| l.contains("    # via L")),
        "{tr:?}"
    );

    assert_eq!(lines(&["listmethod", a, "--limit", "1000000"]).len(), 47934);
    assert_eq!(
        lines(&["listmethod", a, "--class", "androidx.core.net.UriCompat"]),
        [
            "Landroidx/core/net/UriCompat;-><init>()V",
            "Landroidx/core/net/UriCompat;->toSafeString(Landroid/net/Uri;)Ljava/lang/String;"
        ]
    );
    let out = run_cli(&["listmethod", a, "--class", "Lcom/nope/X;"]);
    assert_eq!(out.status.code(), Some(1));
    let out = run_cli(&["findrefs", a, "extends", "Lcom/nope/X;"]);
    assert_eq!(out.status.code(), Some(0), "no subclasses is not an error");
    assert!(out.stdout.is_empty());
}

/// `asc-rs listclass x | head -1`: the reader closing the pipe early
/// must end the run quietly (exit 0), not panic with exit 101.
#[test]
fn closed_stdout_pipe_exits_quietly() {
    let Some(apk) = corpus("apk/workload.apk") else {
        eprintln!("skipping: corpus/apk/workload.apk missing");
        return;
    };
    for args in [&["listclass"][..], &["listmethod"], &["strings"]] {
        let mut child = Command::new(BIN)
            .args(args)
            .arg(&apk)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = child.stdout.take().unwrap();
        let mut first = [0u8; 1];
        std::io::Read::read_exact(&mut out, &mut first).unwrap();
        drop(out);
        let o = child.wait_with_output().unwrap();
        let err = String::from_utf8_lossy(&o.stderr);
        assert_eq!(o.status.code(), Some(0), "{args:?}: {err}");
        assert!(!err.contains("panicked"), "{args:?}: {err}");
    }
}

/// `--format json` is honoured by `disasm` (all three views).
#[test]
fn disasm_json_wraps_the_listing() {
    let Some(apk) = corpus("apk/workload.apk") else {
        eprintln!("skipping: corpus/apk/workload.apk missing");
        return;
    };
    let class = "Lkotlin/jvm/internal/PropertyReference1;";
    for view in ["smali", "bytecode", "cfg"] {
        let run = |fmt: &str| {
            let o = Command::new(BIN)
                .args(["disasm"])
                .arg(&apk)
                .args([class, "--method", "<init>", "--view", view, "--format", fmt])
                .output()
                .unwrap();
            assert_eq!(o.status.code(), Some(0), "{view} {fmt}");
            String::from_utf8(o.stdout).unwrap()
        };
        let text = run("text");
        let v: serde_json::Value = serde_json::from_str(&run("json")).unwrap();
        assert_eq!(v["listing"], text.as_str(), "{view}");
        assert_eq!(v["class"], class);
        assert_eq!(v["method"], "<init>");
        assert_eq!(v["view"], view);
        assert_eq!(v["dex_name"], "classes.dex");
    }
}
