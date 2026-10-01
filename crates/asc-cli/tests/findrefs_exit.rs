//! Regression tests for `findrefs` exit codes and diagnostics when an
//! APK contains both a valid and an unreadable DEX entry.
//!
//! Contract under test (P1):
//! - a scan with per-DEX failures prints every hit it found (stdout),
//!   warns per failing DEX on stderr (both output modes, no `--debug`
//!   needed), reuses the JSON `complete`/`errors` fields, and exits 2;
//! - a fully-scanned APK keeps exit code 0 and adds no stderr warnings.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use asc_dex::mutf8::from_utf16;

const OBJECT: &str = "Ljava/lang/Object;";
const STRING: &str = "Ljava/lang/String;";
const MAIN: &str = "Lp/Main;";
const ACC_PUBLIC_STATIC: u32 = 0x0009;

fn u(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

type Proto = (&'static str, Vec<&'static str>);

fn shorty(p: &Proto) -> String {
    std::iter::once(p.0)
        .chain(p.1.iter().copied())
        .map(|t| if t.len() == 1 { t } else { "L" })
        .collect()
}

/// Minimal DEX writer (same shape as `asc-core/tests/common`): pools
/// sorted, indices looked up by value. Supports exactly one class with
/// static methods — enough to host a `const-string` for findrefs.
struct Dex {
    strings: Vec<Vec<u16>>,
    types: Vec<String>,
    protos: Vec<Proto>,
    methods: Vec<(&'static str, &'static str, Proto)>,
}

impl Dex {
    fn new(methods: Vec<(&'static str, &'static str, Proto)>, literals: &[Vec<u16>]) -> Self {
        let mut types: BTreeSet<String> = [OBJECT, MAIN].map(String::from).into();
        let mut strings: BTreeSet<Vec<u16>> = literals.iter().cloned().collect();
        let mut protos: Vec<Proto> = Vec::new();
        for (c, n, p) in &methods {
            types.insert(c.to_string());
            types.insert(p.0.to_string());
            types.extend(p.1.iter().map(|t| t.to_string()));
            strings.insert(u(n));
            strings.insert(u(&shorty(p)));
            if !protos.contains(p) {
                protos.push(p.clone());
            }
        }
        strings.extend(types.iter().map(|t| u(t)));
        Self {
            strings: strings.into_iter().collect(),
            types: types.into_iter().collect(),
            protos,
            methods,
        }
    }
    fn string(&self, s: &[u16]) -> u32 {
        self.strings.iter().position(|x| x == s).unwrap() as u32
    }
    fn type_(&self, t: &str) -> u32 {
        self.types.iter().position(|x| x == t).unwrap() as u32
    }
    fn method(&self, class: &str, name: &str) -> u16 {
        self.methods
            .iter()
            .position(|m| m.0 == class && m.1 == name)
            .unwrap() as u16
    }

    /// `classes`: (descriptor, [(method name, flags, regs, ins, insns)]).
    fn finish(&self, classes: &[(&str, Vec<(&str, u32, u16, u16, Vec<u16>)>)]) -> Vec<u8> {
        let ids_len = 0x70
            + self.strings.len() * 4
            + self.types.len() * 4
            + self.protos.len() * 12
            + self.methods.len() * 8
            + classes.len() * 32;
        let mut out = vec![0u8; ids_len];
        let mut ids = 0x70;
        let mut put = |out: &mut Vec<u8>, bytes: &[u8]| {
            out[ids..ids + bytes.len()].copy_from_slice(bytes);
            ids += bytes.len();
        };
        let uleb = |out: &mut Vec<u8>, mut v: u32| loop {
            let b = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        };
        let align = |out: &mut Vec<u8>| out.resize(out.len().next_multiple_of(4), 0);

        let header = [
            (0x38, self.strings.len()),
            (0x40, self.types.len()),
            (0x48, self.protos.len()),
            (0x50, 0usize),
            (0x58, self.methods.len()),
            (0x60, classes.len()),
        ];
        let mut offs = 0x70;
        for (at, n) in header {
            out[at..at + 4].copy_from_slice(&(n as u32).to_le_bytes());
            out[at + 4..at + 8].copy_from_slice(&(offs as u32).to_le_bytes());
            offs += n * [4, 4, 12, 8, 8, 32][(at - 0x38) / 8];
        }

        for s in &self.strings {
            let off = out.len() as u32;
            uleb(&mut out, s.len() as u32);
            out.extend(from_utf16(s));
            out.push(0);
            put(&mut out, &off.to_le_bytes());
        }
        for t in &self.types {
            put(&mut out, &self.string(&u(t)).to_le_bytes());
        }
        for p in &self.protos {
            let params = if p.1.is_empty() {
                0
            } else {
                align(&mut out);
                let off = out.len() as u32;
                out.extend((p.1.len() as u32).to_le_bytes());
                for t in &p.1 {
                    out.extend((self.type_(t) as u16).to_le_bytes());
                }
                off
            };
            put(&mut out, &self.string(&u(&shorty(p))).to_le_bytes());
            put(&mut out, &self.type_(p.0).to_le_bytes());
            put(&mut out, &params.to_le_bytes());
        }
        for (c, n, p) in &self.methods {
            put(&mut out, &(self.type_(c) as u16).to_le_bytes());
            let proto = self.protos.iter().position(|q| q == p).unwrap() as u16;
            put(&mut out, &proto.to_le_bytes());
            put(&mut out, &self.string(&u(n)).to_le_bytes());
        }
        for (desc, methods) in classes {
            let mut code_offs = Vec::new();
            for (_, _, regs, ins, insns) in methods {
                align(&mut out);
                code_offs.push(out.len() as u32);
                for v in [*regs, *ins, 4, 0] {
                    out.extend(v.to_le_bytes());
                }
                out.extend(0u32.to_le_bytes());
                out.extend((insns.len() as u32).to_le_bytes());
                out.extend(insns.iter().flat_map(|w| w.to_le_bytes()));
            }
            let data_off = out.len() as u32;
            let mut dm: Vec<(u16, u32, u32)> = methods
                .iter()
                .zip(&code_offs)
                .map(|((n, flags, ..), off)| (self.method(desc, n), *flags, *off))
                .collect();
            dm.sort();
            let mut cd = Vec::new();
            uleb(&mut cd, 0);
            uleb(&mut cd, 0);
            uleb(&mut cd, dm.len() as u32);
            uleb(&mut cd, 0);
            let mut prev = 0;
            for (m, flags, off) in dm {
                uleb(&mut cd, (m - prev) as u32);
                uleb(&mut cd, flags);
                uleb(&mut cd, off);
                prev = m;
            }
            out.extend(cd);
            for v in [
                self.type_(desc),
                1,
                self.type_(OBJECT),
                0,
                u32::MAX,
                0,
                data_off,
                0,
            ] {
                put(&mut out, &v.to_le_bytes());
            }
        }
        // asc-dex sizes class_data conservatively (8 bytes/entry), and
        // real DEX files always have map_list after it.
        out.resize(out.len() + 64, 0);
        let size = out.len() as u32;
        out[..8].copy_from_slice(b"dex\n035\0");
        out[0x20..0x24].copy_from_slice(&size.to_le_bytes());
        out[0x24..0x28].copy_from_slice(&0x70u32.to_le_bytes());
        out[0x28..0x2C].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        out[0x68..0x6C].copy_from_slice(&(size - ids_len as u32).to_le_bytes());
        out[0x6C..0x70].copy_from_slice(&(ids_len as u32).to_le_bytes());
        out
    }
}

/// DEX defining `Lp/Main;` with `m()` returning `const-string v0, needle`.
fn needle_dex(needle: &str) -> Vec<u8> {
    let dex = Dex::new(vec![(MAIN, "m", (STRING, vec![]))], &[u(needle)]);
    let idx = dex.string(&u(needle)) as u16;
    // const-string v0, needle ; return-object v0.
    // Format 21c: unit0 = 0x1A | (reg << 8), unit1 = string idx.
    let insns = vec![0x001A, idx, 0x0011];
    dex.finish(&[(MAIN, vec![("m", ACC_PUBLIC_STATIC, 1, 0, insns)])])
}

/// STORED APK with the given root entries.
fn write_apk(tag: &str, entries: &[(&str, Vec<u8>)]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("asc_cli_{tag}_{}.apk", std::process::id()));
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
    let opts =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in entries {
        zip.start_file(*name, opts).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap();
    path
}

fn run_cli(args: &[&str]) -> (Box<std::process::Output>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_asc-rs"))
        .args(args)
        .output()
        .expect("spawn asc-rs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (Box::new(out), stderr)
}

const NEEDLE: &str = "needlehunter";

#[test]
fn findrefs_partial_scan_keeps_results_exits_2_and_warns() {
    // classes.dex valid (defines the hit), classes2.dex truncated DEX.
    let corrupt = {
        let mut b = b"dex\n035\0".to_vec();
        b.extend(std::iter::repeat(0u8).take(8)); // 16 bytes: header parse fails
        b
    };
    let apk = write_apk(
        "partial",
        &[
            ("classes.dex", needle_dex(NEEDLE)),
            ("classes2.dex", corrupt),
        ],
    );

    // Text mode: results on stdout, warning on stderr, exit 2.
    let (out, stderr) = run_cli(&["findrefs", apk.to_str().unwrap(), "string", NEEDLE]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "incomplete scan must not exit 0; stderr:\n{stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(NEEDLE),
        "partial results must be kept on stdout, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Main"),
        "caller line must be kept on stdout, got:\n{stdout}"
    );
    assert!(
        stderr.contains("classes2.dex") && stderr.contains("warning"),
        "text mode must warn about the failed DEX on stderr without --debug, got:\n{stderr}"
    );

    // JSON mode: same exit code, schema reuse (complete=false, errors).
    let (out, _stderr) = run_cli(&[
        "--format",
        "json",
        "findrefs",
        apk.to_str().unwrap(),
        "string",
        NEEDLE,
    ]);
    assert_eq!(out.status.code(), Some(2));
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"complete\": false"), "json: {json}");
    assert!(json.contains("\"errors\""), "json: {json}");
    assert!(json.contains("classes2.dex"), "json: {json}");

    let _ = std::fs::remove_file(&apk);
}

#[test]
fn findrefs_complete_scan_still_exits_0_quietly() {
    let apk = write_apk("clean", &[("classes.dex", needle_dex(NEEDLE))]);
    let (out, stderr) = run_cli(&["findrefs", apk.to_str().unwrap(), "string", NEEDLE]);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{stderr}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(NEEDLE), "stdout:\n{stdout}");
    assert!(
        !stderr.contains("warning"),
        "a fully-scanned APK must not warn; stderr:\n{stderr}"
    );

    let _ = std::fs::remove_file(&apk);
}
