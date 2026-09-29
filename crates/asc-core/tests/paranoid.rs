//! End-to-end `--paranoid`: a hand-assembled Paranoid-shaped DEX inside
//! an APK, run through `run_getclass` / `run_findrefs`.

use std::collections::BTreeSet;
use std::io::Write;

use asc_core::{
    FindRefsJob, FindRefsOptions, GetClassJob, GetClassOptions, run_findrefs, run_getclass,
};
use asc_dex::mutf8::from_utf16;
use asc_query::Query;

const OBJECT: &str = "Ljava/lang/Object;";
const STRING: &str = "Ljava/lang/String;";
const STRINGS: &str = "[Ljava/lang/String;";
const DEOB: &str = "Lio/michaelrocks/paranoid/Deobfuscator$app;";
const HELPER: &str = "Lio/michaelrocks/paranoid/DeobfuscatorHelper;";
const MAIN: &str = "Lcom/poc/Main;";
const ACC_PUBLIC_STATIC: u32 = 0x0009;
const ACC_STATIC_CTOR: u32 = 0x10008;

fn u(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

type Proto = (&'static str, Vec<&'static str>);
type Member = (&'static str, &'static str, Proto);

/// Minimal DEX writer: every pool is sorted, indices are looked up by value.
struct Dex {
    strings: Vec<Vec<u16>>,
    types: Vec<String>,
    protos: Vec<Proto>,
    fields: Vec<(&'static str, &'static str, &'static str)>,
    methods: Vec<Member>,
}

fn shorty(p: &Proto) -> String {
    std::iter::once(p.0)
        .chain(p.1.iter().copied())
        .map(|t| if t.len() == 1 { t } else { "L" })
        .collect()
}

impl Dex {
    fn new(
        fields: Vec<(&'static str, &'static str, &'static str)>,
        methods: Vec<Member>,
        literals: &[Vec<u16>],
    ) -> Self {
        let mut types: BTreeSet<String> = [OBJECT, DEOB, MAIN].map(String::from).into();
        let mut strings: BTreeSet<Vec<u16>> = literals.iter().cloned().collect();
        let mut protos: Vec<Proto> = Vec::new();
        for (c, t, n) in &fields {
            types.extend([c.to_string(), t.to_string()]);
            strings.insert(u(n));
        }
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
            fields,
            methods,
        }
    }
    fn string(&self, s: &[u16]) -> u32 {
        self.strings.iter().position(|x| x == s).unwrap() as u32
    }
    fn type_(&self, t: &str) -> u32 {
        self.types.iter().position(|x| x == t).unwrap() as u32
    }
    fn field(&self, name: &str) -> u16 {
        self.fields.iter().position(|f| f.2 == name).unwrap() as u16
    }
    fn method(&self, class: &str, name: &str) -> u16 {
        self.methods
            .iter()
            .position(|m| m.0 == class && m.1 == name)
            .unwrap() as u16
    }

    /// `classes`: (descriptor, static field names, [(method name, flags, regs, ins, insns)]).
    #[allow(clippy::type_complexity)]
    fn finish(
        &self,
        classes: &[(&str, Vec<&str>, Vec<(&str, u32, u16, u16, Vec<u16>)>)],
    ) -> Vec<u8> {
        let ids_len = 0x70
            + self.strings.len() * 4
            + self.types.len() * 4
            + self.protos.len() * 12
            + self.fields.len() * 8
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
            (0x50, self.fields.len()),
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
        for (c, t, n) in &self.fields {
            put(&mut out, &(self.type_(c) as u16).to_le_bytes());
            put(&mut out, &(self.type_(t) as u16).to_le_bytes());
            put(&mut out, &self.string(&u(n)).to_le_bytes());
        }
        for (c, n, p) in &self.methods {
            put(&mut out, &(self.type_(c) as u16).to_le_bytes());
            let proto = self.protos.iter().position(|q| q == p).unwrap() as u16;
            put(&mut out, &proto.to_le_bytes());
            put(&mut out, &self.string(&u(n)).to_le_bytes());
        }
        for (desc, sfields, methods) in classes {
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
            let mut sf: Vec<u16> = sfields.iter().map(|f| self.field(f)).collect();
            sf.sort();
            let mut dm: Vec<(u16, u32, u32)> = methods
                .iter()
                .zip(&code_offs)
                .map(|((n, flags, ..), off)| (self.method(desc, n), *flags, *off))
                .collect();
            dm.sort();
            for n in [sf.len(), 0, dm.len(), 0] {
                uleb(&mut out, n as u32);
            }
            let mut prev = 0;
            for f in sf {
                uleb(&mut out, (f - prev) as u32);
                uleb(&mut out, 0x1A); // private static final
                prev = f;
            }
            prev = 0;
            for (m, flags, off) in dm {
                uleb(&mut out, (m - prev) as u32);
                uleb(&mut out, flags);
                uleb(&mut out, off);
                prev = m;
            }
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

/// Builds `Main` (paranoid call sites) + `Deobfuscator$app` into an APK.
fn paranoid_apk(secrets: &[&str]) -> std::path::PathBuf {
    let plain: Vec<Vec<u16>> = secrets.iter().map(|s| u(s)).collect();
    let refs: Vec<&[u16]> = plain.iter().map(Vec::as_slice).collect();
    let (ids, chunks) = asc_paranoid::obfuscate(0xC0FFEE, &refs);
    assert!(chunks.len() < 8, "const/4 chunk count");

    let get_string: Proto = (STRING, vec!["J"]);
    let dex = Dex::new(
        vec![(DEOB, STRINGS, "chunks")],
        vec![
            (DEOB, "<clinit>", ("V", vec![])),
            (DEOB, "getString", get_string.clone()),
            (HELPER, "getString", (STRING, vec!["J", STRINGS])),
            (MAIN, "greet", (STRING, vec![])),
            (MAIN, "url", (STRING, vec![])),
            (MAIN, "reuse", (STRING, vec![])),
            (MAIN, "fromParam", get_string),
        ],
        &chunks,
    );
    let chunks_f = dex.field("chunks");
    let helper = dex.method(HELPER, "getString");
    let deob_get = dex.method(DEOB, "getString");

    let mut clinit = vec![
        0x0012 | (chunks.len() as u16) << 12,
        0x0023,
        dex.type_(STRINGS) as u16,
        0x0069,
        chunks_f,
        0x0062,
        chunks_f,
    ];
    for (i, c) in chunks.iter().enumerate() {
        clinit.extend([
            0x0112 | (i as u16) << 12,
            0x021A,
            dex.string(c) as u16,
            0x024D,
            0x0100,
        ]);
    }
    clinit.push(0x000E);
    let getstring = vec![0x0062, chunks_f, 0x3071, helper, 0x0021, 0x000C, 0x0011];
    let wide = |id: i64| (0..4).map(move |k| (id >> (16 * k)) as u16);
    let call = |id: i64, range: bool| {
        let mut v = vec![0x0018];
        v.extend(wide(id));
        v.extend(if range {
            [0x0277, deob_get, 0x0000]
        } else {
            [0x2071, deob_get, 0x0010]
        });
        v.extend([0x000C, 0x0011]);
        v
    };

    let bytes = dex.finish(&[
        (
            DEOB,
            vec!["chunks"],
            vec![
                ("<clinit>", ACC_STATIC_CTOR, 3, 0, clinit),
                ("getString", ACC_PUBLIC_STATIC, 3, 2, getstring),
            ],
        ),
        (
            MAIN,
            vec![],
            vec![
                ("greet", ACC_PUBLIC_STATIC, 2, 0, call(ids[0], false)),
                ("url", ACC_PUBLIC_STATIC, 2, 0, call(ids[1], true)),
                ("reuse", ACC_PUBLIC_STATIC, 2, 0, call(ids[2], false)),
                (
                    "fromParam",
                    ACC_PUBLIC_STATIC,
                    2,
                    2,
                    vec![0x2071, deob_get, 0x0010, 0x000C, 0x0011],
                ),
            ],
        ),
    ]);

    let path = std::env::temp_dir().join(format!("asc_paranoid_{}.apk", std::process::id()));
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
    let opts =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("classes.dex", opts).unwrap();
    zip.write_all(&bytes).unwrap();
    zip.finish().unwrap();
    path
}

#[test]
fn paranoid_strings_decode_in_getclass_and_findrefs() {
    // "greet" also exists in the pool (method name): reuse path.
    let apk = paranoid_apk(&[
        "Hello, Paranoid! \u{e9}\u{1F600}",
        "https://example.com/api",
        "greet",
    ]);
    let getclass = |paranoid| {
        let opts = GetClassOptions {
            paranoid,
            ..GetClassOptions::default()
        };
        run_getclass(&GetClassJob::new(&apk, MAIN), &opts)
            .unwrap()
            .source
    };
    let findrefs = |pattern: &str, paranoid| {
        let opts = FindRefsOptions {
            paranoid,
            ..FindRefsOptions::default()
        };
        let report = run_findrefs(&FindRefsJob::new(&apk, Query::string(pattern)), &opts).unwrap();
        report
            .results
            .iter()
            .flat_map(|r| {
                r.matches
                    .iter()
                    .map(|m| (m.caller.clone(), m.matched.clone()))
            })
            .collect::<Vec<_>>()
    };

    let plain = getclass(false);
    assert!(!plain.contains("Hello, Paranoid"), "{plain}");

    let decoded = getclass(true);
    assert!(
        decoded.contains("Hello, Paranoid! \u{e9}\u{1F600}"),
        "{decoded}"
    );
    assert!(decoded.contains("https://example.com/api"), "{decoded}");
    assert!(decoded.contains("\"greet\""), "{decoded}");
    // A non-constant id (method parameter) is left as a call.
    assert!(decoded.contains("getString("), "{decoded}");

    assert!(findrefs("example.com", false).is_empty());
    assert_eq!(
        findrefs("example.com", true),
        vec![(
            "Lcom/poc/Main;->url".to_string(),
            vec!["https://example.com/api".to_string()]
        )]
    );

    std::fs::remove_file(&apk).ok();
}
