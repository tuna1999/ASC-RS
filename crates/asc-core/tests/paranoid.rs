//! End-to-end `--paranoid`: a hand-assembled Paranoid-shaped DEX inside
//! an APK, run through `run_getclass` / `run_findrefs`.

mod common;

use asc_core::{
    FindRefsJob, FindRefsOptions, GetClassJob, GetClassOptions, run_findrefs, run_getclass,
};
use asc_query::Query;
use common::{Dex, OBJECT, Proto, STRING, STRINGS, write_apk};

const DEOB: &str = "Lio/michaelrocks/paranoid/Deobfuscator$app;";
const HELPER: &str = "Lio/michaelrocks/paranoid/DeobfuscatorHelper;";
const MAIN: &str = "Lcom/poc/Main;";
const ACC_PUBLIC_STATIC: u32 = 0x0009;
const ACC_STATIC_CTOR: u32 = 0x10008;

fn u(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// Builds `Main` (paranoid call sites) + `Deobfuscator$app` into an APK.
fn paranoid_apk(secrets: &[&str]) -> std::path::PathBuf {
    let plain: Vec<Vec<u16>> = secrets.iter().map(|s| u(s)).collect();
    let refs: Vec<&[u16]> = plain.iter().map(Vec::as_slice).collect();
    let (ids, chunks) = asc_paranoid::obfuscate(0xC0FFEE, &refs);
    assert!(chunks.len() < 8, "const/4 chunk count");

    let get_string: Proto = (STRING, vec!["J"]);
    let dex = Dex::new(
        &[OBJECT, DEOB, MAIN],
        vec![(DEOB, STRINGS, "chunks")],
        vec![
            (DEOB.to_string(), "<clinit>", ("V", vec![])),
            (DEOB.to_string(), "getString", get_string.clone()),
            (
                HELPER.to_string(),
                "getString",
                (STRING, vec!["J", STRINGS]),
            ),
            (MAIN.to_string(), "greet", (STRING, vec![])),
            (MAIN.to_string(), "url", (STRING, vec![])),
            (MAIN.to_string(), "reuse", (STRING, vec![])),
            (MAIN.to_string(), "fromParam", get_string),
        ],
        &chunks,
    );
    let helper = dex.method(HELPER, "getString");
    let chunks_f = dex.field("chunks");
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

    write_apk("paranoid", &[("classes.dex", bytes)])
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
