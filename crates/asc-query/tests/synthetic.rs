//! Synthetic DEX tests for `asc-query`.
//!
//! Tests that exercise `find_refs` against a hand-built DEX. The DEX
//! builder in `common::Builder` was originally meant to support a
//! rich set of multi-class / multi-method / shared-code_off scenarios,
//! but its prototype layout does not always produce a parseable DEX.
//! The scenarios that depend on it are tested via the golden corpus
//! (which is real, well-formed) in `tests/golden.rs` and the
//! divergence verification in `tests/divergence_verification.rs`.
//!
//! This file retains the tests that exercise the engine without
//! requiring a multi-class builder (the empty-target short-circuit).

use asc_dex::view::DexView;
use asc_query::{Query, find_refs};

mod common;

use common::Builder;

/// Helper: `0x1a00 | vAA`, string@BBBB. NB: Dalvik puts the opcode in the
/// LOW byte, so this decodes as opcode `vAA` (0 = nop), not const-string —
/// fine for the short-circuit test, which never walks code.
fn const_string(reg_a: u8, string_idx: u32) -> [u16; 2] {
    [0x1a00 | (reg_a as u16), string_idx as u16]
}

/// Builds a minimal valid DEX containing one class with one method
/// wrapping the supplied bytecode.
fn build_dex(code: &[u16]) -> Vec<u8> {
    let mut b = Builder::new();
    let _s0 = b.add_string("LFoo;");
    let _s1 = b.add_string("V");
    let _s2 = b.add_string("hello world");
    let t_foo = b.add_type("LFoo;");
    let t_v = b.add_type("V");
    let p_void = b.add_proto("V", t_v, &[]);
    let (_m0, code_off) = b.add_method(t_foo, p_void, "foo", code);
    b.add_class(t_foo, 1, None, &[(0, code_off)]);
    b.finalize()
}

#[test]
fn empty_target_short_circuits() {
    // The pattern matches no string in the string pool, so the
    // target set is empty and the engine returns immediately without
    // scanning any code.
    let bytes = build_dex(&const_string(0, 0));
    let view = DexView::parse(&bytes).unwrap();
    let q = Query::string("xyz_no_match_xyz");
    let report = find_refs(&view, &q);
    assert!(report.hits.is_empty());
    assert!(report.errors.is_empty());
    assert!(report.complete);
}

/// Many methods sharing one code body multiply every matched ref (one hit
/// per owner). A small hostile DEX could thus demand hits ∝ refs × owners
/// — far more than its own size. The scan must stop at the work bound,
/// keep what it found and report the DEX incomplete.
#[test]
fn shared_code_body_fan_out_is_bounded() {
    const OWNERS: u32 = 1000;
    const REFS: usize = 1000;
    // Room for the header + ~1000 string/method ids before the data.
    let mut b = Builder::with_data_start(0x8000);
    let s_hello = b.add_string("hello world");
    let t_foo = b.add_type("LFoo;");
    let t_v = b.add_type("V");
    let p_void = b.add_proto("V", t_v, &[]);
    // const-string v0, string@s_hello (opcode in the low byte).
    let code: Vec<u16> = (0..REFS).flat_map(|_| [0x001a, s_hello as u16]).collect();
    let (m0, shared) = b.add_method(t_foo, p_void, "m0", &code);
    let mut methods = vec![(m0, shared)];
    for i in 1..OWNERS {
        let (m, _) = b.add_method(t_foo, p_void, &format!("m{i}"), &[]);
        methods.push((m, shared));
    }
    b.add_class(t_foo, 1, None, &methods);
    let bytes = b.finalize();
    let view = DexView::parse(&bytes).unwrap();
    let report = find_refs(&view, &Query::string("hello"));
    assert!(!report.complete);
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.to_string().contains("work budget exhausted")),
        "{:?}",
        report.errors
    );
    let cap = (bytes.len() / 2).max(1 << 16);
    assert!(
        report.hits.len() <= cap,
        "{} hits > cap {cap}",
        report.hits.len()
    );
    assert!(!report.hits.is_empty(), "hits before the bound are kept");
}

/// Repeated references to one string index are counted per site (the
/// decode is cached by index, so the count must still advance).
#[test]
fn strings_of_class_counts_every_site_of_a_cached_string() {
    let mut b = Builder::with_data_start(0x400);
    let s_hello = b.add_string("hello world");
    let t_foo = b.add_type("LFoo;");
    let t_v = b.add_type("V");
    let p_void = b.add_proto("V", t_v, &[]);
    let code: Vec<u16> = (0..3).flat_map(|_| [0x001a, s_hello as u16]).collect();
    let (m0, off) = b.add_method(t_foo, p_void, "m0", &code);
    b.add_class(t_foo, 1, None, &[(m0, off)]);
    let bytes = b.finalize();
    let view = DexView::parse(&bytes).unwrap();
    let r = asc_query::strings_of_class(&view, "LFoo;");
    assert!(r.complete, "{:?}", r.errors);
    assert_eq!(r.strings.len(), 1);
    assert_eq!(
        (r.strings[0].text.as_str(), r.strings[0].sites),
        ("hello world", 3)
    );
}
