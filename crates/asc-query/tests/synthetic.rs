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

/// Helper: const-string vAA, string@BBBB (`0x1a AA BBBB`).
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
