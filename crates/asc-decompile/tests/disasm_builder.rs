//! Self-check for the synthetic DEX builder in `tests/common/mod.rs`.
//!
//! Runs against `droidsaw_dex::DexFile::parse` only — no dependency on
//! `ClassDecompiler::disassemble`, so the builder is provably correct
//! (pools, map-driven sections, class_data, code_item) before any
//! disassembly expectation is compared against it.

mod common;

use common::*;
use droidsaw_dex::annotation::EncodedValue;
use droidsaw_dex::decode::{CodeItemInvariantViolation, PayloadData, PoolIndex, parse_code_item};
use droidsaw_dex::ids::{CallSiteIdx, MethodHandleIdx, ProtoIdx, StringIdx, TypeIdx};
use droidsaw_dex::parser::DexFile;

const GATE: &str = "Lgate/C;";

/// The class every gate DEX declares: `Lgate/C;` extending
/// `Ljava/lang/Object;`, pool order V(2) / Object(1) / gate(0).
fn base_spec() -> DexSpec {
    let mut s = DexSpec::default();
    let cls = s.ty(GATE);
    let object = s.ty("Ljava/lang/Object;");
    let void = s.ty("V");
    s.proto("V", void, &[]);
    s.classes.push(ClassSpec {
        flags: 0x0001, // ACC_PUBLIC
        class_idx: cls,
        superclass: Some(object),
        interfaces: vec![],
        static_fields: vec![],
        instance_fields: vec![],
        direct_methods: vec![],
        virtual_methods: vec![],
    });
    s
}

#[test]
fn adler32_matches_known_vector() {
    // RFC 1950: Adler-32("Wikipedia") = 0x11E60398.
    assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
}

#[test]
fn sha1_matches_known_vector() {
    // FIPS 180-2 test vector: SHA-1("abc").
    assert_eq!(
        hex(&sha1(b"abc")),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    // and the 448-bit vector, which exercises the two-block padding path.
    assert_eq!(
        hex(&sha1(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
}

/// Write a 32-bit branch offset into the 31t instruction at code-unit
/// `at` (low half at `at + 1`, high half at `at + 2`).
fn patch_branch32(units: &mut [u16], at: u16, rel: i32) {
    let bits = rel as u32;
    units[at as usize + 1] = (bits & 0xFFFF) as u16;
    units[at as usize + 2] = (bits >> 16) as u16;
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn header_and_pools_parse_as_built() {
    let mut s = base_spec();
    let int_ty = s.ty("I");
    assert_eq!(int_ty, 3, "I is type 3");
    // proto 0 = ()V
    let m0 = s.method(0, 0, "m");
    let m1 = s.method(0, 0, "m"); // overload: same name, different proto
    let int_proto = s.proto("I", 0, &[3]);
    let m2 = s.method(0, int_proto, "take");
    assert_eq!((m0, m1, m2), (0, 1, 2));

    s.classes[0].direct_methods.push(Method {
        name: m0,
        flags: 0x0009, // public static
        code: Some(Code {
            registers: 2,
            ins: 0,
            outs: 0,
            units: vec![0x000E], // return-void
            tries: vec![],
            handlers: vec![],
        }),
    });
    s.classes[0].direct_methods.push(Method {
        name: m1,
        flags: 0x1008, // public static synthetic
        code: Some(Code {
            registers: 1,
            ins: 0,
            outs: 0,
            units: vec![0x000E],
            tries: vec![],
            handlers: vec![],
        }),
    });
    s.classes[0].virtual_methods.push(Method {
        name: m2,
        flags: 0x0001,
        code: None,
    });

    let bytes = s.build();
    assert_eq!(&bytes[..8], b"dex\n039\0");
    let file_size = u32::from_le_bytes(bytes[0x20..0x24].try_into().unwrap()) as usize;
    assert_eq!(file_size, bytes.len());
    assert_eq!(
        u32::from_le_bytes(bytes[0x08..0x0C].try_into().unwrap()),
        adler32(&bytes[0x0C..file_size]),
        "stored adler32 must cover [0x0C, file_size)"
    );
    assert_eq!(
        bytes[0x0C..0x20],
        sha1(&bytes[0x20..file_size]),
        "stored signature must cover [0x20, file_size)"
    );

    let dex = DexFile::parse(&bytes, None).expect("builder output must parse");
    assert!(dex.input_checksums_canonical);
    assert_eq!(dex.strings.len(), s.strings.len());
    assert_eq!(
        dex.get_type_descriptor(TypeIdx(0)).unwrap(),
        GATE,
        "type 0 is the gate class"
    );
    assert_eq!(
        dex.get_type_descriptor(TypeIdx(1)).unwrap(),
        "Ljava/lang/Object;"
    );
    assert_eq!(dex.type_descriptors.len(), 4);
    assert_eq!(dex.protos.len(), 2);
    assert_eq!(dex.protos[0].return_type_idx, TypeIdx(2)); // ()V
    assert_eq!(dex.protos[0].parameters_off, 0);
    assert_ne!(dex.protos[1].parameters_off, 0, "(I)V has a type_list");
    assert_eq!(dex.methods.len(), 3);
    assert_eq!(dex.class_defs.len(), 1);
    assert_eq!(
        dex.class_defs[0].superclass_idx,
        Some(TypeIdx(1)),
        "superclass is Ljava/lang/Object;"
    );
    // The builder appends to the id pools in first-use order, so droidsaw
    // records pool-ordering notes. No *subsection* may be skipped.
    let notes: Vec<String> = dex
        .parse_errors
        .iter()
        .map(|f| format!("{:?}", f.kind))
        .collect();
    assert!(
        notes.iter().all(|k| k.contains("OutOfOrder")),
        "only pool-ordering notes expected, got {notes:?}"
    );

    let (idx, _) = dex.find_class(GATE).expect("gate class is found");
    assert_eq!(idx, 0);
    let methods = dex.list_methods(idx, &bytes).unwrap();
    assert_eq!(methods.len(), 3);
    // class_data order: direct methods first, then virtual.
    assert_eq!(methods[0].name, "m");
    assert!(methods[0].is_direct);
    assert!(methods[0].has_code);
    assert_eq!(methods[1].name, "m");
    // 16-byte header + 2 bytes of code, next item 4-byte aligned
    assert_eq!(methods[1].code_off, methods[0].code_off + 20);
    assert_eq!(methods[2].name, "take");
    assert!(!methods[2].is_direct);
    assert!(!methods[2].has_code, "abstract-ish method has no code item");
    assert_eq!(methods[2].return_type, "Lgate/C;");
    assert_eq!(methods[2].parameters, vec!["I"]);

    let code = parse_code_item(&bytes, methods[0].code_off).unwrap();
    assert_eq!(code.registers_size, 2);
    assert_eq!(code.instructions.len(), 1);
    assert!(code.invariant_violations.is_empty());
}

#[test]
fn call_site_and_method_handle_sections_parse() {
    let mut s = base_spec();
    let cls = s.classes[0].class_idx;
    let void_proto = 0u32;
    let int_ty = s.ty("I");
    let int_proto = s.proto("I", 2, &[int_ty]);
    let str_proto = s.proto("Ljava/lang/String;", 2, &[]);
    let metafactory = s.method(cls, void_proto, "metafactory");
    let run = s.method(cls, void_proto, "run");
    let lam = s.method(cls, void_proto, "lambda$run$0");
    // handle 0: invoke-constructor on <init>; 1: invoke-static
    // metafactory (the LambdaMetafactory bootstrap); 2: invoke-instance.
    s.handles.push(MethodHandle {
        kind: 6,
        member: run as u16,
    });
    s.handles.push(MethodHandle {
        kind: 4, // invoke-static
        member: metafactory as u16,
    });
    s.handles.push(MethodHandle {
        kind: 5, // invoke-instance
        member: lam as u16,
    });
    let s_name = s.str("run");
    s.call_sites.push(encoded_array(&[
        Ev::MethodHandle(1),
        Ev::Str(s_name),
        Ev::MethodType(str_proto),
        Ev::MethodHandle(0),
        Ev::MethodType(int_proto),
    ]));
    s.call_sites.push(encoded_array(&[
        Ev::MethodHandle(2),
        Ev::Str(s_name),
        Ev::MethodType(str_proto),
    ]));

    // invoke-custom {v0}, call_site_0 ; invoke-custom/range {v0 .. v2}, call_site_1
    let mut units = insn_35c(0xFC, 1, 0, [0, 0, 0, 0, 0]);
    units.extend(insn_3rc(0xFD, 3, 1, 0));
    units.push(0x000E);
    s.classes[0].direct_methods.push(Method {
        name: 0,
        flags: 0x0008,
        code: Some(Code {
            registers: 3,
            ins: 0,
            outs: 0,
            units,
            tries: vec![],
            handlers: vec![],
        }),
    });
    // method 0 was never declared; wire it up.
    s.methods[0].class_idx = cls as u16;
    s.methods[0].proto_idx = void_proto as u16;

    let bytes = s.build();
    let dex = DexFile::parse(&bytes, None).expect("parse");
    assert_eq!(dex.call_site_ids.len(), 2, "two call_site_ids rows");
    assert_eq!(dex.method_handles.len(), 3);
    assert_eq!(dex.method_handles[0].kind, 6);
    assert_eq!(dex.method_handles[0].field_or_method_id, run as u16);
    assert_eq!(dex.method_handles[1].kind, 4);
    assert_eq!(dex.method_handles[1].field_or_method_id, metafactory as u16);

    let cs0 = &dex.encoded_arrays[&dex.call_site_ids[0]];
    assert_eq!(cs0.len(), 5);
    assert_eq!(cs0[0], EncodedValue::MethodHandle(MethodHandleIdx(1)));
    assert_eq!(cs0[1], EncodedValue::String(StringIdx(s_name)));
    assert_eq!(cs0[2], EncodedValue::MethodType(ProtoIdx(str_proto)));
    assert_eq!(cs0[3], EncodedValue::MethodHandle(MethodHandleIdx(0)));
    assert_eq!(cs0[4], EncodedValue::MethodType(ProtoIdx(int_proto)));
    let cs1 = &dex.encoded_arrays[&dex.call_site_ids[1]];
    assert_eq!(cs1.len(), 3, "second call site carries no extra args");

    // The decode path classifies invoke-custom as CallSite(idx), and the
    // index is the position in call_site_ids (not an offset).
    let code_off = dex.list_methods(0, &bytes).unwrap()[0].code_off;
    let code = parse_code_item(&bytes, code_off).unwrap();
    assert!(
        code.invariant_violations.is_empty(),
        "{:?}",
        code.invariant_violations
    );
    assert_eq!(
        code.instructions[0].pool_idx,
        Some(PoolIndex::CallSite(CallSiteIdx(0)))
    );
    assert_eq!(
        code.instructions[1].pool_idx,
        Some(PoolIndex::CallSite(CallSiteIdx(1)))
    );
}

#[test]
fn hiding_post_o_map_rows_hides_the_sections() {
    let mut s = base_spec();
    s.handles.push(MethodHandle { kind: 4, member: 0 });
    s.call_sites.push(encoded_array(&[Ev::MethodHandle(0)]));
    s.hide_post_o_map_entries = true;
    let bytes = s.build();
    let dex = DexFile::parse(&bytes, None).expect("parse");
    assert!(
        dex.call_site_ids.is_empty(),
        "no TYPE_CALL_SITE_ID_ITEM row"
    );
    assert!(
        dex.method_handles.is_empty(),
        "no TYPE_METHOD_HANDLE_ITEM row"
    );
}

#[test]
fn try_catch_and_payloads_parse() {
    let mut s = base_spec();
    let throwable = s.ty("Ljava/lang/Throwable;");
    s.method(0, 0, "g");
    let mut units: Vec<u16> = Vec::new();
    units.push(0x0000); // 0 nop, so the switch lands on an odd address
    units.extend(insn_31t(0x2B, 0, 0)); // 1..3  packed-switch v0
    let payload_at = units.len() as u16; // 4
    // first_key -2; both targets back to addr 0.
    // rel -1 -> target addr 0; rel 0 -> the switch itself (addr 1)
    units.extend(packed_switch_payload(-2, &[-1, 0]));
    patch_branch32(&mut units, 1, i32::from(payload_at) - 1);
    // try covers [0, 1) -> end label addr 1; typed handler at 3.
    units.push(0x000E); // 4
    units.push(0x000E); // 5
    let switch_pc = 1u16;
    s.classes[0].direct_methods.push(Method {
        name: 0,
        flags: 0x0008,
        code: Some(Code {
            registers: 2,
            ins: 0,
            outs: 1,
            units,
            tries: vec![TrySpec {
                start_addr: 0,
                insn_count: 1,
                handler_off: 1,
            }],
            handlers: vec![HandlerSpec {
                catches: vec![(throwable as u16, 5)],
                catch_all: Some(5),
            }],
        }),
    });
    let bytes = s.build();
    let dex = DexFile::parse(&bytes, None).expect("parse");
    let code_off = dex.list_methods(0, &bytes).unwrap()[0].code_off;
    let code = parse_code_item(&bytes, code_off).unwrap();
    assert!(
        code.invariant_violations.is_empty(),
        "{:?}",
        code.invariant_violations
    );
    assert_eq!(code.tries.len(), 1);
    assert_eq!(code.tries[0].start_addr, 0);
    assert_eq!(code.tries[0].insn_count, 1);
    assert_eq!(code.catch_handlers.len(), 1);
    assert_eq!(code.catch_handlers[0].catches.len(), 1);
    assert_eq!(code.catch_handlers[0].catch_all_addr, Some(5));

    // packed-switch targets are stored relative to the switch instruction.
    let payload = code
        .payloads
        .get(&u32::from(payload_at))
        .unwrap_or_else(|| {
            panic!(
                "payload at {payload_at} unresolved: {:?}",
                code.invariant_violations
            )
        });
    match payload {
        PayloadData::PackedSwitch { first_key, targets } => {
            assert_eq!(*first_key, -2, "first_key is signed");
            assert_eq!(targets, &vec![0u32, switch_pc as u32]);
        }
        other => panic!("expected PackedSwitch, got {other:?}"),
    }
}

#[test]
fn unknown_opcode_byte_is_recorded_as_a_violation() {
    let mut s = base_spec();
    s.method(0, 0, "g");
    let mut units = insn_11n(0x12, 0, 1);
    units.push(0x003F); // 0x3f is not a defined opcode
    units.push(0x000E);
    s.classes[0].direct_methods.push(Method {
        name: 0,
        flags: 0x0008,
        code: Some(Code {
            registers: 2,
            ins: 0,
            outs: 0,
            units,
            tries: vec![],
            handlers: vec![],
        }),
    });
    let bytes = s.build();
    let dex = DexFile::parse(&bytes, None).expect("parse");
    let code_off = dex.list_methods(0, &bytes).unwrap()[0].code_off;
    let code = parse_code_item(&bytes, code_off).unwrap();
    assert_eq!(code.instructions.len(), 2, "the unknown byte is dropped");
    assert!(
        code.invariant_violations.iter().any(|v| matches!(
            v,
            CodeItemInvariantViolation::UnknownOpcodeByte {
                source_pc: 1,
                opcode_byte: 0x3F
            }
        )),
        "{:?}",
        code.invariant_violations
    );
}

#[test]
fn array_payloads_of_every_width_parse() {
    for (width, bytes) in [
        (1u16, vec![0xFFu8, 0x01]),
        (2, vec![0x00, 0x80, 0xFF, 0x7F]),
        (4, vec![0, 0, 0, 0x80, 0xFF, 0xFF, 0xFF, 0x7F]),
        (
            8,
            vec![
                0, 0, 0, 0, 0, 0, 0, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
            ],
        ),
    ] {
        let mut s = base_spec();
        s.method(0, 0, "g");
        let mut units = insn_31t(0x26, 0, 0); // fill-array-data, offset patched below
        units.push(0x000E);
        let payload_at = units.len() as u32;
        units[1] = payload_at as u16; // low half of the 32-bit offset
        units.extend(array_payload(width, &bytes));
        s.classes[0].direct_methods.push(Method {
            name: 0,
            flags: 0x0008,
            code: Some(Code {
                registers: 2,
                ins: 0,
                outs: 0,
                units,
                tries: vec![],
                handlers: vec![],
            }),
        });
        let b = s.build();
        let dex = DexFile::parse(&b, None).expect("parse");
        let code_off = dex.list_methods(0, &b).unwrap()[0].code_off;
        let code = parse_code_item(&b, code_off).unwrap();
        assert!(
            code.invariant_violations.is_empty(),
            "{:?}",
            code.invariant_violations
        );
        match code
            .payloads
            .get(&payload_at)
            .expect("payload at its own address")
        {
            PayloadData::FillArrayData {
                element_width,
                data: d,
            } => {
                assert_eq!(*element_width, width);
                assert_eq!(d, &bytes);
            }
            other => panic!("expected FillArrayData, got {other:?}"),
        }
    }
}
