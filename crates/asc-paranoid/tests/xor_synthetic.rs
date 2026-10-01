//! Synthetic DEX tests for the static XOR string decoder (`--decode-xor`).
//!
//! Byte-level builder (no corpus needed): one decoder class `LDec;` with
//! `static String i(byte[])` (XOR-every-element-with-key loop) and one
//! caller class `LCalls;` whose methods build `byte[]` from constants and
//! call `i`. Negative cases poison the same shape in controlled ways.

#![allow(dead_code)]

use asc_dex::DexView;
use asc_paranoid::xor::{XorResolver, find_xor_decoders};

// ---------------- DEX builder ----------------

#[derive(Clone)]
struct MDef {
    method_idx: u32,
    access: u32,
    registers: u16,
    ins: u16,
    outs: u16,
    insns: Vec<u16>,
}

struct Cls {
    type_idx: u16,
    methods: Vec<MDef>,
}

struct Fixture<'a> {
    strings: &'a [&'a str],
    /// type idx -> string idx
    types: &'a [u32],
    /// (shorty string idx, return type idx, param type idxs)
    protos: &'a [(u32, u16, &'a [u16])],
    /// (class type idx, proto idx, name string idx)
    methods: &'a [(u16, u16, u32)],
    classes: &'a [Cls],
}

fn uleb(v: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut v = v;
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
    out
}

fn build(fx: &Fixture) -> Vec<u8> {
    let header = 112u32;
    let string_ids = header;
    let type_ids = string_ids + fx.strings.len() as u32 * 4;
    let proto_ids = type_ids + fx.types.len() as u32 * 4;
    let method_ids = proto_ids + fx.protos.len() as u32 * 12;
    let class_defs = method_ids + fx.methods.len() as u32 * 8;
    let mut tail = class_defs + fx.classes.len() as u32 * 32;
    let tail_base = tail;
    let align4 = |v: u32| (v + 3) & !3;

    let mut buf: Vec<u8> = Vec::new();
    let push = |buf: &mut Vec<u8>, bytes: &[u8], at: u32| {
        let want = (at - tail_base) as usize;
        assert!(buf.len() <= want, "sections must be appended in order");
        buf.resize(want, 0); // alignment padding
        buf.extend_from_slice(bytes);
    };

    // ---- tail: type lists, string data, code items, class data, map ----
    let mut proto_params_off = vec![0u32; fx.protos.len()];
    for (i, (_, _, params)) in fx.protos.iter().enumerate() {
        if params.is_empty() {
            continue;
        }
        tail = align4(tail);
        proto_params_off[i] = tail;
        let mut tl = (params.len() as u32).to_le_bytes().to_vec();
        for &t in *params {
            tl.extend_from_slice(&t.to_le_bytes());
        }
        push(&mut buf, &tl, tail);
        tail += tl.len() as u32;
    }

    let mut string_data_off = vec![0u32; fx.strings.len()];
    for (i, s) in fx.strings.iter().enumerate() {
        string_data_off[i] = tail;
        let mut sd = uleb(s.len() as u32);
        sd.extend_from_slice(s.as_bytes());
        sd.push(0);
        push(&mut buf, &sd, tail);
        tail += sd.len() as u32;
    }

    let mut code_off = vec![0u32; fx.classes.iter().map(|c| c.methods.len()).sum::<usize>()];
    let mut ci = 0;
    for c in fx.classes {
        for m in &c.methods {
            tail = align4(tail);
            code_off[ci] = tail;
            ci += 1;
            let mut item = Vec::new();
            item.extend_from_slice(&m.registers.to_le_bytes());
            item.extend_from_slice(&m.ins.to_le_bytes());
            item.extend_from_slice(&m.outs.to_le_bytes());
            item.extend_from_slice(&0u16.to_le_bytes()); // tries
            item.extend_from_slice(&0u32.to_le_bytes()); // debug info off
            item.extend_from_slice(&(m.insns.len() as u32).to_le_bytes());
            for &u in &m.insns {
                item.extend_from_slice(&u.to_le_bytes());
            }
            while item.len() % 4 != 0 {
                item.push(0);
            }
            push(&mut buf, &item, tail);
            tail += item.len() as u32;
        }
    }

    let mut class_data_off = vec![0u32; fx.classes.len()];
    for (ci, c) in fx.classes.iter().enumerate() {
        tail = align4(tail);
        class_data_off[ci] = tail;
        let mut cd = Vec::new();
        cd.extend(uleb(0)); // static fields
        cd.extend(uleb(0)); // instance fields
        cd.extend(uleb(c.methods.len() as u32));
        cd.extend(uleb(0)); // virtual methods
        let mut prev = 0u32;
        for (mi, m) in c.methods.iter().enumerate() {
            cd.extend(uleb(m.method_idx.wrapping_sub(prev)));
            prev = m.method_idx;
            cd.extend(uleb(m.access));
            cd.extend(uleb(
                code_off[fx.classes[..ci]
                    .iter()
                    .map(|c| c.methods.len())
                    .sum::<usize>()
                    + mi],
            ));
        }
        push(&mut buf, &cd, tail);
        tail += cd.len() as u32;
    }

    // ---- map list ----
    tail = align4(tail);
    let map_off = tail;
    let mut entries: Vec<(u16, u32, u32)> = vec![
        (0x0000, 1, 0),
        (0x0001, fx.strings.len() as u32, string_ids),
        (0x0002, fx.types.len() as u32, type_ids),
        (0x0003, fx.protos.len() as u32, proto_ids),
        (0x0005, fx.methods.len() as u32, method_ids),
        (0x0006, fx.classes.len() as u32, class_defs),
    ];
    if code_off.iter().any(|&o| o != 0) {
        entries.push((0x2001, code_off.len() as u32, code_off[0]));
    }
    if fx.classes.iter().any(|c| !c.methods.is_empty()) {
        entries.push((0x2000, fx.classes.len() as u32, class_data_off[0]));
    }
    entries.push((0x2002, fx.strings.len() as u32, string_data_off[0]));
    entries.push((0x1000, 1, map_off));
    let mut map = (entries.len() as u32).to_le_bytes().to_vec();
    for (t, n, o) in entries {
        map.extend_from_slice(&t.to_le_bytes());
        map.extend_from_slice(&n.to_le_bytes());
        map.extend_from_slice(&o.to_le_bytes());
    }
    push(&mut buf, &map, tail);
    tail += map.len() as u32;

    // ---- header + id tables ----
    let total = tail;
    assert_eq!(buf.len() as u32 + tail_base, total);
    let mut out = vec![0u8; total as usize];
    out[tail_base as usize..total as usize].copy_from_slice(&buf);
    let put32 = |o: &mut [u8], at: u32, v: u32| {
        o[at as usize..at as usize + 4].copy_from_slice(&v.to_le_bytes())
    };
    let put16 = |o: &mut [u8], at: u32, v: u16| {
        o[at as usize..at as usize + 2].copy_from_slice(&v.to_le_bytes())
    };
    out[..8].copy_from_slice(b"dex\n035\0");
    put32(&mut out, 0x20, total);
    put32(&mut out, 0x24, 112);
    put32(&mut out, 0x28, 0x1234_5678);
    put32(&mut out, 0x34, map_off);
    put32(&mut out, 0x38, fx.strings.len() as u32);
    put32(&mut out, 0x3c, string_ids);
    put32(&mut out, 0x40, fx.types.len() as u32);
    put32(&mut out, 0x44, type_ids);
    put32(&mut out, 0x48, fx.protos.len() as u32);
    put32(&mut out, 0x4c, proto_ids);
    put32(&mut out, 0x50, 0);
    put32(&mut out, 0x54, 0);
    put32(&mut out, 0x58, fx.methods.len() as u32);
    put32(&mut out, 0x5c, method_ids);
    put32(&mut out, 0x60, fx.classes.len() as u32);
    put32(&mut out, 0x64, class_defs);
    put32(&mut out, 0x68, 0);
    put32(&mut out, 0x6c, 0);
    for (i, off) in string_data_off.iter().enumerate() {
        put32(&mut out, string_ids + i as u32 * 4, *off);
    }
    for (i, s) in fx.types.iter().enumerate() {
        put32(&mut out, type_ids + i as u32 * 4, *s);
    }
    for (i, (shorty, ret, _params)) in fx.protos.iter().enumerate() {
        let at = proto_ids + i as u32 * 12;
        put32(&mut out, at, *shorty);
        put16(&mut out, at + 4, *ret);
        put32(&mut out, at + 8, proto_params_off[i]);
    }
    for (i, (class, proto, name)) in fx.methods.iter().enumerate() {
        let at = method_ids + i as u32 * 8;
        put16(&mut out, at, *class);
        put16(&mut out, at + 2, *proto);
        put32(&mut out, at + 4, *name);
    }
    for (i, c) in fx.classes.iter().enumerate() {
        let at = class_defs + i as u32 * 32;
        put32(&mut out, at, c.type_idx as u32);
        put32(&mut out, at + 4, 1); // public
        put32(&mut out, at + 8, 0xFFFF_FFFF); // no superclass
        put32(&mut out, at + 12, 0); // no interfaces
        put32(&mut out, at + 16, 0xFFFF_FFFF); // no source file
        put32(&mut out, at + 20, 0); // no annotations
        put32(&mut out, at + 24, class_data_off[i]);
        put32(&mut out, at + 28, 0); // no static values
    }
    out
}

// ---------------- instruction encoders ----------------

fn const4(dst: u8, v: i8) -> Vec<u16> {
    vec![(((v as u8 as u16) & 0xF) << 12) | ((dst as u16) << 8) | 0x12]
}
fn const16(dst: u8, v: i16) -> Vec<u16> {
    vec![(dst as u16) << 8 | 0x13, v as u16]
}
fn aput_byte(val: u8, arr: u8, idx: u8) -> Vec<u16> {
    vec![(val as u16) << 8 | 0x4F, (idx as u16) << 8 | arr as u16]
}
fn aget_byte(dst: u8, arr: u8, idx: u8) -> Vec<u16> {
    vec![(dst as u16) << 8 | 0x48, (idx as u16) << 8 | arr as u16]
}
fn xor_int_lit8(dst: u8, src: u8, lit: i8) -> Vec<u16> {
    vec![
        (dst as u16) << 8 | 0xDF,
        (lit as u8 as u16) << 8 | src as u16,
    ]
}
fn int_to_byte(dst: u8, src: u8) -> Vec<u16> {
    vec![((src as u16) << 12) | ((dst as u16) << 8) | 0x8D]
}
fn add_int_lit8(dst: u8, src: u8, lit: i8) -> Vec<u16> {
    vec![
        (dst as u16) << 8 | 0xD8,
        (lit as u8 as u16) << 8 | src as u16,
    ]
}
fn if_eqz(a: u8, off: i16) -> Vec<u16> {
    vec![((a as u16) << 8) | 0x38, off as u16]
}
fn goto8(off: i8) -> Vec<u16> {
    vec![((off as u8 as u16) << 8) | 0x28]
}
fn if_ge(a: u8, b: u8, off: i16) -> Vec<u16> {
    vec![((b as u16) << 12) | ((a as u16) << 8) | 0x34, off as u16]
}
fn array_length(dst: u8, src: u8) -> Vec<u16> {
    vec![((src as u16) << 12) | ((dst as u16) << 8) | 0x21]
}
fn new_array(dst: u8, size: u8, type_idx: u16) -> Vec<u16> {
    vec![((size as u16) << 12) | ((dst as u16) << 8) | 0x23, type_idx]
}
fn new_instance(dst: u8, type_idx: u16) -> Vec<u16> {
    vec![(dst as u16) << 8 | 0x22, type_idx]
}
fn invoke_direct_2(midx: u16, r1: u8, r2: u8) -> Vec<u16> {
    vec![
        (2u16 << 12) | 0x70,
        midx,
        (r2 as u16) << 12 | (r1 as u16) << 8,
    ]
}
fn invoke_static_1(midx: u16, r1: u8) -> Vec<u16> {
    vec![(1u16 << 12) | 0x71, midx, r1 as u16]
}
fn invoke_direct_4(midx: u16, r1: u8, r2: u8, r3: u8, r4: u8) -> Vec<u16> {
    vec![
        (4u16 << 12) | 0x70,
        midx,
        (r4 as u16) << 12 | (r3 as u16) << 8 | (r2 as u16) << 4 | r1 as u16,
    ]
}
fn move_result_object(dst: u8) -> Vec<u16> {
    vec![(dst as u16) << 8 | 0x0C]
}
fn return_object(dst: u8) -> Vec<u16> {
    vec![(dst as u16) << 8 | 0x11]
}
/// `return new String(p, 0, p.length)` variant of [`decoder_insns`]
/// (same register budget: v4 = p0, v0 = offset, v1 = j, v2 = tmp, v3 = out).
fn decoder_insns_ii(key: i8) -> Vec<u16> {
    concat(&[
        &const4(0, 0), // offset 0
        &const4(1, 0), // j
        &array_length(2, 4),
        &if_ge(1, 2, 12),
        &aget_byte(2, 4, 1),
        &xor_int_lit8(2, 2, key),
        &int_to_byte(2, 2),
        &aput_byte(2, 4, 1),
        &add_int_lit8(1, 1, 1),
        &goto8(-12),
        &new_instance(3, 2),
        &array_length(2, 4), // v2 = p.length for the ctor
        &invoke_direct_4(3, 3, 4, 0, 2),
        &return_object(3),
    ])
}

fn concat(units: &[&Vec<u16>]) -> Vec<u16> {
    units.iter().flat_map(|v| v.iter().copied()).collect()
}

// ---------------- fixtures ----------------

/// Decoder body: `static String i(byte[] p) { for (int j = 0; j < p.length;
/// j++) p[j] = (byte)(p[j] ^ key); return new String(p); }`
/// registers: v0 = j, v1 = len, v2 = tmp, v3 = out, v4 = p0.
fn decoder_insns(key: i8) -> Vec<u16> {
    concat(&[
        &const4(0, 0),
        &array_length(1, 4),
        &if_ge(0, 1, 12),
        &aget_byte(2, 4, 0),
        &xor_int_lit8(2, 2, key),
        &int_to_byte(2, 2),
        &aput_byte(2, 4, 0),
        &add_int_lit8(0, 0, 1),
        &goto8(-12),
        &new_instance(3, 2),
        &invoke_direct_2(1, 3, 4),
        &return_object(3),
    ])
}

/// Caller: `byte[] a = {e0, e1}; String s = i(a); return s;`
/// registers: v0 = array, v1 = value, v2 = index, v3 = result, v4 = size.
fn caller_insns(e0: i8, e1: i8) -> Vec<u16> {
    concat(&[
        &const4(4, 2),
        &new_array(0, 4, 3),
        &const4(1, e0),
        &const4(2, 0),
        &aput_byte(1, 0, 2),
        &const4(1, e1),
        &const4(2, 1),
        &aput_byte(1, 0, 2),
        &invoke_static_1(0, 0),
        &move_result_object(3),
        &return_object(3),
    ])
}

const STRINGS: &[&str] = &[
    "LDec;",              // 0
    "LCalls;",            // 1
    "Ljava/lang/String;", // 2
    "[B",                 // 3
    "V",                  // 4
    "i",                  // 5
    "<init>",             // 6
    "a",                  // 7
    "LL",                 // 8 shorty ([B)String
    "L",                  // 9 shorty ()String / ([B)V
    "LLII",               // 10 shorty ([BII)V
    "I",                  // 11 int descriptor
];
const TYPES: &[u32] = &[0, 1, 2, 3, 4, 11];
const PROTOTYPES: &[(u32, u16, &[u16])] =
    &[(8, 2, &[3]), (9, 2, &[]), (9, 4, &[3]), (10, 4, &[3, 5, 5])];
const METHODS: &[(u16, u16, u32)] = &[(0, 0, 5), (2, 2, 6), (1, 1, 7), (2, 3, 6)];

fn dex_with_callers(callers: &[MDef]) -> Vec<u8> {
    dex_with(decoder_insns(105), callers)
}

fn dex_with(decoder: Vec<u16>, callers: &[MDef]) -> Vec<u8> {
    let classes = &[
        Cls {
            type_idx: 0,
            methods: vec![MDef {
                method_idx: 0,
                access: 0x8, // static
                registers: 5,
                ins: 1,
                outs: 4,
                insns: decoder,
            }],
        },
        Cls {
            type_idx: 1,
            methods: callers.to_vec(),
        },
    ];
    build(&Fixture {
        strings: STRINGS,
        types: TYPES,
        protos: PROTOTYPES,
        methods: METHODS,
        classes,
    })
}

fn caller(_name: &'static str, insns: Vec<u16>) -> MDef {
    MDef {
        method_idx: 2,
        access: 0x8,
        registers: 5,
        ins: 0,
        outs: 1,
        insns,
    }
}

/// `code_item` of the first method of `class` in `bytes`.
fn code_of_first_method<'a>(bytes: &'a [u8], class: &str) -> asc_dex::CodeItem<'a> {
    let view = DexView::parse(bytes).expect("dex parses");
    for i in 0..view.class_def_count() {
        let cd = view.class_def(i).ok().unwrap();
        let ty = view.type_(cd.class).ok().unwrap();
        let name = view.string(ty).ok().unwrap();
        if name.raw_mutf8() == class.as_bytes() {
            let data = view.class_data(cd.class_data_off).ok().flatten().unwrap();
            let m = &data.direct_methods[0];
            return view.code_item(m.code_off).ok().flatten().unwrap();
        }
    }
    panic!("class {class} not found");
}

// ---------------- tests ----------------

/// The decoder is recognized (class, method, key) and the caller's call
/// site decodes: "hi" is {0x68^105, 0x69^105} = {1, 0}.
#[test]
fn xor_decoder_recognized_and_call_decoded() {
    let bytes = dex_with_callers(&[caller("a", caller_insns(1, 0))]);
    let view = DexView::parse(&bytes).expect("dex parses");

    let decoders = find_xor_decoders(&view);
    assert_eq!(decoders.len(), 1, "decoder i() recognized");
    assert_eq!(decoders[0].class, "LDec;");
    assert_eq!(decoders[0].method, "i");
    assert_eq!(decoders[0].key, 105);

    let resolver = XorResolver::new(&view, &decoders);
    assert!(!resolver.is_empty());
    let code = code_of_first_method(&bytes, "LCalls;");
    let calls = resolver.calls(&view, &code);
    assert_eq!(calls.len(), 1, "one call site decoded");
    let call = &calls[0];
    assert_eq!(call.value, vec![0x68, 0x69], "decodes to \"hi\"");
    assert_eq!(call.result, Some(3), "move-result-object v3");
    assert!(call.patchable, "array untouched after the invoke");
    // invoke-static sits at code-unit offset 11 (1 + 2 + 4*1 + 2*2).
    assert_eq!(call.offset, 11);
}

/// An array read after the invoke aliases the decoder's in-place mutation:
/// the call still decodes (its value is the string at that point) but is
/// not patchable — replacing the call would change what the read sees.
#[test]
fn alias_after_invoke_is_not_patchable() {
    let insns = concat(&[
        &const4(4, 2),
        &new_array(0, 4, 3),
        &const4(1, 1),
        &const4(2, 0),
        &aput_byte(1, 0, 2),
        &const4(1, 0),
        &const4(2, 1),
        &aput_byte(1, 0, 2),
        &invoke_static_1(0, 0),
        &move_result_object(3),
        &aget_byte(1, 0, 2), // touches v0 after the decode call
        &return_object(3),
    ]);
    let bytes = dex_with_callers(&[caller("a", insns)]);
    let view = DexView::parse(&bytes).unwrap();
    let decoders = find_xor_decoders(&view);
    assert_eq!(decoders.len(), 1);
    let resolver = XorResolver::new(&view, &decoders);
    let code = code_of_first_method(&bytes, "LCalls;");
    let calls = resolver.calls(&view, &code);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].value, vec![0x68, 0x69]);
    assert!(!calls[0].patchable, "array read after the invoke");
}

/// An element never stored from a constant stays unknown: no decode, ever.
#[test]
fn unknown_element_is_not_decoded() {
    let insns = concat(&[
        &const4(4, 2),
        &new_array(0, 4, 3),
        &const4(1, 1),
        &const4(2, 0),
        &aput_byte(1, 0, 2),
        // element 1 never stored
        &invoke_static_1(0, 0),
        &move_result_object(3),
        &return_object(3),
    ]);
    let bytes = dex_with_callers(&[caller("a", insns)]);
    let view = DexView::parse(&bytes).unwrap();
    let decoders = find_xor_decoders(&view);
    assert_eq!(decoders.len(), 1);
    let resolver = XorResolver::new(&view, &decoders);
    let code = code_of_first_method(&bytes, "LCalls;");
    assert!(
        resolver.calls(&view, &code).is_empty(),
        "unknown element must not decode"
    );
}

/// A real join: one path builds the array, the other does not. The
/// dataflow meet drops the array binding, so the invoke after the merge
/// must not decode (an unconditional goto, in contrast, is one path and
/// may decode — see `xor_decoder_recognized_and_call_decoded` callers).
#[test]
fn join_of_two_paths_is_not_decoded() {
    let insns = concat(&[
        &const4(3, 0),  // condition
        &if_eqz(3, 10), // skip the construction when zero
        &const4(4, 2),  // then-arm: build the array
        &new_array(0, 4, 3),
        &const4(1, 1),
        &const4(2, 0),
        &aput_byte(1, 0, 2),
        &const4(1, 0),
        &const4(2, 1),
        &aput_byte(1, 0, 2),
        &goto8(2),              // -> join at the invoke
        &const4(0, 0),          // else-arm: v0 is not an array here
        &invoke_static_1(0, 0), // join: v0 = Arr on one path, Int on the other
        &move_result_object(3),
        &return_object(3),
    ]);
    let bytes = dex_with_callers(&[caller("a", insns)]);
    let view = DexView::parse(&bytes).unwrap();
    let decoders = find_xor_decoders(&view);
    assert_eq!(decoders.len(), 1);
    let resolver = XorResolver::new(&view, &decoders);
    let code = code_of_first_method(&bytes, "LCalls;");
    assert!(
        resolver.calls(&view, &code).is_empty(),
        "a join of disagreeing paths must not decode"
    );
}

/// The decoder mutates its argument, so only the first call on an array
/// decodes; the second sees poisoned elements.
#[test]
fn second_call_on_same_array_is_not_decoded() {
    let insns = concat(&[
        &const4(4, 2),
        &new_array(0, 4, 3),
        &const4(1, 1),
        &const4(2, 0),
        &aput_byte(1, 0, 2),
        &const4(1, 0),
        &const4(2, 1),
        &aput_byte(1, 0, 2),
        &invoke_static_1(0, 0),
        &move_result_object(3),
        &invoke_static_1(0, 0), // same array again
        &move_result_object(3),
        &return_object(3),
    ]);
    let bytes = dex_with_callers(&[caller("a", insns)]);
    let view = DexView::parse(&bytes).unwrap();
    let decoders = find_xor_decoders(&view);
    let resolver = XorResolver::new(&view, &decoders);
    let code = code_of_first_method(&bytes, "LCalls;");
    let calls = resolver.calls(&view, &code);
    assert_eq!(calls.len(), 1, "only the first call decodes");
    assert_eq!(calls[0].value, vec![0x68, 0x69]);
}

/// Bytes that do not decode as UTF-8 (`new String(byte[])` on Android is
/// UTF-8) are never guessed: no call.
#[test]
fn invalid_utf8_is_not_decoded() {
    // 150 ^ 105 = 0xFF in both elements -> invalid UTF-8.
    let insns = concat(&[
        &const4(4, 2),
        &new_array(0, 4, 3),
        &const16(1, 150),
        &const4(2, 0),
        &aput_byte(1, 0, 2),
        &const16(1, 150),
        &const4(2, 1),
        &aput_byte(1, 0, 2),
        &invoke_static_1(0, 0),
        &move_result_object(3),
        &return_object(3),
    ]);
    let bytes = dex_with_callers(&[caller("a", insns)]);
    let view = DexView::parse(&bytes).unwrap();
    let decoders = find_xor_decoders(&view);
    assert_eq!(decoders.len(), 1);
    let resolver = XorResolver::new(&view, &decoders);
    let code = code_of_first_method(&bytes, "LCalls;");
    assert!(
        resolver.calls(&view, &code).is_empty(),
        "invalid UTF-8 must not decode"
    );
}

/// A decoder body with a field access (or anything outside the P1
/// allow-list) is not a P1 decoder: nothing is recognized.
#[test]
fn decoder_with_field_access_is_rejected() {
    let mut insns = decoder_insns(105);
    let at = insns.len() - 3; // before new-instance
    insns.splice(
        at..at,
        // sget-object v0, field@0 (0x62, format 21c) — field access
        [0x0062, 0u16],
    );
    let classes = &[
        Cls {
            type_idx: 0,
            methods: vec![MDef {
                method_idx: 0,
                access: 0x8,
                registers: 5,
                ins: 1,
                outs: 2,
                insns,
            }],
        },
        Cls {
            type_idx: 1,
            methods: vec![caller("a", caller_insns(1, 0))],
        },
    ];
    let bytes = build(&Fixture {
        strings: STRINGS,
        types: TYPES,
        protos: PROTOTYPES,
        methods: METHODS,
        classes,
    });
    let view = DexView::parse(&bytes).unwrap();
    assert!(
        find_xor_decoders(&view).is_empty(),
        "field access disqualifies the decoder"
    );
}

/// The `new String(p, 0, p.length)` constructor variant: recognized and
/// decoded exactly like `new String(p)`.
#[test]
fn decoder_with_offset_length_constructor_is_recognized() {
    let bytes = dex_with(decoder_insns_ii(105), &[caller("a", caller_insns(1, 0))]);
    let view = DexView::parse(&bytes).unwrap();
    let decoders = find_xor_decoders(&view);
    assert_eq!(decoders.len(), 1, "([BII)V decoder recognized");
    assert_eq!(decoders[0].key, 105);
    let resolver = XorResolver::new(&view, &decoders);
    let code = code_of_first_method(&bytes, "LCalls;");
    let calls = resolver.calls(&view, &code);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].value, vec![0x68, 0x69]);
}

/// javac register reuse: the invoke result lands in the very register
/// that held the array. That is a pure definition — the array binding
/// dies with it — so the call stays patchable.
#[test]
fn result_reusing_array_register_stays_patchable() {
    let insns = concat(&[
        &const4(4, 2),
        &new_array(0, 4, 3),
        &const4(1, 1),
        &const4(2, 0),
        &aput_byte(1, 0, 2),
        &const4(1, 0),
        &const4(2, 1),
        &aput_byte(1, 0, 2),
        &invoke_static_1(0, 0),
        &move_result_object(0), // overwrites the array register v0
        &return_object(0),
    ]);
    let bytes = dex_with_callers(&[caller("a", insns)]);
    let view = DexView::parse(&bytes).unwrap();
    let decoders = find_xor_decoders(&view);
    let resolver = XorResolver::new(&view, &decoders);
    let code = code_of_first_method(&bytes, "LCalls;");
    let calls = resolver.calls(&view, &code);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].value, vec![0x68, 0x69]);
    assert_eq!(calls[0].result, Some(0));
    assert!(calls[0].patchable, "pure def of the array register");
}

/// `fill-array-data` callers: the array comes from the static payload
/// blob, not const+aput chains.
#[test]
fn fill_array_data_caller_decodes() {
    // payload: ident 0x0300, width u16 =1, size u32 =2, data {1, 0}
    let payload: Vec<u16> = vec![0x0300, 0x0001, 0x0002, 0x0000, 0x0001];
    let fill_off = 3usize; // fill-array-data sits at code-unit offset 3
    let payload_off = 11usize; // after return-object
    let insns = concat(&[
        &const4(4, 2),
        &new_array(0, 4, 3),
        &vec![0x26, ((payload_off - fill_off) as u16), 0u16],
        &invoke_static_1(0, 0),
        &move_result_object(3),
        &return_object(3),
    ]);
    let mut insns = insns;
    insns.extend(payload);
    let bytes = dex_with_callers(&[caller("a", insns)]);
    let view = DexView::parse(&bytes).unwrap();
    let decoders = find_xor_decoders(&view);
    assert_eq!(decoders.len(), 1);
    let resolver = XorResolver::new(&view, &decoders);
    let code = code_of_first_method(&bytes, "LCalls;");
    let calls = resolver.calls(&view, &code);
    assert_eq!(calls.len(), 1, "fill-array-data site decodes");
    assert_eq!(calls[0].value, vec![0x68, 0x69]);
    assert!(calls[0].patchable);
}
