//! Reference-walker unit tests — per-format decode, payload handling,
//! malformed-input reporting, and a realistic end-to-end method body.

use asc_bytecode::{
    walk_verify, BytecodeError, CallSiteIdx, DexRef, FieldIdx, MethodHandleIdx, MethodIdx,
    ProtoIdx, RefInstruction, RefWalker, StringIdx, TypeIdx,
};

// --- helpers -----------------------------------------------------------

/// Pack a sequence of 16-bit code units into a little-endian byte buffer.
fn le_units(units: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(units.len() * 2);
    for u in units {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// Collect every `Ok` hit from a walker into a `Vec`.
fn hits(bytes: &[u8], units: u32) -> Vec<RefInstruction> {
    let walker = RefWalker::new(bytes, units).expect("walker construction");
    walker.filter_map(|r| r.ok()).collect()
}

/// Drain a walker and return the final `units_consumed` plus the count
/// of `Ok` hits. After draining, the cursor equals the total unit count
/// for a clean walk — easier to assert than re-constructing the walker.
fn drain(bytes: &[u8], units: u32) -> (u32, usize) {
    let mut walker = RefWalker::new(bytes, units).expect("walker construction");
    let mut ok = 0usize;
    for item in walker.by_ref() {
        if item.is_ok() {
            ok += 1;
        }
    }
    (walker.units_consumed(), ok)
}

// --- construction ------------------------------------------------------

#[test]
fn new_rejects_length_mismatch() {
    let bytes = [0u8; 3]; // 3 bytes
    let result = RefWalker::new(&bytes, 2); // expects 4 bytes
    assert!(matches!(result, Err(BytecodeError::LengthMismatch { .. })));
}

#[test]
fn new_accepts_exact_match() {
    let bytes = [0u8; 4];
    let walker = RefWalker::new(&bytes, 2).unwrap();
    assert_eq!(walker.units_consumed(), 0);
    assert_eq!(walker.insns_units(), 2);
}

#[test]
fn new_rejects_units_overflow_when_doubled() {
    // insns_units is u32; the maximum doubled value is 0x1_FFFFFFFE,
    // which fits in u64. The walker should report a LengthMismatch
    // for any non-zero units count against a zero-byte buffer.
    let bytes: Vec<u8> = Vec::new();
    let result = RefWalker::new(&bytes, u32::MAX);
    match result {
        Err(BytecodeError::LengthMismatch {
            units,
            bytes: b,
            expected,
            ..
        }) => {
            assert_eq!(units, u32::MAX);
            assert_eq!(b, 0);
            assert_eq!(expected, (u32::MAX as u64) * 2);
        }
        _ => panic!("expected LengthMismatch, got Ok or wrong error variant"),
    }
}

// --- 21c (const-string, const-class, sget-object, const-method-*) ------

#[test]
fn walker_const_string_zero_idx() {
    // const-string v0, string@0x0000  (21c)
    let units = [0x001a, 0x0000];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].offset, 0);
    assert_eq!(h[0].primary, Some(DexRef::String(StringIdx(0))));
    assert_eq!(h[0].secondary, None);
}

#[test]
fn walker_const_string_max_idx() {
    // const-string v0, string@0xFFFF  (21c)
    let units = [0x001a, 0xFFFF];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h[0].primary, Some(DexRef::String(StringIdx(0xFFFF))));
}

#[test]
fn walker_const_class_and_sget() {
    // const-class v0, type@0x42
    // sget-object v1, field@0x99
    let units = [0x001c, 0x0042, 0x0062, 0x0099];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h.len(), 2);
    assert_eq!(h[0].offset, 0);
    assert_eq!(h[0].primary, Some(DexRef::Type(TypeIdx(0x42))));
    assert_eq!(h[1].offset, 2);
    assert_eq!(h[1].primary, Some(DexRef::Field(FieldIdx(0x99))));
}

#[test]
fn walker_const_method_handle_and_type() {
    // const-method-handle v0, method_handle@0xAA
    // const-method-type v1, proto@0xBB
    let units = [0x00fe, 0x00aa, 0x00ff, 0x00bb];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h.len(), 2);
    assert_eq!(h[0].primary, Some(DexRef::MethodHandle(MethodHandleIdx(0xaa))));
    assert_eq!(h[1].primary, Some(DexRef::Proto(ProtoIdx(0xbb))));
}

// --- 22c (iget/iput, instance-of, new-array) ---------------------------

#[test]
fn walker_iget_extracts_field() {
    // iget-object v4, v5, field@0x40  (22c)
    let units = [0x0054, 0x0040];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].primary, Some(DexRef::Field(FieldIdx(0x40))));
}

#[test]
fn walker_instance_of_and_new_array() {
    // instance-of v0, v1, type@0x10  (22c)
    // new-array v2, v3, type@0x11    (22c)
    let units = [0x0020, 0x0010, 0x0023, 0x0011];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h.len(), 2);
    assert_eq!(h[0].primary, Some(DexRef::Type(TypeIdx(0x10))));
    assert_eq!(h[1].primary, Some(DexRef::Type(TypeIdx(0x11))));
}

// --- 31c (const-string/jumbo) -----------------------------------------

#[test]
fn walker_const_string_jumbo_basic() {
    // const-string/jumbo v0, string@0x00000010  (31c, 3 units)
    let units = [0x001b, 0x0010, 0x0000];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].primary, Some(DexRef::String(StringIdx(0x10))));
}

#[test]
fn walker_const_string_jumbo_max_idx() {
    // const-string/jumbo v0, string@0xFFFFFFFF  (31c)
    let units = [0x001b, 0xFFFF, 0xFFFF];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h[0].primary, Some(DexRef::String(StringIdx(0xFFFF_FFFF))));
}

#[test]
fn walker_const_string_jumbo_crosses_word_boundary() {
    // 0xCAFEBABE: lo=0xBABE, hi=0xCAFE.
    let units = [0x001b, 0xBABE, 0xCAFE];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h[0].primary, Some(DexRef::String(StringIdx(0xCAFE_BABE))));
}

// --- 35c (invoke-*, filled-new-array) ---------------------------------

#[test]
fn walker_invoke_virtual_extracts_method() {
    // invoke-virtual {v3, v0}, meth@0x50
    //   code unit 0 = A|G|op  = 0x026e (A=2, G=0, op=0x6e)
    //   code unit 1 = BBBB    = 0x0050
    //   code unit 2 = F|E|D|C = 0x0030 (C=0, D=3)
    let units = [0x026e, 0x0050, 0x0030];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].primary, Some(DexRef::Method(MethodIdx(0x50))));
}

#[test]
fn walker_invoke_virtual_range() {
    // invoke-virtual/range {v0..v2}, meth@0x99
    //   3rc: code unit 0 = AA|op (AA=3 count, op=0x74)
    //         code unit 1 = BBBB method
    //         code unit 2 = CCCC first reg
    let units = [0x0374, 0x0099, 0x0000];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].primary, Some(DexRef::Method(MethodIdx(0x99))));
}

#[test]
fn walker_filled_new_array() {
    // filled-new-array {v0, v1}, type@0x70  (35c)
    let units = [0x0224, 0x0070, 0x0010];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].primary, Some(DexRef::Type(TypeIdx(0x70))));
}

#[test]
fn walker_filled_new_array_range() {
    // filled-new-array/range {v0..v1}, type@0x71  (3rc)
    let units = [0x0225, 0x0071, 0x0000];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].primary, Some(DexRef::Type(TypeIdx(0x71))));
}

#[test]
fn walker_invoke_custom_extracts_callsite() {
    // invoke-custom {v0}, call_site@0x90  (35c)
    let units = [0x01fc, 0x0090, 0x0000];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].primary, Some(DexRef::CallSite(CallSiteIdx(0x90))));
}

// --- 45cc / 4rcc (invoke-polymorphic) ---------------------------------

#[test]
fn walker_invoke_polymorphic_extracts_both_refs() {
    // invoke-polymorphic {v0, v1}, meth@0x80, proto@0x81
    //   45cc: unit 0 = A|G|op = 0x02fa
    //         unit 1 = BBBB method = 0x0080
    //         unit 2 = F|E|D|C = 0x0010 (C=0, D=1)
    //         unit 3 = HHHH proto = 0x0081
    let units = [0x02fa, 0x0080, 0x0010, 0x0081];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].primary, Some(DexRef::Method(MethodIdx(0x80))));
    assert_eq!(h[0].secondary, Some(DexRef::Proto(ProtoIdx(0x81))));
}

#[test]
fn walker_invoke_polymorphic_range_extracts_both_refs() {
    // invoke-polymorphic/range {v0..v1}, meth@0x80, proto@0x81  (4rcc)
    let units = [0x02fb, 0x0080, 0x0000, 0x0081];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].primary, Some(DexRef::Method(MethodIdx(0x80))));
    assert_eq!(h[0].secondary, Some(DexRef::Proto(ProtoIdx(0x81))));
}

#[test]
fn walker_polymorphic_with_zero_indices() {
    let units = [0x02fa, 0x0000, 0x0000, 0x0000];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h[0].primary, Some(DexRef::Method(MethodIdx(0))));
    assert_eq!(h[0].secondary, Some(DexRef::Proto(ProtoIdx(0))));
}

// --- non-ref instructions and stepping --------------------------------

#[test]
fn walker_nop_sled() {
    let units = [0x0000u16; 10];
    let bytes = le_units(&units);
    let (consumed, hits) = drain(&bytes, 10);
    assert_eq!(hits, 0);
    assert_eq!(consumed, 10);
}

#[test]
fn walker_branches_skipped_correctly() {
    // if-eq v0, v1, +1  (22t, 2 units)
    // goto +0            (10t, 1 unit)
    // if-nez v0, -1      (21t, 2 units)
    // const-string v0, string@0x99 (21c, 2 units)
    // return-void        (10x, 1 unit)
    let units = [
        0x0032, 0x0001, // if-eq v0, v1, +1
        0x0028,         // goto +0
        0x0039, 0xFFFF, // if-nez v0, -1
        0x001a, 0x0099, // const-string v0, string@0x99
        0x000e,         // return-void
    ];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].offset, 5);
    assert_eq!(h[0].primary, Some(DexRef::String(StringIdx(0x99))));
}

// --- payload pseudo-instructions --------------------------------------

#[test]
fn walker_steps_over_packed_switch_payload() {
    // packed-switch-payload, size=2:
    //   ident=0x0100, size=2, first_key=10, target[0]=+1, target[1]=+2
    // Total = 4 + 2*2 = 8 units = 16 bytes.
    let units = [
        0x0100, 0x0002, // ident + size
        0x000a, 0x0000, // first_key = 10
        0x0001, 0x0000, // target[0] = +1
        0x0002, 0x0000, // target[1] = +2
    ];
    let bytes = le_units(&units);
    let (consumed, hits) = drain(&bytes, units.len() as u32);
    assert_eq!(hits, 0);
    assert_eq!(consumed, 8);
}

#[test]
fn walker_steps_over_sparse_switch_payload() {
    // sparse-switch-payload, size=1:
    //   ident=0x0200, size=1, key[0]=42, target[0]=+3
    // Total = 2 + 4*1 = 6 units.
    let units = [
        0x0200, 0x0001, // ident + size
        0x002a, 0x0000, // key[0] = 42
        0x0003, 0x0000, // target[0] = +3
    ];
    let bytes = le_units(&units);
    let (consumed, hits) = drain(&bytes, 6);
    assert_eq!(hits, 0);
    assert_eq!(consumed, 6);
}

#[test]
fn walker_steps_over_fill_array_data_odd_size() {
    // fill-array-data-payload:
    //   ident=0x0300, element_width=1 (byte), size=3, data=[1, 2, 3]
    // Total = 4 + ceil(3*1/2) = 4 + 2 = 6 units.
    let units = [
        0x0300, 0x0001, // ident + element_width
        0x0003, 0x0000, // size = 3
        0x0201,         // data[0]=0x01, data[1]=0x02
        0x0003,         // data[2]=0x03, pad=0x00
    ];
    let bytes = le_units(&units);
    let (consumed, hits) = drain(&bytes, 6);
    assert_eq!(hits, 0);
    assert_eq!(consumed, 6);
}

#[test]
fn walker_steps_over_fill_array_data_with_wide_element() {
    // element_width = 8 (long), size = 2 -> 16 bytes data
    // Total = 4 + ceil(2*8/2) = 4 + 8 = 12 units.
    let units = [
        0x0300, 0x0008, // ident + element_width=8
        0x0002, 0x0000, // size = 2
        // 16 bytes of data = 8 units
        0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000,
    ];
    let bytes = le_units(&units);
    let (consumed, hits) = drain(&bytes, units.len() as u32);
    assert_eq!(hits, 0);
    assert_eq!(consumed, 12);
}

#[test]
fn walker_payload_mid_stream() {
    // nop | sparse-switch-payload (size=1) | return-void
    let units = [
        0x0000, // nop
        0x0200, 0x0001, // sparse-switch ident + size
        0x002a, 0x0000, // key[0]
        0x003c, 0x0000, // target[0]
        0x000e, // return-void
    ];
    let bytes = le_units(&units);
    let (consumed, hits) = drain(&bytes, units.len() as u32);
    assert_eq!(hits, 0);
    assert_eq!(consumed, 8);
}

#[test]
fn walker_starts_on_payload() {
    // Cursor lands on a payload at offset 0.
    let units = [0x0200, 0x0000]; // sparse-switch, size=0 (just ident+size)
    let bytes = le_units(&units);
    let (consumed, hits) = drain(&bytes, 2);
    assert_eq!(hits, 0);
    assert_eq!(consumed, 2);
}

#[test]
fn walker_packed_switch_payload_size_oob() {
    // size = 100 but only 4 units available.
    let units = [0x0100, 0x0064, 0x0000, 0x0000];
    let bytes = le_units(&units);
    let mut walker = RefWalker::new(&bytes, 4).unwrap();
    let err = walker.next().unwrap().unwrap_err();
    assert!(matches!(err, BytecodeError::MalformedPayload { offset: 0 }));
}

#[test]
fn walker_fill_array_data_size_oob() {
    // size = 0xFFFFFFFF but only 4 units remain.
    let units = [0x0300, 0x0001, 0xFFFF, 0xFFFF];
    let bytes = le_units(&units);
    let mut walker = RefWalker::new(&bytes, units.len() as u32).unwrap();
    let err = walker.next().unwrap().unwrap_err();
    assert!(matches!(err, BytecodeError::MalformedPayload { offset: 0 }));
}

#[test]
fn walker_sparse_switch_payload_size_oob() {
    let units = [0x0200, 0x03e8, 0, 0, 0, 0, 0, 0, 0, 0];
    let bytes = le_units(&units);
    let mut walker = RefWalker::new(&bytes, units.len() as u32).unwrap();
    let err = walker.next().unwrap().unwrap_err();
    assert!(matches!(err, BytecodeError::MalformedPayload { offset: 0 }));
}

// --- error reporting ---------------------------------------------------

#[test]
fn walker_truncated_last_instruction() {
    // goto/16 (20t, 2 units) but only 1 unit in the buffer.
    let units = [0x0029];
    let bytes = le_units(&units);
    let mut walker = RefWalker::new(&bytes, 1).unwrap();
    let err = walker.next().unwrap().unwrap_err();
    assert!(matches!(
        err,
        BytecodeError::TruncatedInstruction {
            offset: 0,
            needed: 2,
            available: 1,
        }
    ));
}

#[test]
fn walker_truncated_at_jumbo_string() {
    // const-string/jumbo (31c, 3 units) but only 2 units in buffer.
    let units = [0x001b, 0xCAFE];
    let bytes = le_units(&units);
    let mut walker = RefWalker::new(&bytes, 2).unwrap();
    let err = walker.next().unwrap().unwrap_err();
    assert!(matches!(
        err,
        BytecodeError::TruncatedInstruction {
            offset: 0,
            needed: 3,
            available: 2,
        }
    ));
}

#[test]
fn walker_unknown_opcode() {
    // 0x73 is unassigned; walker should fail with the offset.
    let units = [0x0073, 0x0000];
    let bytes = le_units(&units);
    let mut walker = RefWalker::new(&bytes, 2).unwrap();
    let err = walker.next().unwrap().unwrap_err();
    assert!(matches!(
        err,
        BytecodeError::UnknownOpcode {
            offset: 0,
            opcode: 0x73,
        }
    ));
}

#[test]
fn walker_unknown_opcode_mid_stream() {
    // const-string v0, string@0x10 | 0x73 (unknown) | return-void
    let units = [0x001a, 0x0010, 0x0073, 0x0000, 0x000e];
    let bytes = le_units(&units);
    let mut walker = RefWalker::new(&bytes, units.len() as u32).unwrap();
    // First hit: const-string.
    let first = walker.next().unwrap().unwrap();
    assert_eq!(first.offset, 0);
    assert_eq!(first.primary, Some(DexRef::String(StringIdx(0x10))));
    // Second: unknown opcode at offset 2.
    let err = walker.next().unwrap().unwrap_err();
    assert!(matches!(
        err,
        BytecodeError::UnknownOpcode {
            offset: 2,
            opcode: 0x73,
        }
    ));
    // Iterator ends.
    assert!(walker.next().is_none());
}

// --- walk_verify -------------------------------------------------------

#[test]
fn walk_verify_clean_body() {
    let units = [0x001a, 0x0010, 0x000e]; // const-string; return-void
    let bytes = le_units(&units);
    assert!(walk_verify(&bytes, units.len() as u32).is_ok());
}

#[test]
fn walk_verify_fails_on_unknown() {
    let bytes = le_units(&[0x0073, 0x0000]);
    assert!(walk_verify(&bytes, 2).is_err());
}

// --- combined realistic method sequence --------------------------------

#[test]
fn walker_realistic_method_sequence() {
    // Hand-encoded method body exercising every ref format:
    //   0:  const-string        v0, string@0x10            (21c, 2)
    //   2:  const-string/jumbo  v1, string@0xCAFEBABE      (31c, 3)
    //   5:  const-class         v2, type@0x20              (21c, 2)
    //   7:  sget-object         v3, field@0x30             (21c, 2)
    //   9:  iget-object         v4, v5, field@0x40         (22c, 2)
    //   11: invoke-virtual      {v3, v0}, meth@0x50        (35c, 3)
    //   14: invoke-direct       {v2},     meth@0x60        (35c, 3)
    //   17: filled-new-array    {v0, v1}, type@0x70        (35c, 3)
    //   20: invoke-polymorphic  {v0, v1}, meth@0x80, proto@0x81  (45cc, 4)
    //   24: invoke-custom       {v0},     call_site@0x90   (35c, 3)
    //   27: const-method-handle v6, method_handle@0xA0     (21c, 2)
    //   29: const-method-type   v7, proto@0xB0             (21c, 2)
    //   31: return-void                                   (10x, 1)
    // Total: 32 code units.

    let units = [
        0x001a, 0x0010,               // offset 0
        0x001b, 0xBABE, 0xCAFE,       // offset 2
        0x001c, 0x0020,               // offset 5
        0x0062, 0x0030,               // offset 7
        0x0054, 0x0040,               // offset 9
        0x026e, 0x0050, 0x0030,       // offset 11 (C=0, D=3)
        0x0170, 0x0060, 0x0020,       // offset 14 (C=2)
        0x0224, 0x0070, 0x0010,       // offset 17 (C=0, D=1)
        0x02fa, 0x0080, 0x0010, 0x0081, // offset 20
        0x01fc, 0x0090, 0x0000,       // offset 24 (C=0)
        0x00fe, 0x00A0,               // offset 27
        0x00ff, 0x00B0,               // offset 29
        0x000e,                       // offset 31
    ];
    assert_eq!(units.len(), 32);

    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h.len(), 12);

    assert_eq!(h[0].offset, 0);
    assert_eq!(h[0].primary, Some(DexRef::String(StringIdx(0x10))));

    assert_eq!(h[1].offset, 2);
    assert_eq!(h[1].primary, Some(DexRef::String(StringIdx(0xCAFE_BABE))));

    assert_eq!(h[2].offset, 5);
    assert_eq!(h[2].primary, Some(DexRef::Type(TypeIdx(0x20))));

    assert_eq!(h[3].offset, 7);
    assert_eq!(h[3].primary, Some(DexRef::Field(FieldIdx(0x30))));

    assert_eq!(h[4].offset, 9);
    assert_eq!(h[4].primary, Some(DexRef::Field(FieldIdx(0x40))));

    assert_eq!(h[5].offset, 11);
    assert_eq!(h[5].primary, Some(DexRef::Method(MethodIdx(0x50))));

    assert_eq!(h[6].offset, 14);
    assert_eq!(h[6].primary, Some(DexRef::Method(MethodIdx(0x60))));

    assert_eq!(h[7].offset, 17);
    assert_eq!(h[7].primary, Some(DexRef::Type(TypeIdx(0x70))));

    assert_eq!(h[8].offset, 20);
    assert_eq!(h[8].primary, Some(DexRef::Method(MethodIdx(0x80))));
    assert_eq!(h[8].secondary, Some(DexRef::Proto(ProtoIdx(0x81))));

    assert_eq!(h[9].offset, 24);
    assert_eq!(h[9].primary, Some(DexRef::CallSite(CallSiteIdx(0x90))));

    assert_eq!(h[10].offset, 27);
    assert_eq!(
        h[10].primary,
        Some(DexRef::MethodHandle(MethodHandleIdx(0xA0)))
    );

    assert_eq!(h[11].offset, 29);
    assert_eq!(h[11].primary, Some(DexRef::Proto(ProtoIdx(0xB0))));
}

#[test]
fn walker_realistic_method_sequence_with_payload_between_refs() {
    // const-string v0, string@0x10  | packed-switch-payload (size=2)
    // | const-class v1, type@0x42   | return-void
    //
    // packed-switch-payload: 4 + 2*2 = 8 units.
    // Total: 2 + 8 + 2 + 1 = 13 units.
    let units = [
        0x001a, 0x0010, // const-string
        0x0100, 0x0002, // packed-switch ident + size
        0x000a, 0x0000, // first_key = 10
        0x0001, 0x0000, // target[0] = +1
        0x0002, 0x0000, // target[1] = +2
        0x001c, 0x0042, // const-class v1, type@0x42
        0x000e,         // return-void
    ];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h.len(), 2);
    assert_eq!(h[0].offset, 0);
    assert_eq!(h[0].primary, Some(DexRef::String(StringIdx(0x10))));
    assert_eq!(h[1].offset, 10);
    assert_eq!(h[1].primary, Some(DexRef::Type(TypeIdx(0x42))));
}

// --- zero / max boundary indices --------------------------------------

#[test]
fn walker_zero_and_max_indices() {
    // 21c string@0x0000
    // 31c string@0xFFFFFFFF
    // 35c meth@0xFFFF
    let units = [
        0x001a, 0x0000,           // string@0
        0x001b, 0xFFFF, 0xFFFF,   // string@0xFFFFFFFF
        0x026e, 0xFFFF, 0x0010,   // invoke-virtual {v0, v1}, meth@0xFFFF
    ];
    let bytes = le_units(&units);
    let h = hits(&bytes, units.len() as u32);
    assert_eq!(h[0].primary, Some(DexRef::String(StringIdx(0))));
    assert_eq!(h[1].primary, Some(DexRef::String(StringIdx(0xFFFF_FFFF))));
    assert_eq!(h[2].primary, Some(DexRef::Method(MethodIdx(0xFFFF))));
}

// --- allocation-free design proof --------------------------------------

#[test]
fn walker_struct_is_bounded() {
    // RefWalker holds a slice (16 bytes on 64-bit) plus three u32s and a
    // bool. No Vec, no String, no Box — the struct's compile-time size
    // is the strongest type-level proof we can give of the non-alloc
    // invariant.
    let walker_size = std::mem::size_of::<RefWalker>();
    let instr_size = std::mem::size_of::<RefInstruction>();
    let ref_size = std::mem::size_of::<DexRef>();
    assert!(
        walker_size <= 64,
        "RefWalker unexpectedly large: {walker_size} bytes"
    );
    assert!(
        instr_size <= 32,
        "RefInstruction unexpectedly large: {instr_size} bytes"
    );
    assert!(
        ref_size <= 16,
        "DexRef unexpectedly large: {ref_size} bytes"
    );
}

/// Regression (integration gate, workload.apk code_off=3972716): a
/// fill-array-data payload with element_width=1 whose ELEMENT count
/// (64) exceeds the remaining code UNITS (36) must still parse when its
/// byte extent (4 + 32 units) fits exactly. The old guard compared
/// elements against units and false-rejected the walk, killing all
/// later reference hits in the method.
#[test]
fn fill_array_data_element_count_may_exceed_remaining_units() {
    // 36 units total: payload ident (0x0300), element_width=1, size=64,
    // then 32 units of data (64 bytes).
    let mut units: Vec<u16> = vec![0x0300, 0x0001, 0x0040, 0x0000];
    units.extend(std::iter::repeat(0x2a2a).take(32));
    assert_eq!(units.len(), 36);
    let mut bytes = Vec::with_capacity(72);
    for u in &units {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    assert_eq!(
        asc_bytecode::walk_verify(&bytes, 36),
        Ok(()),
        "width-1 payload fitting exactly must verify"
    );

    // Truncation must still be an error: declare size=64 but only
    // provide 20 units of data.
    let mut trunc: Vec<u16> = vec![0x0300, 0x0001, 0x0040, 0x0000];
    trunc.extend(std::iter::repeat(0x0000).take(20));
    let mut tbytes = Vec::new();
    for u in &trunc {
        tbytes.extend_from_slice(&u.to_le_bytes());
    }
    assert!(
        asc_bytecode::walk_verify(&tbytes, trunc.len() as u32).is_err(),
        "payload extent exceeding the buffer must error"
    );
}
