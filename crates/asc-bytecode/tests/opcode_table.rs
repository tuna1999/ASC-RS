//! Opcode-table unit tests — exhaustiveness, format/width/sample
//! coverage, and reference-bearing slot positioning.

use asc_bytecode::{Format, OPCODE_TABLE, OpcodeInfo, RefKind, RefSlot, opcode_info};

#[test]
fn table_is_exhaustive_and_wide() {
    // Every opcode 0x00..=0xFF has a populated entry with positive width.
    // This is the "exhaustiveness" gate called out in the assignment —
    // unassigned opcodes map to `is_unknown: true` with width 1 so the
    // walker fails fast instead of silently skipping a byte.
    for op in 0..=u8::MAX {
        let info = opcode_info(op);
        assert!(
            info.width_units > 0,
            "opcode 0x{op:02x} has zero width_units — table entry missing or corrupted"
        );
        assert_eq!(
            OPCODE_TABLE[op as usize], info,
            "OPCODE_TABLE disagrees with opcode_info at 0x{op:02x}"
        );
    }
    assert_eq!(OPCODE_TABLE.len(), 256);
}

/// `read_index` indexes `insns` without bounds reasoning: every slot must
/// lie fully inside its instruction's declared width.
#[test]
fn every_ref_slot_fits_inside_instruction_width() {
    for (op, info) in OPCODE_TABLE.iter().enumerate() {
        for (slot, _) in info.primary.iter().chain(info.secondary.iter()) {
            assert!(
                matches!(slot.bits, 16 | 32),
                "opcode 0x{op:02x}: bits {}",
                slot.bits
            );
            let units = slot.unit_off as u32 + slot.bits as u32 / 16;
            assert!(
                units <= info.width_units as u32,
                "opcode 0x{op:02x}: slot ends at unit {units} > width {}",
                info.width_units
            );
        }
    }
}

#[test]
fn unknown_opcodes_are_marked_unknown() {
    // Reserved / unassigned opcode bytes from the AOSP table:
    //   0x3e..=0x43, 0x73, 0x79..=0x7a, 0xe3..=0xec, 0xef, 0xf1
    let unknown = [
        0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x73, 0x79, 0x7a, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8,
        0xe9, 0xea, 0xeb, 0xec, 0xef, 0xf1,
    ];
    for &op in &unknown {
        let info = opcode_info(op);
        assert!(
            info.is_unknown,
            "opcode 0x{op:02x} should be marked is_unknown=true"
        );
        assert_eq!(
            info.format,
            Format::Unknown,
            "opcode 0x{op:02x} should have Format::Unknown"
        );
        assert!(
            info.primary.is_none() && info.secondary.is_none(),
            "opcode 0x{op:02x} should have no reference slots"
        );
    }
}

#[test]
fn nop_is_well_known() {
    // 0x00 nop — the most-traversed opcode byte. Width 1, no ref.
    let info = opcode_info(0x00);
    assert_eq!(info.width_units, 1);
    assert_eq!(info.format, Format::Format10x);
    assert!(!info.is_unknown);
    assert!(info.primary.is_none());
    assert!(info.secondary.is_none());
}

#[test]
fn const_string_uses_16_bit_slot() {
    // 0x1a const-string (21c): ref at code-unit 1, 16-bit string index.
    let info = opcode_info(0x1a);
    assert_eq!(info.width_units, 2);
    assert_eq!(info.format, Format::Format21c);
    assert_eq!(info.primary, Some((RefSlot::U16_AT_1, RefKind::String)));
    assert_eq!(info.secondary, None);
}

#[test]
fn const_string_jumbo_uses_32_bit_slot() {
    // 0x1b const-string/jumbo (31c): ref at code-unit 1 spanning 32 bits.
    let info = opcode_info(0x1b);
    assert_eq!(info.width_units, 3);
    assert_eq!(info.format, Format::Format31c);
    assert_eq!(info.primary, Some((RefSlot::U32_AT_1, RefKind::String)));
}

#[test]
fn invoke_polymorphic_has_secondary_proto() {
    // 0xfa invoke-polymorphic (45cc): method @ unit 1, proto @ unit 3.
    let info = opcode_info(0xfa);
    assert_eq!(info.width_units, 4);
    assert_eq!(info.format, Format::Format45cc);
    assert_eq!(info.primary, Some((RefSlot::U16_AT_1, RefKind::Method)));
    assert_eq!(info.secondary, Some((RefSlot::U16_AT_3, RefKind::Proto)));
}

#[test]
fn invoke_polymorphic_range_has_secondary_proto() {
    let info = opcode_info(0xfb);
    assert_eq!(info.width_units, 4);
    assert_eq!(info.format, Format::Format4rcc);
    assert_eq!(info.primary, Some((RefSlot::U16_AT_1, RefKind::Method)));
    assert_eq!(info.secondary, Some((RefSlot::U16_AT_3, RefKind::Proto)));
}

#[test]
fn invoke_custom_uses_callsite() {
    let info = opcode_info(0xfc);
    assert_eq!(info.width_units, 3);
    assert_eq!(info.format, Format::Format35c);
    assert_eq!(info.primary, Some((RefSlot::U16_AT_1, RefKind::CallSite)));
    assert_eq!(info.secondary, None);

    let info = opcode_info(0xfd);
    assert_eq!(info.width_units, 3);
    assert_eq!(info.format, Format::Format3rc);
    assert_eq!(info.primary, Some((RefSlot::U16_AT_1, RefKind::CallSite)));
}

#[test]
fn const_method_handle_and_type() {
    let info = opcode_info(0xfe);
    assert_eq!(info.width_units, 2);
    assert_eq!(info.format, Format::Format21c);
    assert_eq!(
        info.primary,
        Some((RefSlot::U16_AT_1, RefKind::MethodHandle))
    );

    let info = opcode_info(0xff);
    assert_eq!(info.width_units, 2);
    assert_eq!(info.format, Format::Format21c);
    assert_eq!(info.primary, Some((RefSlot::U16_AT_1, RefKind::Proto)));
}

#[test]
fn all_iget_iput_are_22c_field() {
    // 0x52..=0x5f: iget/iput family, all 22c field references.
    for op in 0x52u8..=0x5f {
        let info = opcode_info(op);
        assert_eq!(
            info,
            OpcodeInfo {
                width_units: 2,
                format: Format::Format22c,
                primary: Some((RefSlot::U16_AT_1, RefKind::Field)),
                secondary: None,
                is_unknown: false,
            },
            "opcode 0x{op:02x} should be 22c field"
        );
    }
}

#[test]
fn all_sget_sput_are_21c_field() {
    // 0x60..=0x6d: sget/sput family, all 21c field references.
    for op in 0x60u8..=0x6d {
        let info = opcode_info(op);
        assert_eq!(
            info,
            OpcodeInfo {
                width_units: 2,
                format: Format::Format21c,
                primary: Some((RefSlot::U16_AT_1, RefKind::Field)),
                secondary: None,
                is_unknown: false,
            },
            "opcode 0x{op:02x} should be 21c field"
        );
    }
}

#[test]
fn invoke_families_have_correct_method_layout() {
    // 0x6e..=0x72: invoke-virtual / super / direct / static / interface
    // (35c, method).
    for op in 0x6eu8..=0x72 {
        let info = opcode_info(op);
        assert_eq!(
            info,
            OpcodeInfo {
                width_units: 3,
                format: Format::Format35c,
                primary: Some((RefSlot::U16_AT_1, RefKind::Method)),
                secondary: None,
                is_unknown: false,
            },
            "opcode 0x{op:02x} should be 35c method"
        );
    }
    // 0x74..=0x78: invoke-*/range (3rc, method).
    for op in 0x74u8..=0x78 {
        let info = opcode_info(op);
        assert_eq!(
            info,
            OpcodeInfo {
                width_units: 3,
                format: Format::Format3rc,
                primary: Some((RefSlot::U16_AT_1, RefKind::Method)),
                secondary: None,
                is_unknown: false,
            },
            "opcode 0x{op:02x} should be 3rc method"
        );
    }
}

#[test]
fn branch_opcodes_match_format_width() {
    // 10t (1 unit), 20t (2 units), 30t (3 units).
    assert_eq!(opcode_info(0x28).width_units, 1);
    assert_eq!(opcode_info(0x29).width_units, 2);
    assert_eq!(opcode_info(0x2a).width_units, 3);

    assert_eq!(opcode_info(0x28).format, Format::Format10t);
    assert_eq!(opcode_info(0x29).format, Format::Format20t);
    assert_eq!(opcode_info(0x2a).format, Format::Format30t);
}

#[test]
fn const_wide_is_51l() {
    // 0x18 const-wide (51l, 5 units).
    let info = opcode_info(0x18);
    assert_eq!(info.width_units, 5);
    assert_eq!(info.format, Format::Format51l);
}

#[test]
fn slot_positions_within_width() {
    // Invariant: every populated slot's unit_off is strictly less than
    // the instruction's width. (Verified at build-table time; double-checked
    // here for the ref-bearing subset.)
    for op in 0..=u8::MAX {
        let info = opcode_info(op);
        for slot in info.primary.into_iter().chain(info.secondary) {
            assert!(
                (slot.0.unit_off as u16) < info.width_units,
                "opcode 0x{op:02x}: slot unit_off={} >= width={}",
                slot.0.unit_off,
                info.width_units
            );
            assert!(
                slot.0.bits == 16 || slot.0.bits == 32,
                "opcode 0x{op:02x}: slot bits must be 16 or 32, got {}",
                slot.0.bits
            );
        }
    }
}

#[test]
fn ref_bearing_opcodes_are_exhaustive() {
    // Cross-check: every opcode listed in the assignment's
    // "Reference-bearing opcodes" section must expose the documented
    // slot. Catch a future regression where one of these is dropped
    // from the table.
    type Slot = (RefKind, u8);
    let expected: &[(u8, Option<Slot>, Option<Slot>)] = &[
        // string
        (0x1a, Some((RefKind::String, 16)), None),
        (0x1b, Some((RefKind::String, 32)), None),
        // type
        (0x1c, Some((RefKind::Type, 16)), None),
        (0x1f, Some((RefKind::Type, 16)), None),
        (0x22, Some((RefKind::Type, 16)), None),
        (0x20, Some((RefKind::Type, 16)), None),
        (0x23, Some((RefKind::Type, 16)), None),
        (0x24, Some((RefKind::Type, 16)), None),
        (0x25, Some((RefKind::Type, 16)), None),
        // field (22c)
        (0x52, Some((RefKind::Field, 16)), None),
        (0x5f, Some((RefKind::Field, 16)), None),
        // field (21c)
        (0x60, Some((RefKind::Field, 16)), None),
        (0x6d, Some((RefKind::Field, 16)), None),
        // method (35c)
        (0x6e, Some((RefKind::Method, 16)), None),
        (0x72, Some((RefKind::Method, 16)), None),
        // method (3rc)
        (0x74, Some((RefKind::Method, 16)), None),
        (0x78, Some((RefKind::Method, 16)), None),
        // method (45cc / 4rcc) with proto secondary
        (
            0xfa,
            Some((RefKind::Method, 16)),
            Some((RefKind::Proto, 16)),
        ),
        (
            0xfb,
            Some((RefKind::Method, 16)),
            Some((RefKind::Proto, 16)),
        ),
        // call site (35c / 3rc)
        (0xfc, Some((RefKind::CallSite, 16)), None),
        (0xfd, Some((RefKind::CallSite, 16)), None),
        // method handle
        (0xfe, Some((RefKind::MethodHandle, 16)), None),
        // proto (const-method-type)
        (0xff, Some((RefKind::Proto, 16)), None),
    ];

    for &(op, primary, secondary) in expected {
        let info = opcode_info(op);
        let actual_primary = info.primary.map(|(slot, kind)| (kind, slot.bits));
        let actual_secondary = info.secondary.map(|(slot, kind)| (kind, slot.bits));
        assert_eq!(
            actual_primary, primary,
            "opcode 0x{op:02x} primary slot mismatch"
        );
        assert_eq!(
            actual_secondary, secondary,
            "opcode 0x{op:02x} secondary slot mismatch"
        );
    }
}
