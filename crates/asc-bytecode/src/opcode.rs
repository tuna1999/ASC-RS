//! Dalvik opcode metadata — formats, instruction widths, and reference
//! operand locations.
//!
//! The complete `0x00..=0xFF` opcode byte table lives in [`OPCODE_TABLE`];
//! look it up via [`opcode_info`]. Unassigned / reserved opcodes map to
//! `OpcodeInfo { is_unknown: true, width_units: 1, .. }` so the walker
//! fails fast on them rather than silently skipping a byte.
//!
//! Reference-bearing opcodes (the ones the asc-rebuild index-rewriting
//! pipeline cares about) attach a [`RefSlot`] + [`RefKind`] to either the
//! `primary` slot, the `secondary` slot, or both (`45cc` / `4rcc` carry a
//! method index plus a prototype index). Slot positions are measured in
//! 16-bit code units from the start of the instruction, matching the
//! encoding diagrams on <https://source.android.com/docs/core/runtime/instruction-formats>.

use crate::dex_ids::*;

/// Dalvik instruction format tag.
///
/// Names match the canonical AOSP / source.android.com tables
/// (`10x`, `12x`, `11n`, ...). Three extra values cover payload
/// pseudo-instructions (`PackedSwitchPayload`, `SparseSwitchPayload`,
/// `FillArrayDataPayload`) and two legacy / non-standard formats
/// (`Format20bc` for `throw-verification-error` `0xed`,
/// `Format35mi` for `execute-inline` `0xee`). `Unknown` marks table
/// entries that do not correspond to an assigned opcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    /// Reserved for unassigned / unrecognised opcode bytes.
    Unknown,

    // 1-code-unit formats.
    Format10x,
    Format12x,
    Format11n,
    Format11x,
    Format10t,

    // 2-code-unit formats.
    Format20t,
    Format22x,
    Format21t,
    Format21s,
    Format21h,
    Format21c,
    Format23x,
    Format22b,
    Format22t,
    Format22s,
    Format22c,

    // 3-code-unit formats.
    Format30t,
    Format31i,
    Format31t,
    Format31c,
    Format32x,
    Format35c,
    Format3rc,

    // 4-code-unit formats.
    Format45cc,
    Format4rcc,

    // 5-code-unit format.
    Format51l,

    // Non-standard / quickened / verification opcodes.
    Format20bc,
    Format35mi,

    // Payload pseudo-instructions (ident in first code unit, not real ops).
    PackedSwitchPayload,
    SparseSwitchPayload,
    FillArrayDataPayload,
}

/// Which DEX constant pool an operand references.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefKind {
    String,
    Type,
    Field,
    Method,
    Proto,
    CallSite,
    MethodHandle,
}

/// Position and width of a reference operand inside an instruction.
///
/// `unit_off` counts 16-bit code units from the start of the instruction;
/// `bits` is `16` or `32` and indicates whether the index is one or two
/// code units wide. 32-bit slots only appear on `31c` (jumbo string).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RefSlot {
    pub unit_off: u8,
    pub bits: u8,
}

impl RefSlot {
    /// 16-bit index at code-unit offset 1 — used by every
    /// `21c` / `22c` / `35c` / `3rc` primary pool reference and by the
    /// `45cc` / `4rcc` method primary reference.
    pub const U16_AT_1: Self = Self { unit_off: 1, bits: 16 };

    /// 32-bit index starting at code-unit offset 1 — `const-string/jumbo`
    /// (`31c`) only.
    pub const U32_AT_1: Self = Self { unit_off: 1, bits: 32 };

    /// 16-bit index at code-unit offset 3 — the prototype reference on
    /// `45cc` / `4rcc` (`invoke-polymorphic`, `invoke-polymorphic/range`).
    pub const U16_AT_3: Self = Self { unit_off: 3, bits: 16 };
}

/// Metadata for one opcode byte.
///
/// Built once into [`OPCODE_TABLE`]; queried via [`opcode_info`].
/// `width_units` is in 16-bit code units and is always `>= 1`. The
/// `is_unknown` flag distinguishes "reserved / unassigned opcode byte"
/// from "known opcode that happens not to carry a reference slot".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpcodeInfo {
    pub width_units: u16,
    pub format: Format,
    pub primary: Option<(RefSlot, RefKind)>,
    pub secondary: Option<(RefSlot, RefKind)>,
    pub is_unknown: bool,
}

// --- table construction --------------------------------------------------

const fn known(
    width: u16,
    format: Format,
    primary: Option<(RefSlot, RefKind)>,
    secondary: Option<(RefSlot, RefKind)>,
) -> OpcodeInfo {
    OpcodeInfo {
        width_units: width,
        format,
        primary,
        secondary,
        is_unknown: false,
    }
}

const fn unknown() -> OpcodeInfo {
    OpcodeInfo {
        width_units: 1,
        format: Format::Unknown,
        primary: None,
        secondary: None,
        is_unknown: true,
    }
}

/// Complete opcode table, indexed by the opcode byte (0x00..=0xFF).
///
/// Every entry is populated. Reserved / unassigned bytes are filled with
/// `unknown()` so the walker always knows the cursor must stop there.
pub const OPCODE_TABLE: [OpcodeInfo; 256] = build_table();

const fn build_table() -> [OpcodeInfo; 256] {
    let mut t = [unknown(); 256];

    // 0x00 nop
    t[0x00] = known(1, Format::Format10x, None, None);

    // 0x01-0x03 move / move-from16 / move-16
    t[0x01] = known(1, Format::Format12x, None, None);
    t[0x02] = known(2, Format::Format22x, None, None);
    t[0x03] = known(3, Format::Format32x, None, None);

    // 0x04-0x06 move-wide
    t[0x04] = known(1, Format::Format12x, None, None);
    t[0x05] = known(2, Format::Format22x, None, None);
    t[0x06] = known(3, Format::Format32x, None, None);

    // 0x07-0x09 move-object
    t[0x07] = known(1, Format::Format12x, None, None);
    t[0x08] = known(2, Format::Format22x, None, None);
    t[0x09] = known(3, Format::Format32x, None, None);

    // 0x0a-0x0d move-result, move-result-wide, move-result-object, move-exception
    t[0x0a] = known(1, Format::Format11x, None, None);
    t[0x0b] = known(1, Format::Format11x, None, None);
    t[0x0c] = known(1, Format::Format11x, None, None);
    t[0x0d] = known(1, Format::Format11x, None, None);

    // 0x0e return-void, 0x0f-0x11 return / return-wide / return-object
    t[0x0e] = known(1, Format::Format10x, None, None);
    t[0x0f] = known(1, Format::Format11x, None, None);
    t[0x10] = known(1, Format::Format11x, None, None);
    t[0x11] = known(1, Format::Format11x, None, None);

    // 0x12 const/4 (11n)
    t[0x12] = known(1, Format::Format11n, None, None);

    // 0x13-0x15 const/16 (21s), const (31i), const/high16 (21h)
    t[0x13] = known(2, Format::Format21s, None, None);
    t[0x14] = known(3, Format::Format31i, None, None);
    t[0x15] = known(2, Format::Format21h, None, None);

    // 0x16-0x19 const-wide/16, const-wide/32, const-wide, const-wide/high16
    t[0x16] = known(2, Format::Format21s, None, None);
    t[0x17] = known(3, Format::Format31i, None, None);
    t[0x18] = known(5, Format::Format51l, None, None);
    t[0x19] = known(2, Format::Format21h, None, None);

    // 0x1a const-string (21c, string), 0x1b const-string/jumbo (31c, 32-bit string)
    t[0x1a] = known(
        2,
        Format::Format21c,
        Some((RefSlot::U16_AT_1, RefKind::String)),
        None,
    );
    t[0x1b] = known(
        3,
        Format::Format31c,
        Some((RefSlot::U32_AT_1, RefKind::String)),
        None,
    );

    // 0x1c const-class (21c, type)
    t[0x1c] = known(
        2,
        Format::Format21c,
        Some((RefSlot::U16_AT_1, RefKind::Type)),
        None,
    );

    // 0x1d-0x1e monitor-enter, monitor-exit
    t[0x1d] = known(1, Format::Format11x, None, None);
    t[0x1e] = known(1, Format::Format11x, None, None);

    // 0x1f check-cast (21c, type), 0x20 instance-of (22c, type)
    t[0x1f] = known(
        2,
        Format::Format21c,
        Some((RefSlot::U16_AT_1, RefKind::Type)),
        None,
    );
    t[0x20] = known(
        2,
        Format::Format22c,
        Some((RefSlot::U16_AT_1, RefKind::Type)),
        None,
    );

    // 0x21 array-length
    t[0x21] = known(1, Format::Format12x, None, None);

    // 0x22 new-instance (21c, type), 0x23 new-array (22c, type)
    t[0x22] = known(
        2,
        Format::Format21c,
        Some((RefSlot::U16_AT_1, RefKind::Type)),
        None,
    );
    t[0x23] = known(
        2,
        Format::Format22c,
        Some((RefSlot::U16_AT_1, RefKind::Type)),
        None,
    );

    // 0x24 filled-new-array (35c, type), 0x25 filled-new-array/range (3rc, type)
    t[0x24] = known(
        3,
        Format::Format35c,
        Some((RefSlot::U16_AT_1, RefKind::Type)),
        None,
    );
    t[0x25] = known(
        3,
        Format::Format3rc,
        Some((RefSlot::U16_AT_1, RefKind::Type)),
        None,
    );

    // 0x26 fill-array-data (31t)
    t[0x26] = known(3, Format::Format31t, None, None);

    // 0x27 throw
    t[0x27] = known(1, Format::Format11x, None, None);

    // 0x28 goto (10t), 0x29 goto/16 (20t), 0x2a goto/32 (30t)
    t[0x28] = known(1, Format::Format10t, None, None);
    t[0x29] = known(2, Format::Format20t, None, None);
    t[0x2a] = known(3, Format::Format30t, None, None);

    // 0x2b packed-switch (31t), 0x2c sparse-switch (31t)
    t[0x2b] = known(3, Format::Format31t, None, None);
    t[0x2c] = known(3, Format::Format31t, None, None);

    // 0x2d-0x31 cmpl-float, cmpg-float, cmpl-double, cmpg-double, cmp-long (23x)
    t[0x2d] = known(2, Format::Format23x, None, None);
    t[0x2e] = known(2, Format::Format23x, None, None);
    t[0x2f] = known(2, Format::Format23x, None, None);
    t[0x30] = known(2, Format::Format23x, None, None);
    t[0x31] = known(2, Format::Format23x, None, None);

    // 0x32-0x37 if-eq, if-ne, if-lt, if-ge, if-gt, if-le (22t)
    t[0x32] = known(2, Format::Format22t, None, None);
    t[0x33] = known(2, Format::Format22t, None, None);
    t[0x34] = known(2, Format::Format22t, None, None);
    t[0x35] = known(2, Format::Format22t, None, None);
    t[0x36] = known(2, Format::Format22t, None, None);
    t[0x37] = known(2, Format::Format22t, None, None);

    // 0x38-0x3d if-eqz, if-nez, if-ltz, if-gez, if-gtz, if-lez (21t)
    t[0x38] = known(2, Format::Format21t, None, None);
    t[0x39] = known(2, Format::Format21t, None, None);
    t[0x3a] = known(2, Format::Format21t, None, None);
    t[0x3b] = known(2, Format::Format21t, None, None);
    t[0x3c] = known(2, Format::Format21t, None, None);
    t[0x3d] = known(2, Format::Format21t, None, None);

    // 0x3e-0x43 reserved/unused (already unknown)

    // 0x44-0x51 aget / aget-wide / aget-object / aget-boolean / aget-byte /
    //         aget-char / aget-short / aput / aput-wide / aput-object /
    //         aput-boolean / aput-byte / aput-char / aput-short (23x)
    t[0x44] = known(2, Format::Format23x, None, None);
    t[0x45] = known(2, Format::Format23x, None, None);
    t[0x46] = known(2, Format::Format23x, None, None);
    t[0x47] = known(2, Format::Format23x, None, None);
    t[0x48] = known(2, Format::Format23x, None, None);
    t[0x49] = known(2, Format::Format23x, None, None);
    t[0x4a] = known(2, Format::Format23x, None, None);
    t[0x4b] = known(2, Format::Format23x, None, None);
    t[0x4c] = known(2, Format::Format23x, None, None);
    t[0x4d] = known(2, Format::Format23x, None, None);
    t[0x4e] = known(2, Format::Format23x, None, None);
    t[0x4f] = known(2, Format::Format23x, None, None);
    t[0x50] = known(2, Format::Format23x, None, None);
    t[0x51] = known(2, Format::Format23x, None, None);

    // 0x52-0x5f iget / iput family (22c, field)
    let mut i = 0x52u16;
    while i <= 0x5f {
        t[i as usize] = known(
            2,
            Format::Format22c,
            Some((RefSlot::U16_AT_1, RefKind::Field)),
            None,
        );
        i += 1;
    }

    // 0x60-0x6d sget / sput family (21c, field)
    let mut i = 0x60u16;
    while i <= 0x6d {
        t[i as usize] = known(
            2,
            Format::Format21c,
            Some((RefSlot::U16_AT_1, RefKind::Field)),
            None,
        );
        i += 1;
    }

    // 0x6e-0x72 invoke-virtual, invoke-super, invoke-direct, invoke-static, invoke-interface
    //   (35c, method)
    let mut i = 0x6eu16;
    while i <= 0x72 {
        t[i as usize] = known(
            3,
            Format::Format35c,
            Some((RefSlot::U16_AT_1, RefKind::Method)),
            None,
        );
        i += 1;
    }

    // 0x73 reserved (already unknown)

    // 0x74-0x78 invoke-*/range (3rc, method)
    let mut i = 0x74u16;
    while i <= 0x78 {
        t[i as usize] = known(
            3,
            Format::Format3rc,
            Some((RefSlot::U16_AT_1, RefKind::Method)),
            None,
        );
        i += 1;
    }

    // 0x79-0x7a reserved (already unknown)

    // 0x7b-0x8f unary / conversion ops (12x)
    let mut i = 0x7bu16;
    while i <= 0x8f {
        t[i as usize] = known(1, Format::Format12x, None, None);
        i += 1;
    }

    // 0x90-0xaf binary ops (23x)
    let mut i = 0x90u16;
    while i <= 0xaf {
        t[i as usize] = known(2, Format::Format23x, None, None);
        i += 1;
    }

    // 0xb0-0xcf binary ops /2addr (12x)
    let mut i = 0xb0u16;
    while i <= 0xcf {
        t[i as usize] = known(1, Format::Format12x, None, None);
        i += 1;
    }

    // 0xd0-0xd7 lit16 binary ops (22s)
    let mut i = 0xd0u16;
    while i <= 0xd7 {
        t[i as usize] = known(2, Format::Format22s, None, None);
        i += 1;
    }

    // 0xd8-0xe2 lit8 binary ops (22b)
    let mut i = 0xd8u16;
    while i <= 0xe2 {
        t[i as usize] = known(2, Format::Format22b, None, None);
        i += 1;
    }

    // 0xe3-0xec reserved (already unknown)

    // 0xed throw-verification-error (20bc): 2 units, AA | ed | BBBB (kind@).
    //   No standard pool slot; the verifier-only ref is not part of the
    //   asc-rebuild rewrite contract.
    t[0xed] = known(2, Format::Format20bc, None, None);

    // 0xee execute-inline (35mi): 3 units, A | G | ee | BBBB (inline@) |
    //   F | E | D | C. BBBB is an inline-method ID, not a regular method
    //   pool entry, so no ref slot.
    t[0xee] = known(3, Format::Format35mi, None, None);

    // 0xef reserved (already unknown)

    // 0xf0 invoke-direct-empty (35c-style, 3 units, optimized empty
    //   constructor call). No ref slot — the optimized stream already
    //   embedded the direct reference at compile time.
    t[0xf0] = known(3, Format::Format35c, None, None);

    // 0xf1 reserved (already unknown)

    // 0xf2-0xf4 iget-quick / iget-wide-quick / iget-object-quick (22cs).
    //   2 units; CCCC is a field byte offset, not a field-pool index.
    let mut i = 0xf2u16;
    while i <= 0xf4 {
        t[i as usize] = known(2, Format::Format22c, None, None);
        i += 1;
    }

    // 0xf5-0xf7 iput-quick / iput-wide-quick / iput-object-quick (22cs).
    let mut i = 0xf5u16;
    while i <= 0xf7 {
        t[i as usize] = known(2, Format::Format22c, None, None);
        i += 1;
    }

    // 0xf8 invoke-virtual-quick (35ms). 3 units; BBBB is a vtable offset,
    //   not a method pool index — no ref slot.
    t[0xf8] = known(3, Format::Format35c, None, None);

    // 0xf9 invoke-virtual-quick/range (3rms).
    t[0xf9] = known(3, Format::Format3rc, None, None);

    // 0xfa invoke-polymorphic (45cc, 4 units, method @ unit 1, proto @ unit 3).
    t[0xfa] = known(
        4,
        Format::Format45cc,
        Some((RefSlot::U16_AT_1, RefKind::Method)),
        Some((RefSlot::U16_AT_3, RefKind::Proto)),
    );

    // 0xfb invoke-polymorphic/range (4rcc).
    t[0xfb] = known(
        4,
        Format::Format4rcc,
        Some((RefSlot::U16_AT_1, RefKind::Method)),
        Some((RefSlot::U16_AT_3, RefKind::Proto)),
    );

    // 0xfc invoke-custom (35c, call_site).
    t[0xfc] = known(
        3,
        Format::Format35c,
        Some((RefSlot::U16_AT_1, RefKind::CallSite)),
        None,
    );

    // 0xfd invoke-custom/range (3rc, call_site).
    t[0xfd] = known(
        3,
        Format::Format3rc,
        Some((RefSlot::U16_AT_1, RefKind::CallSite)),
        None,
    );

    // 0xfe const-method-handle (21c, method handle).
    t[0xfe] = known(
        2,
        Format::Format21c,
        Some((RefSlot::U16_AT_1, RefKind::MethodHandle)),
        None,
    );

    // 0xff const-method-type (21c, proto).
    t[0xff] = known(
        2,
        Format::Format21c,
        Some((RefSlot::U16_AT_1, RefKind::Proto)),
        None,
    );

    t
}

/// Look up the metadata for a single opcode byte.
#[inline]
pub fn opcode_info(op: u8) -> OpcodeInfo {
    OPCODE_TABLE[op as usize]
}

// --- payload size helpers (used by the walker) ---------------------------

/// Compute the total code-unit extent of a payload pseudo-instruction
/// starting at code-unit offset `offset`.
///
/// `header` is the raw `&[u8]` slice covering the entire `insns` buffer
/// (not just the payload); `offset_units` is where the payload begins;
/// `insns_units` is the total declared length in code units.
///
/// Returns `Err(MalformedPayload { offset: offset_units })` if the
/// payload's declared `size` / `element_width` fields would carry the
/// extent past the end of the buffer or overflow internally. The
/// returned `u32` is the payload extent in code units; the caller's
/// cursor advances by this amount and processing continues.
pub(crate) fn payload_extent(
    header: &[u8],
    offset_units: u32,
    insns_units: u32,
    kind: PayloadKind,
) -> Result<u32, crate::error::BytecodeError> {
    let byte_off = (offset_units as usize).checked_mul(2).ok_or(
        crate::error::BytecodeError::MalformedPayload { offset: offset_units },
    )?;
    let remaining = insns_units
        .checked_sub(offset_units)
        .ok_or(crate::error::BytecodeError::MalformedPayload { offset: offset_units })?;

    let units = match kind {
        PayloadKind::PackedSwitch => {
            if byte_off + 4 > header.len() {
                return Err(crate::error::BytecodeError::MalformedPayload {
                    offset: offset_units,
                });
            }
            let size = u16::from_le_bytes([header[byte_off + 2], header[byte_off + 3]]) as u32;
            size.checked_mul(2)
                .and_then(|v| v.checked_add(4))
                .ok_or(crate::error::BytecodeError::MalformedPayload {
                    offset: offset_units,
                })?
        }
        PayloadKind::SparseSwitch => {
            if byte_off + 4 > header.len() {
                return Err(crate::error::BytecodeError::MalformedPayload {
                    offset: offset_units,
                });
            }
            let size = u16::from_le_bytes([header[byte_off + 2], header[byte_off + 3]]) as u32;
            size.checked_mul(4)
                .and_then(|v| v.checked_add(2))
                .ok_or(crate::error::BytecodeError::MalformedPayload {
                    offset: offset_units,
                })?
        }
        PayloadKind::FillArrayData => {
            if byte_off + 8 > header.len() {
                return Err(crate::error::BytecodeError::MalformedPayload {
                    offset: offset_units,
                });
            }
            let element_width =
                u16::from_le_bytes([header[byte_off + 2], header[byte_off + 3]]) as u32;
            let size = u32::from_le_bytes([
                header[byte_off + 4],
                header[byte_off + 5],
                header[byte_off + 6],
                header[byte_off + 7],
            ]);
            // size * element_width as u64 to avoid 32-bit overflow, then
            // ceil-divide by 2 to convert bytes to code units.
            let total_bytes = (size as u64)
                .checked_mul(element_width as u64)
                .ok_or(crate::error::BytecodeError::MalformedPayload {
                    offset: offset_units,
                })?;
            let extra_units = total_bytes.div_ceil(2);
            let extra_units_u32 = u32::try_from(extra_units).map_err(|_| {
                crate::error::BytecodeError::MalformedPayload {
                    offset: offset_units,
                }
            })?;
            extra_units_u32.checked_add(4).ok_or(
                crate::error::BytecodeError::MalformedPayload {
                    offset: offset_units,
                },
            )?
        }
    };

    // Final sanity: the declared extent must fit in what remains.
    if units > remaining {
        return Err(crate::error::BytecodeError::MalformedPayload {
            offset: offset_units,
        });
    }
    let needed_bytes = (units as usize)
        .checked_mul(2)
        .ok_or(crate::error::BytecodeError::MalformedPayload {
            offset: offset_units,
        })?;
    if byte_off + needed_bytes > header.len() {
        return Err(crate::error::BytecodeError::MalformedPayload {
            offset: offset_units,
        });
    }
    Ok(units)
}

/// Tag for which payload pseudo-instruction was detected at the cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PayloadKind {
    PackedSwitch,
    SparseSwitch,
    FillArrayData,
}

impl PayloadKind {
    /// Detect a payload from its first code unit.
    #[inline]
    pub(crate) fn from_first_unit(first: u16) -> Option<Self> {
        match first {
            0x0100 => Some(Self::PackedSwitch),
            0x0200 => Some(Self::SparseSwitch),
            0x0300 => Some(Self::FillArrayData),
            _ => None,
        }
    }
}

// --- 16-bit / 32-bit index reader ----------------------------------------

/// Read a 16-bit or 32-bit little-endian index from `insns` at
/// `insn_byte_off + slot.unit_off * 2`. Caller must guarantee that the
/// slot and its bit width fit inside the instruction's declared width.
#[inline]
pub(crate) fn read_index(insns: &[u8], insn_byte_off: usize, slot: RefSlot) -> u32 {
    let byte_off = insn_byte_off + (slot.unit_off as usize) * 2;
    match slot.bits {
        16 => u16::from_le_bytes([insns[byte_off], insns[byte_off + 1]]) as u32,
        32 => {
            let lo = u16::from_le_bytes([insns[byte_off], insns[byte_off + 1]]);
            let hi = u16::from_le_bytes([insns[byte_off + 2], insns[byte_off + 3]]);
            (lo as u32) | ((hi as u32) << 16)
        }
        other => unreachable!("RefSlot.bits must be 16 or 32, got {other}"),
    }
}

/// Wrap a raw `u32` index in the appropriate [`DexRef`] variant for a
/// given [`RefKind`].
#[inline]
pub(crate) fn make_ref(kind: RefKind, idx: u32) -> crate::walker::DexRef {
    use crate::walker::DexRef;
    match kind {
        RefKind::String => DexRef::String(StringIdx(idx)),
        RefKind::Type => DexRef::Type(TypeIdx(idx)),
        RefKind::Field => DexRef::Field(FieldIdx(idx)),
        RefKind::Method => DexRef::Method(MethodIdx(idx)),
        RefKind::Proto => DexRef::Proto(ProtoIdx(idx)),
        RefKind::CallSite => DexRef::CallSite(CallSiteIdx(idx)),
        RefKind::MethodHandle => DexRef::MethodHandle(MethodHandleIdx(idx)),
    }
}
