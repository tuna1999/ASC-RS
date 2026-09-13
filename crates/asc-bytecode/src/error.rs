//! Errors raised by the Dalvik reference walker.
//!
//! All variants carry a `code_unit_offset` so callers can pinpoint the
//! position in the original `insns` buffer where the failure was detected
//! (the walker advances strictly in 16-bit code units; byte offsets are
//! `offset * 2`).

use thiserror::Error;

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum BytecodeError {
    /// The buffer is shorter than `insns_units * 2`, or `insns_units`
    /// overflowed when doubled. Detected at `RefWalker::new` time before
    /// any instruction is consumed. `offset` is always `0` for this
    /// variant (no cursor exists yet).
    #[error(
        "insns buffer length {bytes} does not match insns_units={units} (expected {expected} bytes)"
    )]
    LengthMismatch {
        offset: u32,
        units: u32,
        bytes: u64,
        expected: u64,
    },

    /// The cursor reached a code-unit position where the remaining
    /// buffer holds fewer code units than the decoded instruction width
    /// requires. `offset` is the unit offset of the truncated insn;
    /// `needed` is the width the table demanded; `available` is what
    /// was actually left (`insns_units - offset`).
    #[error(
        "truncated instruction at code-unit offset {offset}: needed {needed} unit(s), {available} remaining"
    )]
    TruncatedInstruction {
        offset: u32,
        needed: u32,
        available: u32,
    },

    /// The opcode byte is in the `0x00..=0xFF` range but maps to no
    /// assigned Dalvik instruction (table entry has `is_unknown == true`).
    #[error("unknown opcode 0x{opcode:02x} at code-unit offset {offset}")]
    UnknownOpcode { offset: u32, opcode: u8 },

    /// A payload pseudo-instruction (`0x0100` packed-switch,
    /// `0x0200` sparse-switch, `0x0300` fill-array-data) declared a
    /// `size` / `element_width` that would carry its declared extent past
    /// the remaining buffer, or overflowed internally when computing the
    /// extent (`size * 2`, `size * 4`, `size * element_width`).
    #[error("malformed payload pseudo-instruction at code-unit offset {offset}")]
    MalformedPayload { offset: u32 },
}
