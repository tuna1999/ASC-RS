//! Non-allocating scanner that yields every reference-bearing instruction
//! in a Dalvik `insns` buffer.
//!
//! The walker is the read half of the asc-rebuild rewrite contract:
//! asc-rebuild rewrites the indexes *in place*; this walker locates them.
//! Slot positions exposed via [`crate::opcode::OpcodeInfo`] and emitted on
//! [`RefInstruction`] match the source.android.com instruction-format
//! diagrams.
//!
//! ## Non-allocation guarantee
//! - `RefWalker` borrows the `insns` slice and holds four `u32` / `bool`
//!   fields. No `Vec`, no `String`, no `Box`.
//! - `RefInstruction` is `Copy`. It holds two `Option<DexRef>` values
//!   where each `DexRef` variant is `#[repr(transparent)] u32`. No heap.
//! - No panic on untrusted input. Every code-unit access is bounded by
//!   the validated `insns.len() == insns_units * 2` invariant established
//!   at construction time, plus the per-instruction width check.

use crate::dex_ids::*;
use crate::error::BytecodeError;
use crate::opcode::{PayloadKind, make_ref, opcode_info, payload_extent, read_index};

/// A reference operand located inside a Dalvik instruction.
///
/// Each variant wraps a typed pool index from [`crate::dex_ids`]. The
/// raw `u32` is the literal pool index as it appears in the binary
/// (asc-rebuild rewrites it in place; consumers should treat the value
/// as opaque and pass it to their pool lookup).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DexRef {
    String(StringIdx),
    Type(TypeIdx),
    Field(FieldIdx),
    Method(MethodIdx),
    Proto(ProtoIdx),
    CallSite(CallSiteIdx),
    MethodHandle(MethodHandleIdx),
}

/// One reference-bearing Dalvik instruction.
///
/// `offset` is the code-unit offset of the instruction within the
/// original `insns` buffer (so byte offset = `offset * 2`). `primary` and
/// `secondary` carry the reference operands: `secondary` is populated
/// only for `45cc` / `4rcc` (`invoke-polymorphic`, `invoke-polymorphic/range`),
/// where the prototype reference lives at code-unit offset 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefInstruction {
    pub offset: u32,
    pub primary: Option<DexRef>,
    pub secondary: Option<DexRef>,
}

/// Streaming, zero-allocating iterator over the reference-bearing
/// instructions of a code body.
///
/// Constructed via [`RefWalker::new`], which validates that
/// `insns.len() == insns_units * 2`. The walker yields every instruction
/// that carries a pool reference and silently steps over everything else
/// using the per-opcode width table. Payload pseudo-instructions
/// (`packed-switch` / `sparse-switch` / `fill-array-data`) are stepped
/// past in a single jump whose extent is computed from the payload's
/// declared `size` / `element_width`.
///
/// On the first error the walker terminates: callers iterate to
/// exhaustion, keep the partial `Ok` hits, and decide what to do with
/// the trailing `Err`.
pub struct RefWalker<'a> {
    insns: &'a [u8],
    insns_units: u32,
    cursor_units: u32,
    finished: bool,
}

impl<'a> RefWalker<'a> {
    /// Build a walker over `insns`.
    ///
    /// Returns `Err(LengthMismatch)` if `insns.len() != insns_units * 2`
    /// or if `insns_units * 2` overflows.
    pub fn new(insns: &'a [u8], insns_units: u32) -> Result<Self, BytecodeError> {
        let bytes = insns.len() as u64;
        let expected =
            (insns_units as u64)
                .checked_mul(2)
                .ok_or(BytecodeError::LengthMismatch {
                    offset: 0,
                    units: insns_units,
                    bytes,
                    expected: u64::MAX,
                })?;
        if bytes != expected {
            return Err(BytecodeError::LengthMismatch {
                offset: 0,
                units: insns_units,
                bytes,
                expected,
            });
        }
        Ok(Self {
            insns,
            insns_units,
            cursor_units: 0,
            finished: false,
        })
    }

    /// Code units the walker has already consumed (i.e. the cursor).
    pub fn units_consumed(&self) -> u32 {
        self.cursor_units
    }

    /// Declared total code-unit count for the buffer.
    pub fn insns_units(&self) -> u32 {
        self.insns_units
    }

    #[inline]
    fn read_first_unit(&self, byte_off: usize) -> Option<u16> {
        let slice = self.insns.get(byte_off..byte_off + 2)?;
        Some(u16::from_le_bytes([slice[0], slice[1]]))
    }
}

impl<'a> Iterator for RefWalker<'a> {
    type Item = Result<RefInstruction, BytecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.finished || self.cursor_units >= self.insns_units {
                return None;
            }

            let offset = self.cursor_units;
            let byte_off = match (offset as usize).checked_mul(2) {
                Some(b) => b,
                None => {
                    self.finished = true;
                    return Some(Err(BytecodeError::MalformedPayload { offset }));
                }
            };

            // First code unit of the instruction.
            let first_unit = match self.read_first_unit(byte_off) {
                Some(u) => u,
                None => {
                    self.finished = true;
                    return Some(Err(BytecodeError::TruncatedInstruction {
                        offset,
                        needed: 1,
                        available: 0,
                    }));
                }
            };

            // Payload pseudo-instructions are detected by their ident
            // (0x0100 / 0x0200 / 0x0300 in the first code unit). The
            // opcode byte of every payload ident is 0x00, which would
            // otherwise decode as `nop`.
            if let Some(kind) = PayloadKind::from_first_unit(first_unit) {
                match payload_extent(self.insns, offset, self.insns_units, kind) {
                    Ok(units) => {
                        self.cursor_units = match offset.checked_add(units) {
                            Some(n) => n,
                            None => {
                                self.finished = true;
                                return Some(Err(BytecodeError::MalformedPayload { offset }));
                            }
                        };
                        continue;
                    }
                    Err(e) => {
                        self.finished = true;
                        return Some(Err(e));
                    }
                }
            }

            // Regular instruction: look up by low byte.
            let opcode = (first_unit & 0xFF) as u8;
            let info = opcode_info(opcode);

            if info.is_unknown {
                self.finished = true;
                return Some(Err(BytecodeError::UnknownOpcode { offset, opcode }));
            }

            let width = info.width_units as u32;
            let end = match offset.checked_add(width) {
                Some(e) => e,
                None => {
                    self.finished = true;
                    let available = self.insns_units.saturating_sub(offset);
                    return Some(Err(BytecodeError::TruncatedInstruction {
                        offset,
                        needed: width,
                        available,
                    }));
                }
            };

            if end > self.insns_units {
                self.finished = true;
                let available = self.insns_units - offset;
                return Some(Err(BytecodeError::TruncatedInstruction {
                    offset,
                    needed: width,
                    available,
                }));
            }

            // Decode any reference operands. The slot offset is bounded
            // by `info.width_units` (verified at build-table time), and
            // `end <= insns_units` guarantees the buffer covers every
            // byte the slot needs to read.
            let primary = info
                .primary
                .map(|(slot, kind)| make_ref(kind, read_index(self.insns, byte_off, slot)));
            let secondary = info
                .secondary
                .map(|(slot, kind)| make_ref(kind, read_index(self.insns, byte_off, slot)));

            self.cursor_units = end;

            // Per the spec, the walker yields ONLY reference-bearing
            // instructions and silently steps over everything else.
            // Instructions without a pool ref (nop, arithmetic ops,
            // branches, payloads) advance the cursor and continue.
            if primary.is_none() && secondary.is_none() {
                continue;
            }

            return Some(Ok(RefInstruction {
                offset,
                primary,
                secondary,
            }));
        }
    }
}

/// Convenience: walk the entire `insns` buffer, ignore the references,
/// and return the first error (if any). Useful as a smoke test of
/// "this code body has no truncated / unknown / malformed-payload
/// instructions".
pub fn walk_verify(insns: &[u8], insns_units: u32) -> Result<(), BytecodeError> {
    let walker = RefWalker::new(insns, insns_units)?;
    for item in walker {
        item?;
    }
    Ok(())
}

/// Width in code units of the instruction (or payload pseudo-instruction)
/// starting at `offset`, validated against `insns_units`. `insns` must
/// hold at least `insns_units * 2` bytes.
pub fn insn_width(insns: &[u8], offset: u32, insns_units: u32) -> Result<u32, BytecodeError> {
    let byte_off = offset as usize * 2;
    let first = insns
        .get(byte_off..byte_off + 2)
        .filter(|_| offset < insns_units)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(BytecodeError::TruncatedInstruction {
            offset,
            needed: 1,
            available: 0,
        })?;
    if let Some(kind) = PayloadKind::from_first_unit(first) {
        return payload_extent(insns, offset, insns_units, kind);
    }
    let opcode = (first & 0xFF) as u8;
    let info = opcode_info(opcode);
    if info.is_unknown {
        return Err(BytecodeError::UnknownOpcode { offset, opcode });
    }
    let width = info.width_units as u32;
    let available = insns_units - offset;
    if width > available {
        return Err(BytecodeError::TruncatedInstruction {
            offset,
            needed: width,
            available,
        });
    }
    Ok(width)
}

// `RefSlot` and `RefKind` are re-exported by the crate root so callers
// can `use asc_bytecode::{RefSlot, RefKind}` without reaching into
// `opcode` directly. Both are used by `asc-rebuild` to know where to
// patch and what index kind an occupied slot carries.
