//! `debug_info_item` parsing.
//!
//! A debug info record carries:
//! - `line_start` (uleb)
//! - `parameters_size` (uleb)
//! - `parameters_size` ULEB128P1-encoded string indices
//! - a stream of state-machine opcodes
//!
//! We return the parsed header + an iterator over opcodes. The iterator
//! stops cleanly on `DBG_END_SEQUENCE` and surfaces malformed input via
//! [`DexError`].

use crate::error::DexError;
use crate::ids::{StringIdx, TypeIdx};
use crate::view::DexView;

/// State-machine opcode constants.
pub const DBG_END_SEQUENCE: u8 = 0x00;
pub const DBG_ADVANCE_PC: u8 = 0x01;
pub const DBG_ADVANCE_LINE: u8 = 0x02;
pub const DBG_START_LOCAL: u8 = 0x03;
pub const DBG_START_LOCAL_EXTENDED: u8 = 0x04;
pub const DBG_END_LOCAL: u8 = 0x05;
pub const DBG_RESTART_LOCAL: u8 = 0x06;
pub const DBG_SET_PROLOGUE_END: u8 = 0x07;
pub const DBG_SET_EPILOGUE_BEGIN: u8 = 0x08;
pub const DBG_SET_FILE: u8 = 0x09;
/// DBG_LINE_BASE — special opcodes 0x0a..=0xff encode
/// `line + DBG_LINE_BASE`, with `DBG_LINE_BASE = -4`.
pub const DBG_LINE_BASE: i32 = -4;
/// DBG_LINE_RANGE — special opcodes advance line by `(op - 0x0a) % DBG_LINE_RANGE + DBG_LINE_BASE`.
pub const DBG_LINE_RANGE: i32 = 15;

/// Parsed header of a `debug_info_item` (the part before the opcode stream).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugInfoHeader {
    pub line_start: u32,
    pub parameter_names: Vec<Option<StringIdx>>,
}

/// A single debug opcode (already decoded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebugOp {
    EndSequence,
    AdvancePc {
        addr_diff: u32,
    },
    AdvanceLine {
        line_diff: i32,
    },
    StartLocal {
        reg: u32,
        name: Option<StringIdx>,
        ty: Option<TypeIdx>,
    },
    StartLocalExtended {
        reg: u32,
        name: Option<StringIdx>,
        ty: Option<TypeIdx>,
        sig: Option<StringIdx>,
    },
    EndLocal {
        reg: u32,
    },
    RestartLocal {
        reg: u32,
    },
    SetPrologueEnd,
    SetEpilogueBegin,
    SetFile {
        name: Option<StringIdx>,
    },
    /// Special opcode (0x0a..=0xff): line delta + pc delta derived from the opcode byte.
    Special {
        opcode: u8,
        line_diff: i32,
        addr_diff: u32,
    },
}

impl<'a> DexView<'a> {
    /// Parses the `debug_info_item` header at `off`. Returns `Ok(None)` for `off == 0`.
    pub fn debug_info(&self, off: u32) -> Result<Option<DebugInfoHeader>, DexError> {
        if off == 0 {
            return Ok(None);
        }
        let p = off as usize;
        if p >= self.physical.len() {
            return Err(DexError::OffsetOutOfBounds {
                off: p,
                file: self.physical.len(),
            });
        }
        let (line_start, n) = crate::leb::uleb128_to_u32(&self.physical[p..])?;
        let mut q = p + n;
        let (params_size, n) = crate::leb::uleb128_to_u32(&self.physical[q..])?;
        q += n;
        let mut parameter_names =
            Vec::with_capacity((params_size as usize).min(self.physical.len()));
        for _ in 0..params_size {
            let (v, n) = crate::leb::uleb128_to_u32(&self.physical[q..])?;
            q += n;
            // ULEB128P1: 0 means absent, otherwise the index is `v - 1`.
            if v == 0 {
                parameter_names.push(None);
            } else {
                parameter_names.push(Some(StringIdx(v - 1)));
            }
        }
        Ok(Some(DebugInfoHeader {
            line_start,
            parameter_names,
        }))
    }

    /// Iterator over the opcode stream of a debug_info record at `off`.
    /// `off` must be the start of the record (i.e. the header's ULEB).
    pub fn debug_ops<'s>(&'s self, off: u32) -> Result<DebugOps<'a>, DexError> {
        let p = off as usize;
        if p >= self.physical.len() {
            return Err(DexError::OffsetOutOfBounds {
                off: p,
                file: self.physical.len(),
            });
        }
        let (_line_start, n) = crate::leb::uleb128_to_u32(&self.physical[p..])?;
        let mut q = p + n;
        let (params_size, n) = crate::leb::uleb128_to_u32(&self.physical[q..])?;
        q += n;
        for _ in 0..params_size {
            let (_, n) = crate::leb::uleb128_to_u32(&self.physical[q..])?;
            q += n;
        }
        Ok(DebugOps {
            physical: self.physical,
            pos: q,
            done: false,
        })
    }

    /// Resolve a code-unit offset within `debug_info` at `off` to the
    /// 1-indexed source line. Returns `Ok(None)` when `off == 0` (no
    /// debug_info emitted for this code) or when the address falls
    /// before any opcode that updates the line (still returns
    /// `line_start` in that case).
    pub fn line_for_code_unit(&self, off: u32, code_off: u32) -> Result<Option<u32>, DexError> {
        let Some(header) = self.debug_info(off)? else {
            return Ok(None);
        };
        let mut ops = self.debug_ops(off)?;
        let mut pc: u32 = 0;
        let mut line: i64 = header.line_start as i64;
        // The first emitted source line is line_start; that is the
        // answer for any code_off <= first opcode's address.
        let mut best: u32 = header.line_start;
        let target = code_off;
        for op in ops.by_ref() {
            let op = op?;
            match op {
                DebugOp::EndSequence => break,
                DebugOp::AdvancePc { addr_diff } => pc = pc.saturating_add(addr_diff),
                DebugOp::AdvanceLine { line_diff } => line = line.saturating_add(line_diff as i64),
                DebugOp::Special {
                    addr_diff,
                    line_diff,
                    ..
                } => {
                    pc = pc.saturating_add(addr_diff);
                    line = line.saturating_add(line_diff as i64);
                }
                DebugOp::SetPrologueEnd
                | DebugOp::SetEpilogueBegin
                | DebugOp::StartLocal { .. }
                | DebugOp::StartLocalExtended { .. }
                | DebugOp::EndLocal { .. }
                | DebugOp::RestartLocal { .. }
                | DebugOp::SetFile { .. } => {}
            }
            if line <= 0 {
                continue;
            }
            if pc > target {
                break;
            }
            best = line as u32;
            if pc == target {
                break;
            }
        }
        Ok(Some(best.max(1)))
    }
}

/// Iterator over a debug opcode stream.
pub struct DebugOps<'a> {
    physical: &'a [u8],
    pos: usize,
    done: bool,
}

impl<'a> Iterator for DebugOps<'a> {
    type Item = Result<DebugOp, DexError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if self.pos >= self.physical.len() {
            self.done = true;
            return Some(Err(DexError::Truncated {
                needed: self.pos + 1,
                actual: self.physical.len(),
            }));
        }
        let opcode = self.physical[self.pos];
        let start = self.pos;
        self.pos += 1;
        let op = match opcode {
            DBG_END_SEQUENCE => {
                self.done = true;
                Ok(DebugOp::EndSequence)
            }
            DBG_ADVANCE_PC => match crate::leb::uleb128_to_u32(slice_at(self.physical, self.pos)) {
                Ok((v, n)) => {
                    self.pos += n;
                    Ok(DebugOp::AdvancePc { addr_diff: v })
                }
                Err(e) => Err(e),
            },
            DBG_ADVANCE_LINE => match crate::leb::sleb128_to_i32(slice_at(self.physical, self.pos))
            {
                Ok((v, n)) => {
                    self.pos += n;
                    Ok(DebugOp::AdvanceLine { line_diff: v })
                }
                Err(e) => Err(e),
            },
            DBG_START_LOCAL => {
                let r = read_three(slice_at(self.physical, self.pos));
                match r {
                    Ok(((reg, name, ty), n)) => {
                        self.pos += n;
                        Ok(DebugOp::StartLocal {
                            reg,
                            name: uleb_p1(name),
                            ty: uleb_p1_type(ty),
                        })
                    }
                    Err(e) => Err(e),
                }
            }
            DBG_START_LOCAL_EXTENDED => {
                let r = read_four(slice_at(self.physical, self.pos));
                match r {
                    Ok(((reg, name, ty, sig), n)) => {
                        self.pos += n;
                        Ok(DebugOp::StartLocalExtended {
                            reg,
                            name: uleb_p1(name),
                            ty: uleb_p1_type(ty),
                            sig: uleb_p1(sig),
                        })
                    }
                    Err(e) => Err(e),
                }
            }
            DBG_END_LOCAL | DBG_RESTART_LOCAL => {
                match crate::leb::uleb128_to_u32(slice_at(self.physical, self.pos)) {
                    Ok((v, n)) => {
                        self.pos += n;
                        Ok(if opcode == DBG_END_LOCAL {
                            DebugOp::EndLocal { reg: v }
                        } else {
                            DebugOp::RestartLocal { reg: v }
                        })
                    }
                    Err(e) => Err(e),
                }
            }
            DBG_SET_PROLOGUE_END => Ok(DebugOp::SetPrologueEnd),
            DBG_SET_EPILOGUE_BEGIN => Ok(DebugOp::SetEpilogueBegin),
            DBG_SET_FILE => match crate::leb::uleb128_to_u32(slice_at(self.physical, self.pos)) {
                Ok((v, n)) => {
                    self.pos += n;
                    Ok(DebugOp::SetFile { name: uleb_p1(v) })
                }
                Err(e) => Err(e),
            },
            op if op >= 0x0a => {
                let adjusted = op - 0x0a;
                let line_diff = (adjusted as i32 % DBG_LINE_RANGE) + DBG_LINE_BASE;
                let addr_diff = (adjusted as u32) / (DBG_LINE_RANGE as u32);
                Ok(DebugOp::Special {
                    opcode: op,
                    line_diff,
                    addr_diff,
                })
            }
            other => Err(DexError::BadDebugOpcode {
                op: other,
                off: start,
                message: "unknown debug opcode",
            }),
        };
        Some(op)
    }
}

#[inline]
fn slice_at(physical: &[u8], pos: usize) -> &[u8] {
    if pos > physical.len() {
        &[]
    } else {
        &physical[pos..]
    }
}

#[inline]
fn uleb_p1(v: u32) -> Option<StringIdx> {
    if v == 0 { None } else { Some(StringIdx(v - 1)) }
}

#[inline]
fn uleb_p1_type(v: u32) -> Option<TypeIdx> {
    if v == 0 { None } else { Some(TypeIdx(v - 1)) }
}

/// Four-element uleb tuple returned by [`read_four`].
type UlebFour = ((u32, u32, u32, u32), usize);

fn read_three(bytes: &[u8]) -> Result<((u32, u32, u32), usize), DexError> {
    let (a, n) = crate::leb::uleb128_to_u32(bytes)?;
    let (b, n2) = crate::leb::uleb128_to_u32(&bytes[n..])?;
    let (c, n3) = crate::leb::uleb128_to_u32(&bytes[n + n2..])?;
    Ok(((a, b, c), n + n2 + n3))
}

fn read_four(bytes: &[u8]) -> Result<UlebFour, DexError> {
    let (a, n) = crate::leb::uleb128_to_u32(bytes)?;
    let (b, n2) = crate::leb::uleb128_to_u32(&bytes[n..])?;
    let (c, n3) = crate::leb::uleb128_to_u32(&bytes[n + n2..])?;
    let (d, n4) = crate::leb::uleb128_to_u32(&bytes[n + n2 + n3..])?;
    Ok(((a, b, c, d), n + n2 + n3 + n4))
}
