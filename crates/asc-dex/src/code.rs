//! `code_item`, `try_item`, and `encoded_catch_handler` accessors.
//!
//! A `code_item` follows a fixed 16-byte header followed by `insns_size`
//! 16-bit code units. When `tries_size > 0` and `insns_size` is odd, two
//! padding bytes of zeros follow the instructions; we expose them as part
//! of the `insns` slice so callers that index by code unit get the expected
//! length (`2 * insns_size`).
//!
//! The `encoded_catch_handler_list` immediately follows the `tries` array
//! (and any padding required for 4-byte alignment).

use crate::error::DexError;
use crate::view::DexView;

/// Parsed `code_item`. The `insns` slice has length `2 * insns_size`,
/// including the padding unit when one is required.
#[derive(Debug, Clone, Copy)]
pub struct CodeItem<'a> {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns_size: u32,
    pub insns: &'a [u8],
}

/// One entry in the `tries` array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    /// Byte offset into the `encoded_catch_handler_list` (relative to its
    /// start). Resolved into a [`CatchHandler`] by
    /// [`DexView::catch_handler`].
    pub handler_off: u16,
}

/// A parsed `encoded_catch_handler`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchHandler {
    /// Each pair is `(type_idx, addr)`. May be empty when only a catch-all
    /// is present.
    pub pairs: Vec<(u32, u32)>,
    /// Bytecode address of the catch-all handler; `None` when absent.
    pub catch_all_addr: Option<u32>,
}

/// Iterator over a `code_item`'s `tries` array.
pub struct TriesIter<'a> {
    physical: &'a [u8],
    base: usize,
    pos: usize,
    count: usize,
}

impl<'a> Iterator for TriesIter<'a> {
    type Item = TryItem;
    fn next(&mut self) -> Option<TryItem> {
        if self.pos >= self.count {
            return None;
        }
        let off = self.base + self.pos * 8;
        if off + 8 > self.physical.len() {
            self.pos = self.count;
            return None;
        }
        let start_addr = match crate::read::read_u32(self.physical, off) {
            Ok(v) => v,
            Err(_) => {
                self.pos = self.count;
                return None;
            }
        };
        let insn_count = match crate::read::read_u16(self.physical, off + 4) {
            Ok(v) => v,
            Err(_) => {
                self.pos = self.count;
                return None;
            }
        };
        let handler_off = match crate::read::read_u16(self.physical, off + 6) {
            Ok(v) => v,
            Err(_) => {
                self.pos = self.count;
                return None;
            }
        };
        self.pos += 1;
        Some(TryItem {
            start_addr,
            insn_count,
            handler_off,
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.count - self.pos;
        (rem, Some(rem))
    }
}

impl<'a> DexView<'a> {
    /// Parses a `code_item` at `off`. `off` must be 4-byte aligned. Returns
    /// `Ok(None)` when `off == 0`.
    pub fn code_item(&self, off: u32) -> Result<Option<CodeItem<'a>>, DexError> {
        if off == 0 {
            return Ok(None);
        }
        let off_us = off as usize;
        if off_us & 3 != 0 {
            return Err(DexError::MisalignedCodeItem { off: off_us });
        }
        if off_us + 16 > self.physical.len() {
            return Err(DexError::Truncated {
                needed: off_us + 16,
                actual: self.physical.len(),
            });
        }
        let regs = crate::read::read_u16(self.physical, off_us)?;
        let ins = crate::read::read_u16(self.physical, off_us + 2)?;
        let outs = crate::read::read_u16(self.physical, off_us + 4)?;
        let tries = crate::read::read_u16(self.physical, off_us + 6)?;
        let dbg = crate::read::read_u32(self.physical, off_us + 8)?;
        let insns_size = crate::read::read_u32(self.physical, off_us + 12)?;

        let insn_units = insns_size as usize;
        let insn_bytes = insn_units.checked_mul(2).ok_or(DexError::InvalidLength {
            off: off_us,
            message: "insns_size overflow",
        })?;
        let insns_start = off_us + 16;
        let insns_end = insns_start
            .checked_add(insn_bytes)
            .ok_or(DexError::InvalidLength {
                off: off_us,
                message: "insns_size overflow",
            })?;
        if insns_end > self.physical.len() {
            return Err(DexError::Truncated {
                needed: insns_end,
                actual: self.physical.len(),
            });
        }
        // DEX requires one padding unit (2 bytes) when tries_size > 0 AND
        // insns_size is odd. We always expose 2*insns_size bytes; the
        // padding bytes extend the slice.
        let extra = if tries > 0 && (insns_size & 1) == 1 {
            if insns_end + 2 > self.physical.len() {
                return Err(DexError::Truncated {
                    needed: insns_end + 2,
                    actual: self.physical.len(),
                });
            }
            2
        } else {
            0
        };
        let insns = &self.physical[insns_start..insns_end + extra];

        Ok(Some(CodeItem {
            registers_size: regs,
            ins_size: ins,
            outs_size: outs,
            tries_size: tries,
            debug_info_off: dbg,
            insns_size,
            insns,
        }))
    }

    /// Computes the absolute byte offset where the `tries` array (and
    /// thus the encoded catch handler list) starts for a code item.
    fn code_item_tries_base(&self, code: &CodeItem<'a>) -> usize {
        let insns_ptr = code.insns.as_ptr() as usize;
        let physical_ptr = self.physical.as_ptr() as usize;
        insns_ptr - physical_ptr + code.insns.len()
    }

    /// Iterator over the `tries` array of the given `code_item`.
    pub fn tries_iter<'s>(
        &'s self,
        code: &CodeItem<'a>,
    ) -> Result<TriesIter<'a>, DexError> {
        let base = self.code_item_tries_base(code);
        let count = code.tries_size as usize;
        if count == 0 {
            return Ok(TriesIter {
                physical: self.physical,
                base,
                pos: 0,
                count: 0,
            });
        }
        if base & 3 != 0 {
            return Err(DexError::InvalidLength {
                off: base,
                message: "tries array is not 4-byte aligned",
            });
        }
        let needed = count.checked_mul(8).ok_or(DexError::InvalidLength {
            off: base,
            message: "tries overflow",
        })?;
        if base + needed > self.physical.len() {
            return Err(DexError::Truncated {
                needed: base + needed,
                actual: self.physical.len(),
            });
        }
        Ok(TriesIter {
            physical: self.physical,
            base,
            pos: 0,
            count,
        })
    }

    /// Returns the `encoded_catch_handler_list` raw bytes (start, size) for
    /// a given code item. Returns `Ok(None)` when `tries_size == 0`.
    pub fn catch_handler_list<'s>(
        &'s self,
        code: &CodeItem<'a>,
    ) -> Result<Option<CatchHandlerList<'a>>, DexError> {
        if code.tries_size == 0 {
            return Ok(None);
        }
        let tries_base = self.code_item_tries_base(code);
        let tries_bytes = (code.tries_size as usize) * 8;
        let mut list_off = tries_base + tries_bytes;
        let pad = (4 - (list_off & 3)) & 3;
        list_off += pad;
        if list_off + 4 > self.physical.len() {
            return Err(DexError::Truncated {
                needed: list_off + 4,
                actual: self.physical.len(),
            });
        }
        let list_size = crate::read::read_u32(self.physical, list_off)?;
        let raw_base = list_off;
        let raw_end = list_off
            .checked_add(4)
            .and_then(|x| x.checked_add(list_size as usize))
            .ok_or(DexError::InvalidLength {
                off: list_off,
                message: "catch_handler list overflow",
            })?;
        if raw_end > self.physical.len() {
            return Err(DexError::Truncated {
                needed: raw_end,
                actual: self.physical.len(),
            });
        }
        let raw = &self.physical[raw_base..raw_end];
        Ok(Some(CatchHandlerList {
            raw,
            raw_base,
            size: list_size,
        }))
    }

    /// Resolves a single try item's catch handler.
    pub fn catch_handler(
        &self,
        list: &CatchHandlerList<'a>,
        try_item: &TryItem,
    ) -> Result<CatchHandler, DexError> {
        let off = try_item.handler_off as usize;
        if off >= list.raw.len() {
            return Err(DexError::BadCatchHandlerOffset {
                off: list.raw_base + off,
                start: list.raw_base,
                end: list.raw_base + list.raw.len(),
            });
        }
        // Walk past the size prefix.
        let mut q = 4usize; // skip list size
        while q < list.raw.len() {
            if q - 4 == off {
                return Self::parse_catch_handler_at(list.raw, q);
            }
            let advance = entry_total_len(&list.raw[q..])?;
            q += advance;
        }
        Err(DexError::BadCatchHandlerOffset {
            off: list.raw_base + off,
            start: list.raw_base,
            end: list.raw_base + list.raw.len(),
        })
    }

    /// Parses the catch handler at the given byte offset inside `raw`.
    fn parse_catch_handler_at(raw: &[u8], q: usize) -> Result<CatchHandler, DexError> {
        let (size_signed, n) = crate::leb::sleb128(&raw[q..])?;
        let mut p = q + n;
        let count = size_signed.unsigned_abs() as usize;
        let mut pairs = Vec::with_capacity(count);
        for _ in 0..count {
            let (t, n) = crate::leb::uleb128(&raw[p..])?;
            p += n;
            let (a, n) = crate::leb::uleb128(&raw[p..])?;
            p += n;
            pairs.push((t as u32, a as u32));
        }
        let catch_all = if size_signed <= 0 {
            let (a, _n) = crate::leb::uleb128(&raw[p..])?;
            Some(a as u32)
        } else {
            None
        };
        Ok(CatchHandler {
            pairs,
            catch_all_addr: catch_all,
        })
    }
}

/// Lazily-iterable view of an `encoded_catch_handler_list`.
#[derive(Debug, Clone)]
pub struct CatchHandlerList<'a> {
    raw: &'a [u8],
    raw_base: usize,
    /// Total size (in bytes) recorded in the list header; used for bounds.
    size: u32,
}

impl<'a> CatchHandlerList<'a> {
    /// Returns the total byte size of the list (not counting the 4-byte size
    /// header itself).
    #[inline]
    pub fn size(&self) -> u32 {
        self.size
    }

    /// Resolves the catch handler at `handler_off` (a `try_item.handler_off`
    /// value, relative to the start of the list).
    pub fn get(&self, handler_off: u16) -> Result<CatchHandler, DexError> {
        let off = handler_off as usize;
        if off >= self.raw.len() {
            return Err(DexError::BadCatchHandlerOffset {
                off: self.raw_base + off,
                start: self.raw_base,
                end: self.raw_base + self.raw.len(),
            });
        }
        let mut q = 4usize;
        while q < self.raw.len() {
            if q - 4 == off {
                return DexView::parse_catch_handler_at(self.raw, q);
            }
            let advance = entry_total_len(&self.raw[q..])?;
            q += advance;
        }
        Err(DexError::BadCatchHandlerOffset {
            off: self.raw_base + off,
            start: self.raw_base,
            end: self.raw_base + self.raw.len(),
        })
    }

    /// Eagerly parses every handler entry and returns them in order.
    pub fn iter_all(&self) -> Result<Vec<CatchHandler>, DexError> {
        let mut out = Vec::new();
        let mut q = 4usize;
        while q < self.raw.len() {
            let h = DexView::parse_catch_handler_at(self.raw, q)?;
            let advance = entry_total_len(&self.raw[q..])?;
            out.push(h);
            q += advance;
        }
        Ok(out)
    }
}

/// Returns the total number of bytes consumed by one entry, including the
/// size SLEB itself.
fn entry_total_len(raw_at_entry: &[u8]) -> Result<usize, DexError> {
    let (size_signed, n) = crate::leb::sleb128(raw_at_entry)?;
    let mut p = n;
    let count = size_signed.unsigned_abs() as usize;
    for _ in 0..count {
        let (_, k) = crate::leb::uleb128(&raw_at_entry[p..])?;
        p += k;
        let (_, k) = crate::leb::uleb128(&raw_at_entry[p..])?;
        p += k;
    }
    if size_signed <= 0 {
        let (_, k) = crate::leb::uleb128(&raw_at_entry[p..])?;
        p += k;
    }
    Ok(p)
}