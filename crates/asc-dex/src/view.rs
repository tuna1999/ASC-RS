//! The `DexView<'a>` zero-copy DEX reader.

use crate::error::DexError;
use crate::header::{DexHeader, DexVersion};
use crate::pools;

/// A zero-copy, lazy DEX reader.
///
/// `physical` is the original buffer the caller supplied; `header_off` is
/// where the DEX header starts inside it (0 for single-DEX files, the
/// logical offset for DEX-041 containers).
///
/// All offsets inside the DEX (string data, type lists, code items, …) are
/// interpreted against `physical`. The `DexView` does **not** normalise
/// anything into a temporary copy: each accessor reads directly from the
/// borrowed bytes.
pub struct DexView<'a> {
    /// Original buffer.
    pub(crate) physical: &'a [u8],
    /// Offset of the DEX header inside `physical`.
    pub(crate) header_off: usize,
    /// Parsed header.
    pub(crate) header: DexHeader,
}

impl<'a> DexView<'a> {
    /// Parses the DEX header at the start of `bytes`.
    ///
    /// `parse` is O(1): it reads the 0x70-byte header, validates pool
    /// extents, and returns. **No pool is walked and no allocation
    /// proportional to pool counts is performed.**
    pub fn parse(bytes: &'a [u8]) -> Result<Self, DexError> {
        Self::parse_at(bytes, 0)
    }

    /// Parses a logical DEX whose header starts at `header_off` inside
    /// `bytes` (used for DEX-041 containers).
    pub fn parse_at(bytes: &'a [u8], header_off: usize) -> Result<Self, DexError> {
        let header = DexHeader::parse(bytes, header_off)?;
        let file_size = header.file_size as usize;
        if file_size > bytes.len() - header_off {
            return Err(DexError::Truncated {
                needed: header_off + file_size,
                actual: bytes.len(),
            });
        }
        // Bounds-check every pool extent against the logical DEX's absolute
        // extent `header_off..header_off + file_size`. This is O(1) per pool
        // (count + stride arithmetic only — no iteration of pool entries).
        pools::validate_all(&header, file_size, header_off)?;
        Ok(Self {
            physical: bytes,
            header_off,
            header,
        })
    }

    /// Borrows the underlying physical buffer.
    #[inline]
    pub fn physical(&self) -> &'a [u8] {
        self.physical
    }

    /// Borrows the parsed header.
    #[inline]
    pub fn header(&self) -> &DexHeader {
        &self.header
    }

    /// Returns the header offset.
    #[inline]
    pub fn header_off(&self) -> usize {
        self.header_off
    }

    /// Returns the DEX version this view was parsed for.
    #[inline]
    pub fn version(&self) -> DexVersion {
        self.header.version
    }

    /// Iterates over a series of logical DEX headers in a DEX-041 physical
    /// container.
    ///
    /// Mirrors `reference/asc/src/asc_client/dex_container.py::dex041_logical_offsets`:
    /// each subsequent logical header is found by reading
    /// `file_size@header_off + 0x20` and advancing that many bytes. Stops
    /// when the next header would extend past EOF, the magic fails to match,
    /// or `file_size < 0x70`.
    pub fn logical_header_offsets(physical: &[u8]) -> Result<Vec<usize>, DexError> {
        let mut offsets = Vec::new();
        let len = physical.len();
        let mut off = 0usize;
        loop {
            if off + DexHeader::SIZE > len {
                break;
            }
            if &physical[off..off + 8] != b"dex\n041\0" {
                break;
            }
            let file_size = crate::read::read_u32(physical, off + 0x20)? as usize;
            if file_size < DexHeader::SIZE || off + file_size > len {
                break;
            }
            offsets.push(off);
            if file_size == 0 {
                // Guard against an infinite loop if a malicious blob has
                // file_size == 0.
                return Err(DexError::TooManyLogicalDex {
                    count: offsets.len() as u32,
                });
            }
            off += file_size;
            // Cap at a reasonable upper bound.
            if offsets.len() > 1024 {
                return Err(DexError::TooManyLogicalDex {
                    count: offsets.len() as u32,
                });
            }
        }
        if offsets.is_empty() {
            offsets.push(0);
        }
        Ok(offsets)
    }
}
