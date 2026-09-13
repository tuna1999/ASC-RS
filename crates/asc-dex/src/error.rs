//! Errors returned by `asc-dex`.
//!
//! All public accessors that read untrusted DEX bytes return
//! `Result<_, DexError>` instead of panicking. The variants below let
//! callers distinguish structural problems (`BadVersion`, `TruncatedHeader`,
//! `PoolOutOfBounds`) from corrupted payloads (`UlebOverflow`,
//! `BadMutf8`, `BadEncodedValue`, …).
//!
//! No variant is constructed from user data without a bounds check.

use thiserror::Error;

/// Errors produced while parsing or accessing a DEX file.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DexError {
    /// Input buffer is too small to contain a DEX header (0x70 bytes) or a
    /// pool region, or a sub-structure (string, code_item, …) was truncated.
    #[error("truncated input: need {needed} bytes, have {actual}")]
    Truncated { needed: usize, actual: usize },

    /// Header magic was not one of the supported `dex\n0XX\x00` versions
    /// (035 / 037 / 038 / 039 / 040 / 041).
    #[error("unsupported or unknown DEX magic: {0:?}")]
    BadVersion([u8; 8]),

    /// A header field is inconsistent: e.g. `header_size != 0x70`,
    /// `endian_tag != 0x12345678`, or a pool has `count > 0` but `off == 0`.
    #[error("invalid header field at 0x{off:02x}: {message}")]
    InvalidHeader { off: usize, message: &'static str },

    /// A pool `[off, off + count*stride)` extends beyond the physical buffer.
    #[error(
        "pool {pool} out of bounds: off=0x{off:x}, count={count}, stride={stride}, file={file}"
    )]
    PoolOutOfBounds {
        pool: &'static str,
        off: usize,
        count: u32,
        stride: usize,
        file: usize,
    },

    /// A typed index is not in `[0, count)` for the relevant pool.
    #[error("index {idx} out of bounds for pool {pool} (count={count})")]
    IndexOutOfBounds {
        pool: &'static str,
        idx: u32,
        count: u32,
    },

    /// A pointer stored in a DEX structure (string `data_off`, class
    /// `class_data_off`, etc.) does not point inside the physical file.
    #[error("offset 0x{off:x} out of bounds (file size {file})")]
    OffsetOutOfBounds { off: usize, file: usize },

    /// A string record does not end with the mandatory `0x00` terminator.
    #[error("string data at offset 0x{off:x} has no NUL terminator within {span} bytes")]
    StringNotTerminated { off: usize, span: usize },

    /// A `uleb128` integer is malformed (truncated, too long, or > u32::MAX).
    #[error("uleb128 decode failed: {message}")]
    Uleb { message: &'static str },

    /// A `sleb128` integer is malformed (truncated, too long).
    #[error("sleb128 decode failed: {message}")]
    Sleb { message: &'static str },

    /// An MUTF-8 byte sequence is irrecoverable even for the lossy decoder
    /// (should not happen: `decode_lossy` is total).
    #[error("mutf8 decode failed at offset {off}")]
    BadMutf8 { off: usize },

    /// `class_data_item` uleb index delta overflowed the cumulative counter.
    #[error("class_data uleb delta overflow at offset 0x{off:x}")]
    ClassDataDeltaOverflow { off: usize },

    /// `encoded_value` / `encoded_annotation` recursion exceeded the depth
    /// cap (default 64). Indicates a malicious or corrupt payload.
    #[error("encoded_value depth exceeded {max}")]
    EncodedValueDepthExceeded { max: u8 },

    /// A sub-structure length / count is internally inconsistent
    /// (e.g. `type_list.size` larger than the remaining bytes).
    #[error("invalid length at offset 0x{off:x}: {message}")]
    InvalidLength { off: usize, message: &'static str },

    /// A `try_item.handler_off` does not lie inside the `encoded_catch_handler_list`.
    #[error(
        "catch handler offset 0x{off:x} outside encoded_catch_handler_list ({start:x}..{end:x})"
    )]
    BadCatchHandlerOffset {
        off: usize,
        start: usize,
        end: usize,
    },

    /// A `debug_info_item` opcode stream is truncated or malformed.
    #[error("bad debug_info opcode 0x{op:02x} at offset 0x{off:x}: {message}")]
    BadDebugOpcode {
        op: u8,
        off: usize,
        message: &'static str,
    },

    /// `code_off` is not 4-byte aligned.
    #[error("code_off 0x{off:x} is not 4-byte aligned")]
    MisalignedCodeItem { off: usize },

    /// Loop / container guard: e.g. 041 traversal visited more logical DEX
    /// headers than reasonable.
    #[error("too many logical DEX headers ({count}); possible infinite loop in container")]
    TooManyLogicalDex { count: u32 },

    /// Catch-all for unexpected invariant violations. New variants should be
    /// preferred; this exists so we never silently panic on malformed input.
    #[error("malformed DEX: {0}")]
    Malformed(&'static str),
}

impl DexError {
    /// Convenience constructor for "needed N bytes, only have M" reports that
    /// many call sites want to build when a slice index goes out of range.
    #[inline]
    pub const fn truncated(needed: usize, actual: usize) -> Self {
        DexError::Truncated { needed, actual }
    }
}
