//! Error types surfaced by `asc-rebuild`.

use thiserror::Error;

/// All failures that can occur while reconstructing a minimal standalone DEX.
#[derive(Debug, Error)]
pub enum RebuildError {
    /// The target class descriptor was not present in the source DEX.
    #[error("class descriptor {0:?} not found in source DEX")]
    ClassNotFound(String),

    /// A malformed descriptor was provided (not a valid DEX descriptor
    /// shape, e.g. empty, missing leading `L`, or missing trailing `;`).
    #[error("invalid descriptor {0:?}: {1}")]
    BadDescriptor(String, &'static str),

    /// The 041 container path was taken without explicit per-logical-DEX
    /// resolution. `rebuild` always works on one `DexView`; callers must
    /// split containers themselves.
    #[error("rebuild requires a non-041 single-DEX view (got version {0:?})")]
    UnsupportedVersion(String),

    /// The target class's `class_def` row references an offset that the
    /// view could not resolve.
    #[error("source DEX rejected by asc-dex: {0}")]
    Source(#[from] asc_dex::DexError),

    /// `bytecode` reference traversal failed. Wraps the asc-bytecode error
    /// into a string to keep `RebuildError` dependency-light at API edges.
    #[error("bytecode ref traversal failed at code off {off}: {message}")]
    BytecodeRef { off: u32, message: String },

    /// `RefWalker` walked past `insns_units`; refactor or malformed code.
    #[error("bytecode walker truncated at code off {off}")]
    BytecodeTruncated { off: u32 },

    /// `class_data` uleb sequence overflowed the 32-bit accumulator.
    #[error("class_data delta overflow at off {off}")]
    ClassDataOverflow { off: u32 },

    /// `encoded_value` traversal exceeded the depth cap.
    #[error("encoded_value recursion exceeded {max} at off {off}")]
    EncodedValueDepth { off: u32, max: u8 },

    /// Pool size cap exceeded while collecting dependencies.
    #[error("pool {pool} would grow to {count}, exceeds cap {cap}")]
    PoolCap {
        pool: &'static str,
        count: u32,
        cap: u32,
    },

    /// Internal invariant violation: an internal table missed an entry that
    /// should be present (e.g. a referenced pool idx was never queued).
    #[error("internal inconsistency: {0}")]
    Internal(&'static str),

    /// I/O while loading the source corpus.
    #[error("i/o: {0}")]
    Io(String),
}

impl From<std::io::Error> for RebuildError {
    fn from(e: std::io::Error) -> Self {
        RebuildError::Io(e.to_string())
    }
}
