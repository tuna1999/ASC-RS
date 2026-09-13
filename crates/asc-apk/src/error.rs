//! Error type for `asc-apk`.
//!
//! Every offset read from the file is bounds-checked before use; every parse
//! path returns `Err` on malformed input rather than panicking.

use std::io;

/// Errors produced by parsing an APK/ZIP container or extracting an entry.
///
/// `thiserror` derives `Display` (a single-line message) and `From<io::Error>`
/// for ergonomic propagation from the filesystem.
#[derive(Debug, thiserror::Error)]
pub enum ApkError {
    /// File is not a ZIP/APK: EOCD signature was not found within the trailing
    /// 65557 bytes (comment + 22 fixed bytes).
    #[error("not a ZIP/APK file: EOCD signature not found")]
    NotAZip,

    /// File truncated: an offset/size referenced from a header would read past
    /// EOF or beyond the central directory window.
    #[error("ZIP/APK truncated: {0}")]
    Truncated(&'static str),

    /// Feature not supported by this engine (e.g. encrypted entry, unsupported
    /// compression method, missing ZIP64 locator where one is required).
    #[error("unsupported ZIP/APK feature: {0}")]
    Unsupported(&'static str),

    /// Local header signature did not match `PK\x03\x04` at the offset
    /// recorded in the central directory. Captures the offending offset.
    #[error("bad local header signature at offset {at}")]
    BadSignature {
        /// Absolute offset in the archive where the bad signature was found.
        at: u64,
    },

    /// Inflate produced a different number of bytes than the central
    /// directory's declared uncompressed size.
    #[error("inflated size mismatch: declared {declared}, produced {produced}")]
    SizeMismatch {
        /// Compressed/uncompressed size field from the central directory.
        declared: u64,
        /// Number of bytes actually produced by the inflate stream.
        produced: u64,
    },

    /// Inflation output exceeded the configured `InflateLimits::max_output`.
    #[error("inflated output exceeds cap: produced {produced} bytes (cap {cap})")]
    TooLarge {
        /// Bytes produced so far when the cap was exceeded.
        produced: u64,
        /// Configured cap (`max_output`).
        cap: u64,
    },

    /// Underlying DEFLATE stream is corrupt / truncated / has bad checksum.
    #[error("deflate stream error: {0}")]
    Deflate(String),

    /// Caller asked for an entry by exact name but it is not present.
    #[error("entry not found: {0}")]
    EntryNotFound(String),

    /// Filesystem / IO failure (open, stat, mmap).
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}
