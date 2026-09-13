//! Public types representing ZIP/APK entries and their extracted bytes.

/// Compression method recorded in the central directory entry.
///
/// Only the values produced by `apksigner`/the Android build toolchain
/// (plus `Stored`, used for uncompressed resources) are supported by this
/// engine. Any other method raises [`crate::ApkError::Unsupported`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Compression {
    /// Method 0: entry bytes are stored verbatim (no compression).
    Stored,
    /// Method 8: raw DEFLATE stream (no zlib header).
    Deflated,
}

impl Compression {
    /// Decode the 16-bit compression method field from a ZIP record.
    ///
    /// Returns `Ok(Stored)` for `0`, `Ok(Deflated)` for `8`, and
    /// `Err(method)` for any other value (callers map to
    /// [`crate::ApkError::Unsupported`]).
    pub(crate) fn from_method(method: u16) -> Result<Self, u16> {
        match method {
            0 => Ok(Compression::Stored),
            8 => Ok(Compression::Deflated),
            other => Err(other),
        }
    }
}

/// One central-directory entry in the archive.
///
/// The struct is `Send + Sync` (it is a value type) and is `Clone` so callers
/// can keep references to entries returned from `Apk::dex_entries` without
/// lifetime gymnastics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexEntry {
    /// Entry name as stored in the ZIP central directory (UTF-8 lossy when
    /// the language-encoding flag was clear and the bytes were not valid
    /// UTF-8). Never empty.
    pub name: String,

    /// Compression method of the entry data.
    pub method: Compression,

    /// Compressed payload size, in bytes. Resolved through ZIP64 placeholders
    /// if needed.
    pub compressed_size: u64,

    /// Uncompressed payload size, in bytes. Resolved through ZIP64 placeholders
    /// if needed.
    pub uncompressed_size: u64,

    /// CRC-32 of the uncompressed data, recorded in the central directory.
    pub crc32: u32,

    /// Absolute offset (from start of archive) of the entry's local file
    /// header. The data payload starts at
    /// `local_header_offset + 30 + name_len + extra_len` (computed at read
    /// time; the local-header `extra_len` may differ from the central one).
    pub local_header_offset: u64,
}

/// Bytes extracted for an entry: either a borrowed slice (for `Stored`
/// entries, zero-copy) or an owned `Vec<u8>` (for inflated `Deflated`
/// entries).
///
/// `EntryBytes::as_slice` always yields a `&[u8]` view; the type also
/// derefs to `[u8]` for ergonomic indexing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryBytes<'a> {
    /// Bytes are borrowed directly from the backing mmap or buffer. Lifetime
    /// is tied to the `Apk`/`ZipView` that produced them.
    Borrowed(&'a [u8]),
    /// Bytes were inflated into a freshly allocated `Vec<u8>`.
    Inflated(Vec<u8>),
}

impl<'a> EntryBytes<'a> {
    /// Borrow the entry's bytes regardless of storage variant.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            EntryBytes::Borrowed(b) => b,
            EntryBytes::Inflated(v) => v.as_slice(),
        }
    }

    /// Returns the length of the payload in bytes.
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Whether the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

impl<'a> AsRef<[u8]> for EntryBytes<'a> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a> std::ops::Deref for EntryBytes<'a> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a> From<&'a [u8]> for EntryBytes<'a> {
    fn from(b: &'a [u8]) -> Self {
        EntryBytes::Borrowed(b)
    }
}

impl<'a> From<Vec<u8>> for EntryBytes<'a> {
    fn from(v: Vec<u8>) -> Self {
        EntryBytes::Inflated(v)
    }
}
