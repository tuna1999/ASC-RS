//! Bounded raw-DEFLATE inflation.
//!
//! Provides chunked-stream inflation of a single entry's compressed payload
//! into a fresh `Vec<u8>`, with hard caps configurable by the caller.
//!
//! The stream is interpreted as *raw* DEFLATE (no zlib header), matching
//! what ZIP method 8 actually stores. A future post-V2 wave may add the
//! "skip-blocks" optimisation that the Python oracle uses; this engine
//! performs full inflation.

use std::io::Read;

/// Default cap on inflated output per entry: 1 GiB.
///
/// 1 GiB matches the `getclass`/`findrefs` workloads comfortably while
/// preventing a hostile archive from forcing a multi-gigabyte allocation.
pub const DEFAULT_MAX_OUTPUT: usize = 1 << 30;

/// Chunk size used for streaming inflation. The last read of a stream is
/// capped at one byte past the declared uncompressed size, so an
/// over-long stream is rejected after at most one extra byte of output —
/// the declaration (not this chunk) is what bounds the inflate work.
pub const INFLATE_CHUNK: usize = 64 * 1024;

/// Limits that govern inflate output size.
#[derive(Debug, Clone, Copy)]
pub struct InflateLimits {
    /// Maximum number of uncompressed bytes the inflater will produce. A
    /// stream whose declared uncompressed size exceeds this value is
    /// rejected before any allocation; a stream whose actual output crosses
    /// this value mid-flight is rejected with [`crate::ApkError::TooLarge`].
    pub max_output: usize,
}

impl Default for InflateLimits {
    fn default() -> Self {
        InflateLimits {
            max_output: DEFAULT_MAX_OUTPUT,
        }
    }
}

impl InflateLimits {
    /// Construct an `InflateLimits` with a custom output cap. Returns
    /// `None` if `max_output` is zero (the engine always rejects empty
    /// caps because it could not then return any inflated bytes).
    pub const fn with_max_output(max_output: usize) -> Option<Self> {
        if max_output == 0 {
            None
        } else {
            Some(InflateLimits { max_output })
        }
    }
}

/// Inflate a raw DEFLATE slice into a fresh `Vec<u8>` of exactly
/// `expected_len` bytes.
///
/// * `compressed` is the raw (no zlib header) DEFLATE payload.
/// * `expected_len` is the central-directory declared uncompressed size;
///   the result is required to have exactly this length.
/// * `limits` caps the output size; `TooLarge` is returned if the
///   inflater exceeds `limits.max_output` at any point.
///
/// Work bound: the decoder is never asked to produce more than
/// `expected_len + 1` bytes, so a lying declaration bounds this call's
/// inflate work — callers that reserve the declared size are honest.
///
/// Stream corruption yields [`crate::ApkError::Deflate`]. Length
/// mismatch yields [`crate::ApkError::SizeMismatch`].
pub(crate) fn inflate_into_vec(
    compressed: &[u8],
    expected_len: usize,
    limits: InflateLimits,
) -> Result<Vec<u8>, crate::ApkError> {
    // Reject immediately if declared uncompressed size exceeds the cap,
    // before allocating the output buffer.
    if expected_len > limits.max_output {
        return Err(crate::ApkError::TooLarge {
            produced: expected_len as u64,
            cap: limits.max_output as u64,
        });
    }

    let mut out: Vec<u8> = Vec::with_capacity(expected_len);
    let mut decoder = flate2::read::DeflateDecoder::new(compressed);

    // Chunked loop that fails the moment the stream produces more than
    // the central directory declared. `expected_len <= limits.max_output`
    // was checked above, so this is the tighter bound. Each read is
    // capped at `expected_len + 1` bytes of output, so the total output
    // the decoder is ever asked to produce is bounded by the declaration
    // plus ONE byte — not one 64 KiB chunk. That is what makes the
    // declared-size reservations in `asc_core::budget` and
    // `asc_core::xapk` charge the real inflate work: a container of
    // members that each declare 0 bytes and expand to megabytes can no
    // longer spend 64 KiB of uncharged inflate work per member.
    //
    // `SizeMismatch.produced` is therefore exactly `declared + 1` when
    // the stream is longer than declared (and the count observed at the
    // stop point, never the full stream length).
    let mut chunk = vec![0u8; INFLATE_CHUNK];
    loop {
        // `out.len() <= expected_len` holds by construction, so this is
        // at least 1; saturating so a bogus `expected_len == usize::MAX`
        // cannot overflow into a panic.
        let cap = INFLATE_CHUNK.min(expected_len.saturating_sub(out.len()).saturating_add(1));
        let n = match decoder.read(&mut chunk[..cap]) {
            Ok(n) => n,
            Err(e) => return Err(crate::ApkError::Deflate(e.to_string())),
        };
        if n == 0 {
            break;
        }
        // Cannot overflow in practice (`out.len() <= expected_len`), but
        // saturating so a future caller passing a bogus cap stays a clean
        // error rather than a debug-overflow panic on untrusted input.
        let produced = out.len().saturating_add(n);
        if produced > expected_len {
            return Err(crate::ApkError::SizeMismatch {
                declared: expected_len as u64,
                produced: produced as u64,
            });
        }
        out.extend_from_slice(&chunk[..n]);
    }

    if out.len() != expected_len {
        return Err(crate::ApkError::SizeMismatch {
            declared: expected_len as u64,
            produced: out.len() as u64,
        });
    }
    Ok(out)
}

/// Inflate at most `max` leading bytes of a raw DEFLATE slice without
/// reading the rest of the stream. Returns the bytes plus `true` when the
/// stream ended within `max` (i.e. the prefix is the whole entry).
/// Corruption after the prefix is intentionally not detected.
pub(crate) fn inflate_prefix(
    compressed: &[u8],
    max: usize,
) -> Result<(Vec<u8>, bool), crate::ApkError> {
    let mut decoder = flate2::read::DeflateDecoder::new(compressed);
    let mut out = Vec::new();
    let err = |e: std::io::Error| crate::ApkError::Deflate(e.to_string());
    (&mut decoder)
        .take(max as u64)
        .read_to_end(&mut out)
        .map_err(err)?;
    let mut probe = [0u8; 1];
    let complete = out.len() < max || decoder.read(&mut probe).map_err(err)? == 0;
    Ok((out, complete))
}

/// Verify the CRC-32 of `data` against `expected`. Used by the optional
/// `read_entry_verified` path; cheap (crc32fast is ~30 GB/s on modern CPUs).
pub(crate) fn verify_crc32(data: &[u8], expected: u32) -> bool {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize() == expected
}
