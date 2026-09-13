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

/// Chunk size used for streaming inflation. Smaller than the cap so that
/// `TooLarge` is detected promptly (within at most one extra chunk worth
/// of memory growth past the cap).
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

    // Cap-aware loop: read up to INFLATE_CHUNK bytes at a time and stop as
    // soon as the buffer exceeds `max_output`.
    let mut chunk = vec![0u8; INFLATE_CHUNK];
    loop {
        let cap = INFLATE_CHUNK.min(chunk.len());
        let n = match decoder.read(&mut chunk[..cap]) {
            Ok(n) => n,
            Err(e) => return Err(crate::ApkError::Deflate(e.to_string())),
        };
        if n == 0 {
            break;
        }
        if out.len() + n > limits.max_output {
            return Err(crate::ApkError::TooLarge {
                produced: (out.len() + n) as u64,
                cap: limits.max_output as u64,
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

/// Verify the CRC-32 of `data` against `expected`. Used by the optional
/// `read_entry_verified` path; cheap (crc32fast is ~30 GB/s on modern CPUs).
pub(crate) fn verify_crc32(data: &[u8], expected: u32) -> bool {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize() == expected
}
