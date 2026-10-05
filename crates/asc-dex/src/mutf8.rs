//! Modified UTF-8 (MUTF-8) decoder used by DEX string data.
//!
//! MUTF-8 differs from standard UTF-8 in two ways:
//! - the code point U+0000 is encoded as the two-byte sequence `0xC0 0x80`
//!   instead of `0x00` (because a NUL byte terminates the string),
//! - supplementary characters (U+10000 and above) are encoded as a six-byte
//!   sequence carrying the UTF-16 surrogate pair rather than the standard
//!   4-byte UTF-8 form.
//!
//! Standard UTF-8 1-, 2-, and 3-byte sequences follow the usual encoding.
//!
//! `decode_lossy` is total: every byte sequence yields a `String` (or returns
//! the borrowed slice when no replacement happened). Invalid sequences are
//! replaced with U+FFFD and decoding resumes at the next plausible byte.

use std::borrow::Cow;

/// Maximum number of MUTF-8 bytes the decoder is willing to scan for the
/// mandatory `0x00` terminator in `find_terminator`. Past this we assume the
/// record is malformed and surface a
/// [`crate::DexError::StringNotTerminated`].
pub const MAX_STRING_SCAN: usize = 1 << 20; // 1 MiB — far larger than any real DEX string

/// Locates the mandatory NUL byte that terminates a DEX string record,
/// starting at `start` (which should point at the first MUTF-8 byte after
/// the `utf16_len` ULEB128).
///
/// MUTF-8 never contains `0x00` as a payload byte (U+0000 is the two-byte
/// sequence `0xC0 0x80`), so a linear scan is safe and exact.
///
/// Returns `Ok(n)` with `n >= start` when a NUL terminator is found, or
/// [`crate::DexError::StringNotTerminated`] when none appears within
/// [`MAX_STRING_SCAN`] bytes or before the buffer ends.
pub fn find_terminator(bytes: &[u8], start: usize) -> Result<usize, crate::DexError> {
    let len = bytes.len();
    let limit = (start + MAX_STRING_SCAN).min(len);
    let mut i = start;
    while i < limit {
        if bytes[i] == 0 {
            return Ok(i);
        }
        i += 1;
    }
    Err(crate::DexError::StringNotTerminated {
        off: start,
        span: limit - start,
    })
}

/// Pushes a single Unicode code point encoded as UTF-8 into `out`.
#[inline]
fn push_cp(out: &mut Vec<u8>, cp: u32) {
    if let Some(ch) = char::from_u32(cp) {
        let mut buf = [0u8; 4];
        let s = ch.encode_utf8(&mut buf);
        out.extend_from_slice(s.as_bytes());
    } else {
        out.extend_from_slice("\u{FFFD}".as_bytes());
    }
}

/// Pushes the U+FFFD replacement character.
#[inline]
fn push_repl(out: &mut Vec<u8>) {
    out.extend_from_slice("\u{FFFD}".as_bytes());
}

/// Output-buffer sizing hint for [`decode_lossy`].
///
/// `utf16_len_hint` is read straight from the DEX `string_data_item` and is
/// never checked against the payload, so it is attacker-controlled: a
/// two-byte string may declare `u32::MAX` units. Trusting it would reserve
/// gigabytes per decoded string and break the "bounded memory" contract, so
/// it is capped by what the input could actually produce — every input byte
/// expands to at most 3 output bytes (a U+FFFD replacement).
#[inline]
fn capacity_hint(bytes_len: usize, utf16_len_hint: u32) -> usize {
    (utf16_len_hint as usize).min(bytes_len.saturating_mul(3))
}

/// Decodes a MUTF-8 byte slice into UTF-8 text, replacing invalid sequences
/// with U+FFFD. The returned `Cow` borrows the original slice when no
/// replacements were needed (the common ASCII case), and allocates a fresh
/// `String` only when replacement actually occurred.
///
/// `utf16_len_hint` is informational only — DEX stores the UTF-16 code unit
/// length, but we use it as a sizing hint for the output buffer rather than
/// for verification. It is *not* validated by the caller, so it is bounded
/// by [`capacity_hint`] before it reaches the allocator.
pub fn decode_lossy<'a>(bytes: &'a [u8], utf16_len_hint: u32) -> Cow<'a, str> {
    // Fast path: pure ASCII (no leading zero anywhere, all bytes < 0x80).
    let mut all_ascii = true;
    for &b in bytes {
        if b == 0 || b >= 0x80 {
            all_ascii = false;
            break;
        }
    }
    if all_ascii {
        // Every byte < 0x80 means `bytes` is valid UTF-8 by construction.
        if let Ok(s) = std::str::from_utf8(bytes) {
            return Cow::Borrowed(s);
        }
        // Should be unreachable; fall through to the slow path.
    }

    let mut out: Vec<u8> = Vec::with_capacity(capacity_hint(bytes.len(), utf16_len_hint));
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == 0 {
            // terminator (shouldn't appear inside payload)
            break;
        }
        if b < 0x80 {
            out.push(b);
            i += 1;
        } else if b == 0xC0 && i + 1 < bytes.len() && bytes[i + 1] == 0x80 {
            // MUTF-8 encoded NUL
            out.push(0);
            i += 2;
        } else if (b & 0xE0) == 0xC0 {
            // 2-byte sequence
            if i + 1 >= bytes.len() || (bytes[i + 1] & 0xC0) != 0x80 {
                push_repl(&mut out);
                i += 1;
                continue;
            }
            let cp = (((b & 0x1F) as u32) << 6) | ((bytes[i + 1] & 0x3F) as u32);
            if cp < 0x80 {
                // overlong
                push_repl(&mut out);
            } else {
                push_cp(&mut out, cp);
            }
            i += 2;
        } else if (b & 0xF0) == 0xE0 {
            // Could be a 3-byte sequence OR the leading byte of a MUTF-8
            // 6-byte supplementary sequence.
            if b == 0xED
                && i + 5 < bytes.len()
                && (bytes[i + 1] & 0xF0) == 0xA0
                && (bytes[i + 2] & 0xC0) == 0x80
                && bytes[i + 3] == 0xED
                && (bytes[i + 4] & 0xF0) == 0xB0
                && (bytes[i + 5] & 0xC0) == 0x80
            {
                // 6-byte MUTF-8 supplementary encoded as UTF-16 surrogate pair.
                let hi = 0xD800u32
                    | ((((bytes[i + 1] & 0x0F) as u32) << 6) | ((bytes[i + 2] & 0x3F) as u32));
                let lo = 0xDC00u32
                    | ((((bytes[i + 4] & 0x0F) as u32) << 6) | ((bytes[i + 5] & 0x3F) as u32));
                let cp = 0x10000u32 + (((hi & 0x3FF) << 10) | (lo & 0x3FF));
                push_cp(&mut out, cp);
                i += 6;
            } else {
                // Plain 3-byte sequence.
                if i + 2 >= bytes.len()
                    || (bytes[i + 1] & 0xC0) != 0x80
                    || (bytes[i + 2] & 0xC0) != 0x80
                {
                    push_repl(&mut out);
                    i += 1;
                    continue;
                }
                let cp = (((b & 0x0F) as u32) << 12)
                    | ((((bytes[i + 1] & 0x3F) as u32) << 6) | ((bytes[i + 2] & 0x3F) as u32));
                if (0xD800..=0xDFFF).contains(&cp) || cp < 0x800 {
                    // surrogate range or overlong
                    push_repl(&mut out);
                } else {
                    push_cp(&mut out, cp);
                }
                i += 3;
            }
        } else {
            // Invalid leading byte.
            push_repl(&mut out);
            i += 1;
        }
    }
    match String::from_utf8(out) {
        Ok(s) => Cow::Owned(s),
        // Unreachable: we only pushed bytes via encode_utf8 or single NUL.
        Err(_) => Cow::Borrowed(""),
    }
}

/// Decodes MUTF-8 into raw UTF-16 code units, keeping unpaired
/// surrogates and U+0000 intact (what the JVM `String` sees). Malformed
/// bytes become U+FFFD.
pub fn to_utf16(bytes: &[u8]) -> Vec<u16> {
    let mut out = Vec::with_capacity(bytes.len());
    let cont = |i: usize| {
        bytes
            .get(i)
            .filter(|&&b| b & 0xC0 == 0x80)
            .map(|&b| (b & 0x3F) as u16)
    };
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == 0 {
            break;
        }
        if b < 0x80 {
            out.push(b as u16);
            i += 1;
        } else if b & 0xE0 == 0xC0
            && let Some(c1) = cont(i + 1)
        {
            out.push(((b & 0x1F) as u16) << 6 | c1);
            i += 2;
        } else if b & 0xF0 == 0xE0
            && let (Some(c1), Some(c2)) = (cont(i + 1), cont(i + 2))
        {
            out.push(((b & 0x0F) as u16) << 12 | c1 << 6 | c2);
            i += 3;
        } else {
            out.push(0xFFFD);
            i += 1;
        }
    }
    out
}

/// Encodes UTF-16 code units as MUTF-8 (no terminator): U+0000 → `C0 80`,
/// every other unit (surrogates included) as its own 1–3 byte sequence.
pub fn from_utf16(units: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(units.len());
    for &u in units {
        match u {
            0x0001..=0x007F => out.push(u as u8),
            0x0000 | 0x0080..=0x07FF => {
                out.extend_from_slice(&[0xC0 | (u >> 6) as u8, 0x80 | (u & 0x3F) as u8])
            }
            _ => out.extend_from_slice(&[
                0xE0 | (u >> 12) as u8,
                0x80 | ((u >> 6) & 0x3F) as u8,
                0x80 | (u & 0x3F) as u8,
            ]),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_passthrough() {
        let s = decode_lossy(b"hello", 5);
        assert!(matches!(s, Cow::Borrowed(_)));
        assert_eq!(s.as_ref(), "hello");
    }

    #[test]
    fn two_byte_seq() {
        // U+00E9 (é) = C3 A9
        let s = decode_lossy(&[0xC3, 0xA9], 1);
        assert_eq!(s.as_ref(), "é");
    }

    #[test]
    fn three_byte_seq() {
        // U+20AC (€) = E2 82 AC
        let s = decode_lossy(&[0xE2, 0x82, 0xAC], 1);
        assert_eq!(s.as_ref(), "€");
    }

    #[test]
    fn encoded_nul() {
        // U+0000 encoded as C0 80 — must yield a single NUL char in the string.
        let s = decode_lossy(&[b'a', 0xC0, 0x80, b'b'], 4);
        assert_eq!(s.as_ref(), "a\x00b");
    }

    #[test]
    fn truncated_two_byte() {
        // C3 alone — invalid.
        let s = decode_lossy(&[0xC3], 1);
        assert_eq!(s.as_ref(), "\u{FFFD}");
    }

    #[test]
    fn mutf8_encoded_nul_as_c080() {
        // C0 80 here is interpreted as the MUTF-8 encoded NUL (per spec).
        let s = decode_lossy(&[0xC0, 0x80], 1);
        assert_eq!(s.as_ref(), "\u{0000}");
    }

    #[test]
    fn surrogate_pair_mutf8() {
        // U+1F600 = 😀, encoded in MUTF-8 as the 6-byte surrogate form.
        // high surrogate 0xD83D 0xDE00: 0xED 0xA0 0xBD 0xED 0xB8 0x80
        let s = decode_lossy(&[0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80], 2);
        assert_eq!(s.as_ref(), "😀");
    }

    #[test]
    fn lone_high_surrogate_replaced() {
        // ED A0 BD — high surrogate with no matching low surrogate: invalid.
        let s = decode_lossy(&[0xED, 0xA0, 0xBD], 1);
        assert_eq!(s.as_ref(), "\u{FFFD}");
    }

    #[test]
    fn utf16_round_trip_keeps_nul_and_lone_surrogates() {
        let units = [0x0000, 0x0041, 0x00E9, 0xD83D, 0x20AC, 0xDE00, 0xFFFF];
        let enc = from_utf16(&units);
        assert_eq!(&enc[..2], &[0xC0, 0x80]);
        assert!(!enc.contains(&0));
        assert_eq!(to_utf16(&enc), units);
    }

    /// A hostile `utf16_len` cannot size the output buffer: it is read
    /// straight from the file and never validated against the payload, so
    /// the reservation is capped by what the input could expand to. Before
    /// the clamp this asked the allocator for `u32::MAX` bytes for a
    /// two-byte string.
    #[test]
    fn capacity_hint_is_bounded_by_the_payload() {
        // Two input bytes → at most 6 output bytes, whatever the hint says.
        assert_eq!(capacity_hint(2, u32::MAX), 6);
        assert_eq!(capacity_hint(0, u32::MAX), 0);
        // A plausible, smaller hint is still honoured as the tighter bound.
        assert_eq!(capacity_hint(64, 8), 8);
        // Saturating: a huge payload cannot overflow the multiply.
        assert_eq!(capacity_hint(usize::MAX, u32::MAX), u32::MAX as usize);
    }

    /// The clamp changes only the reservation, never the decoded text.
    #[test]
    fn hostile_utf16_len_decodes_normally() {
        let s = decode_lossy(&[0xC3, 0xA9], u32::MAX);
        assert_eq!(s.as_ref(), "é");
    }
}
