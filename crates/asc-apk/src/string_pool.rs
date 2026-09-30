//! `ResStringPool` decoder shared by binary XML (`asc-manifest`) and
//! `resources.arsc` (`asc-resources`).
//!
//! Follows AOSP `ResStringPool::stringAt`: strings are addressed through
//! the offset table, UTF-16 lengths use the extended 32-bit form when the
//! high bit of the first word is set (`((w0 & 0x7fff) << 16) | w1`), and
//! UTF-8 pools carry a char length then a byte length, each 1 or 2 bytes.
//! Every read is bounded by the chunk end. A slot that cannot be decoded
//! becomes `""` and is counted in [`Pool::bad_slots`]: the framework decodes
//! lazily, so unreferenced slots may hold garbage. Structural problems
//! (bad extents, caps) are errors.

const UTF8_FLAG: u32 = 1 << 8;
/// Offset of the pool-specific fields from the chunk start.
const BODY_OFF: usize = 8;

/// Caller-chosen caps.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_count: u32,
    /// Total decoded bytes across all strings.
    pub max_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolError {
    /// A read or extent ran past the chunk.
    Truncated(String),
    /// Structurally invalid or over a cap.
    Bad(String),
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolError::Truncated(s) | PoolError::Bad(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for PoolError {}

#[derive(Debug, Clone, Default)]
pub struct Pool {
    pub strings: Vec<String>,
    /// Slots that failed to decode and were replaced by `""`.
    pub bad_slots: usize,
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(off..off.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(off..off.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// Parse the pool whose chunk spans `chunk_start..chunk_end` of `bytes`.
pub fn parse(
    bytes: &[u8],
    chunk_start: usize,
    chunk_end: usize,
    limits: Limits,
) -> Result<Pool, PoolError> {
    if chunk_end > bytes.len() || chunk_start > chunk_end {
        return Err(PoolError::Truncated("string pool extent".into()));
    }
    let b = &bytes[..chunk_end];
    let chunk_size = chunk_end - chunk_start;
    let body = chunk_start + BODY_OFF;
    let hdr = |i: usize| u32_at(b, body + 4 * i);
    let (Some(count), Some(_styles), Some(flags), Some(strings_start), Some(_)) =
        (hdr(0), hdr(1), hdr(2), hdr(3), hdr(4))
    else {
        return Err(PoolError::Truncated(
            "string pool header overruns EOF".into(),
        ));
    };
    if count > limits.max_count {
        return Err(PoolError::Bad(format!(
            "string pool count {count} exceeds cap"
        )));
    }
    if strings_start as usize > chunk_size {
        return Err(PoolError::Bad(format!(
            "stringsStart {strings_start} > chunk_size {chunk_size}"
        )));
    }
    let offsets = body + 20;
    let offsets_end = (count as usize)
        .checked_mul(4)
        .and_then(|n| offsets.checked_add(n))
        .filter(|&e| e <= chunk_end)
        .ok_or_else(|| PoolError::Truncated("string offset table".into()))?;
    let base = chunk_start + strings_start as usize;
    let utf8 = flags & UTF8_FLAG != 0;

    let mut pool = Pool {
        strings: Vec::with_capacity(count as usize),
        bad_slots: 0,
    };
    let mut total: u64 = 0;
    for (i, off) in (offsets..offsets_end).step_by(4).enumerate() {
        let rel = u32_at(b, off).unwrap_or(0) as usize;
        let s = match if utf8 {
            utf8_at(b, base.saturating_add(rel))
        } else {
            utf16_at(b, base.saturating_add(rel))
        } {
            Some(s) => s,
            None => {
                pool.bad_slots += 1;
                String::new()
            }
        };
        total = total.saturating_add(s.len() as u64);
        if total > limits.max_bytes {
            return Err(PoolError::Bad(format!(
                "decoded string pool exceeds cap at index {i}"
            )));
        }
        pool.strings.push(s);
    }
    Ok(pool)
}

fn utf16_at(b: &[u8], mut pos: usize) -> Option<String> {
    let w0 = u16_at(b, pos)? as usize;
    pos += 2;
    let chars = if w0 & 0x8000 != 0 {
        let w1 = u16_at(b, pos)? as usize;
        pos += 2;
        ((w0 & 0x7fff) << 16) | w1
    } else {
        w0
    };
    let end = pos.checked_add(chars.checked_mul(2)?)?;
    // payload plus the u16 NUL terminator must stay inside the chunk
    if end.checked_add(2)? > b.len() {
        return None;
    }
    let units = b[pos..end]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]));
    Some(
        char::decode_utf16(units)
            .map(|r| r.unwrap_or('\u{FFFD}'))
            .collect(),
    )
}

/// AOSP `decodeLength` for UTF-8 pools: 1 byte, or 2 bytes when bit 7 is set.
fn len8(b: &[u8], pos: &mut usize) -> Option<usize> {
    let b0 = *b.get(*pos)? as usize;
    *pos += 1;
    if b0 & 0x80 == 0 {
        return Some(b0);
    }
    let b1 = *b.get(*pos)? as usize;
    *pos += 1;
    Some(((b0 & 0x7f) << 8) | b1)
}

fn utf8_at(b: &[u8], mut pos: usize) -> Option<String> {
    let _chars = len8(b, &mut pos)?;
    let n = len8(b, &mut pos)?;
    let end = pos.checked_add(n)?;
    if end.checked_add(1)? > b.len() {
        return None;
    }
    Some(String::from_utf8_lossy(&b[pos..end]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIM: Limits = Limits {
        max_count: 1 << 20,
        max_bytes: 1 << 20,
    };

    /// Build a pool chunk from raw pre-encoded string bodies.
    fn pool(utf8: bool, bodies: &[Vec<u8>]) -> Vec<u8> {
        let count = bodies.len() as u32;
        let strings_start = 28 + 4 * count;
        let mut data = Vec::new();
        let mut offs = Vec::new();
        for b in bodies {
            offs.push(data.len() as u32);
            data.extend_from_slice(b);
        }
        while data.len() % 4 != 0 {
            data.push(0);
        }
        let size = strings_start + data.len() as u32;
        let mut v = Vec::new();
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&28u16.to_le_bytes());
        v.extend_from_slice(&size.to_le_bytes());
        v.extend_from_slice(&count.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&(if utf8 { UTF8_FLAG } else { 0 }).to_le_bytes());
        v.extend_from_slice(&strings_start.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        for o in offs {
            v.extend_from_slice(&o.to_le_bytes());
        }
        v.extend_from_slice(&data);
        v
    }

    fn u16s(s: &str) -> Vec<u8> {
        let u: Vec<u16> = s.encode_utf16().collect();
        let mut v = (u.len() as u16).to_le_bytes().to_vec();
        for x in u {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v.extend_from_slice(&[0, 0]);
        v
    }

    #[test]
    fn utf16_and_utf8_roundtrip() {
        let c = pool(false, &[u16s("héllo"), u16s("")]);
        let p = parse(&c, 0, c.len(), LIM).unwrap();
        assert_eq!(p.strings, ["héllo", ""]);
        let u8b = |s: &str| {
            let mut v = vec![s.chars().count() as u8, s.len() as u8];
            v.extend_from_slice(s.as_bytes());
            v.push(0);
            v
        };
        let c = pool(true, &[u8b("aé")]);
        assert_eq!(parse(&c, 0, c.len(), LIM).unwrap().strings, ["aé"]);
    }

    #[test]
    fn extended_utf16_length_is_decoded() {
        // 0x8000|hi, lo: 0x0000_0002 chars encoded in the long form.
        let mut body = vec![];
        body.extend_from_slice(&0x8000u16.to_le_bytes());
        body.extend_from_slice(&2u16.to_le_bytes());
        for u in [b'o' as u16, b'k' as u16, 0] {
            body.extend_from_slice(&u.to_le_bytes());
        }
        let c = pool(false, &[body]);
        let p = parse(&c, 0, c.len(), LIM).unwrap();
        assert_eq!(p.strings, ["ok"]);
        assert_eq!(p.bad_slots, 0);
    }

    #[test]
    fn truncated_second_length_word_is_a_bad_slot() {
        // string is the very last thing in the chunk: w0 has the high bit,
        // the second word is missing.
        let body = 0x8000u16.to_le_bytes().to_vec();
        let mut c = pool(false, &[body]);
        // shrink the chunk so the second word is out of range
        let cut = c.len() - 2;
        c.truncate(cut);
        let p = parse(&c, 0, c.len(), LIM).unwrap();
        assert_eq!(p.strings, [""]);
        assert_eq!(p.bad_slots, 1);
    }

    #[test]
    fn surrogate_pairs_decode_and_lone_surrogates_degrade() {
        let c = pool(false, &[u16s("a\u{1F600}")]);
        assert_eq!(parse(&c, 0, c.len(), LIM).unwrap().strings, ["a\u{1F600}"]);
        let mut lone = 2u16.to_le_bytes().to_vec();
        for u in [0x61u16, 0xD83D, 0] {
            lone.extend_from_slice(&u.to_le_bytes());
        }
        let c = pool(false, &[lone]);
        assert_eq!(parse(&c, 0, c.len(), LIM).unwrap().strings, ["a\u{FFFD}"]);
    }

    #[test]
    fn caps_and_extents_are_errors() {
        let c = pool(false, &[u16s("abc")]);
        let tight = Limits {
            max_count: 1,
            max_bytes: 2,
        };
        assert!(matches!(
            parse(&c, 0, c.len(), tight),
            Err(PoolError::Bad(_))
        ));
        assert!(matches!(
            parse(&c, 0, c.len() + 1, LIM),
            Err(PoolError::Truncated(_))
        ));
    }
}
