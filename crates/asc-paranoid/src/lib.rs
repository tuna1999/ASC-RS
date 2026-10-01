//! # asc-paranoid
//!
//! Static deobfuscation of strings hidden by
//! [Paranoid](https://github.com/MichaelRocks/paranoid) /
//! [LSParanoid](https://github.com/LSPosed/LSParanoid) (v0.3.0+).
//!
//! Paranoid replaces every literal with
//! `const-wide vA, #id; invoke-static {vA, vA+1}, X->getString(J)String;
//! move-result-object vB`, where class `X` owns a `String[]` of
//! "chunks" filled in `<clinit>`. The id alone, plus those chunks,
//! determines the string, so no emulation is needed.
//!
//! [`decode`] / [`obfuscate`] are ports of Paranoid's
//! `DeobfuscatorHelper` / `RandomHelper` / `StringRegistryImpl`
//! (Apache-2.0, © Michael Rozumyanskiy); the approach follows
//! giacomoferretti/paranoid-deobfuscator (Apache-2.0).
//! [`find_deobfuscators`] and [`Resolver`] work on a borrowed
//! [`asc_dex::DexView`].

mod dex;
pub mod xor;

pub use crate::dex::{Call, Deobfuscator, Resolver, find_deobfuscators};
pub use crate::xor::{XorCall, XorDecoder, XorResolver, find_xor_decoders};

/// Chunk length Paranoid splits its string table into.
pub const MAX_CHUNK_LENGTH: usize = 0x1FFF;

fn seed(x: i64) -> i64 {
    let x = x as u64;
    let z = (x ^ (x >> 33)).wrapping_mul(0x62A9_D9ED_7997_05F5);
    ((z ^ (z >> 28)).wrapping_mul(0xCB24_D0A5_C88C_35B3) >> 32) as i64
}

/// Java `(short) ((x << k) | (x >>> (32 - k)))` with `x` promoted to int.
fn rotl(x: i16, k: u32) -> i16 {
    let x = x as i32;
    ((x << k) | ((x as u32) >> (32 - k)) as i32) as i16
}

/// `RandomHelper.next`, including Java's sign-extension of the `short`
/// halves when they are OR-ed into the `long` result.
fn next(state: i64) -> i64 {
    let mut s0 = state as i16;
    let mut s1 = (state >> 16) as i16;
    let mut n = s0.wrapping_add(s1);
    n = rotl(n, 9).wrapping_add(s0);
    s1 ^= s0;
    s0 = rotl(s0, 13);
    s0 ^= s1;
    s0 ^= ((s1 as i32) << 5) as i16;
    s1 = rotl(s1, 10);
    let mut r = n as i64;
    r <<= 16;
    r |= s1 as i64;
    r <<= 16;
    r |= s0 as i64;
    r
}

#[inline]
fn hi16(state: i64) -> u16 {
    ((state as u64) >> 32) as u16
}

fn char_at(index: i64, chunks: &[Vec<u16>], state: i64) -> Option<i64> {
    let i = usize::try_from(index).ok()?;
    let c = *chunks
        .get(i / MAX_CHUNK_LENGTH)?
        .get(i % MAX_CHUNK_LENGTH)?;
    Some(next(state) ^ ((c as i64) << 32))
}

/// `DeobfuscatorHelper.getString(id, chunks)` as UTF-16 code units.
/// `None` when the id points outside `chunks` (wrong table or not a
/// Paranoid id).
pub fn decode(id: i64, chunks: &[Vec<u16>]) -> Option<Vec<u16>> {
    let mut state = next(seed(id & 0xFFFF_FFFF));
    let low = hi16(state) as u64;
    state = next(state);
    let high = ((state as u64) >> 16) & 0xFFFF_0000;
    // Java: `(int) ((id >>> 32) ^ low ^ high)`.
    let index = ((id as u64 >> 32) ^ low ^ high) as u32 as i32 as i64;
    state = char_at(index, chunks, state)?;
    let len = hi16(state) as i64;
    let mut out = Vec::with_capacity(len as usize);
    for i in 0..len {
        state = char_at(index + i + 1, chunks, state)?;
        out.push(hi16(state));
    }
    Some(out)
}

/// Paranoid's `StringRegistryImpl`: registers `strings` under `seed`,
/// returning each string's id and the chunk table. Used to build
/// fixtures; `decode(ids[i], &chunks) == strings[i]`.
pub fn obfuscate(seed_value: u32, strings: &[&[u16]]) -> (Vec<i64>, Vec<Vec<u16>>) {
    let seed_value = seed_value as i64;
    let mut table: Vec<u16> = Vec::new();
    let mut ids = Vec::with_capacity(strings.len());
    for s in strings {
        let mut state = next(seed(seed_value));
        let mut mask = state & 0xFFFF_0000_0000;
        state = next(state);
        mask |= (state & 0xFFFF_0000_0000) << 16;
        ids.push(seed_value | (((table.len() as i64) << 32) ^ mask));
        state = next(state);
        table.push(hi16(state) ^ s.len() as u16);
        for &c in *s {
            state = next(state);
            table.push(hi16(state) ^ c);
        }
    }
    let chunks = table
        .chunks(MAX_CHUNK_LENGTH)
        .map(<[u16]>::to_vec)
        .collect();
    (ids, chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16s(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn round_trips_across_chunk_boundary() {
        let long = "x".repeat(MAX_CHUNK_LENGTH + 10);
        let inputs = [
            u16s("hello"),
            u16s(""),
            u16s(&long),
            u16s("h\u{0}\u{1F600}é"),
            u16s("tail"),
        ];
        let refs: Vec<&[u16]> = inputs.iter().map(Vec::as_slice).collect();
        for seed_value in [0, 1, 0x1234_5678, u32::MAX] {
            let (ids, chunks) = obfuscate(seed_value, &refs);
            assert!(chunks.len() >= 2);
            for (id, want) in ids.iter().zip(&inputs) {
                assert_eq!(decode(*id, &chunks).as_ref(), Some(want));
            }
        }
    }

    #[test]
    fn out_of_range_id_is_none() {
        let (_, chunks) = obfuscate(7, &[&u16s("abc")]);
        assert_eq!(decode(0x7FFF_0000_0000_0000, &chunks), None);
        assert_eq!(decode(1, &[]), None);
    }

    /// Pins the Java arithmetic (short sign-extension in `next`) against
    /// values from paranoid-deobfuscator's numpy port of `RandomHelper`.
    #[test]
    fn prng_matches_reference_port() {
        let s = seed(0x1234_5678);
        assert_eq!(s, 1_280_074_043);
        assert_eq!(next(s), -7273);
        assert_eq!(next(next(s)), -1_610_584_425);
        assert_eq!(next(-1), -1);
        assert_eq!(next(0x7FFF_8001), -67_158_079);
    }
}
