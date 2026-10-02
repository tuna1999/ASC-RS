//! APK Signing Block scanner (v2 / v3 / v3.1), display only.
//!
//! The block sits between the last local entry and the central directory:
//! `u64 size | pairs… | u64 size | "APK Sig Block 42"`. Each pair is
//! `u64 len | u32 id | value`. Signers are length-prefixed sequences (not
//! counted) per the AOSP grammar; digest/signature algorithm IDs are kept
//! as full `u32`. Nothing here verifies a signature, digest or trust.

use crate::error::ApkError;

const MAGIC: &[u8; 16] = b"APK Sig Block 42";
const ID_V2: u32 = 0x7109_871a;
const ID_V3: u32 = 0xf053_68c0;
const ID_V31: u32 = 0x1b93_ad61;
const MAX_PAIRS: usize = 1024;
const MAX_SIGNERS: usize = 16;
const MAX_CERTS: usize = 16;
const MAX_CERT_LEN: usize = 64 << 10;
const MAX_ALGS: usize = 64;

/// State of the signing block itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockStatus {
    /// No `APK Sig Block 42` footer before the central directory.
    Absent,
    Present {
        offset: u64,
        size: u64,
    },
    Malformed(String),
    Unsupported(String),
}

/// One id/value pair in the block (value is not retained).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairInfo {
    pub id: u32,
    pub value_len: u64,
}

/// One signer of a v2/v3 scheme block.
#[derive(Debug, Clone, Default)]
pub struct SignerBlock {
    /// Raw certificate DER, signed-data order (first is the signer's).
    pub certs: Vec<Vec<u8>>,
    pub digest_algs: Vec<u32>,
    pub signature_algs: Vec<u32>,
    /// v3 only.
    pub min_sdk: Option<u32>,
    pub max_sdk: Option<u32>,
}

/// A parsed scheme pair. `error` set = partially parsed (signers so far).
#[derive(Debug, Clone)]
pub struct SchemeBlock {
    pub id: u32,
    pub name: &'static str,
    pub signers: Vec<SignerBlock>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SigningScan {
    pub block: BlockStatus,
    pub pairs: Vec<PairInfo>,
    pub schemes: Vec<SchemeBlock>,
}

struct Rd<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Rd<'a> {
    fn u32(&mut self) -> Result<u32, &'static str> {
        let s = self.b.get(self.pos..self.pos + 4).ok_or("truncated u32")?;
        self.pos += 4;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    /// `u32 length | bytes`.
    fn lp(&mut self) -> Result<&'a [u8], &'static str> {
        let n = self.u32()? as usize;
        let end = self.pos.checked_add(n).ok_or("length overflow")?;
        let s = self
            .b
            .get(self.pos..end)
            .ok_or("length-prefixed field exceeds its parent")?;
        self.pos = end;
        Ok(s)
    }
    fn done(&self) -> bool {
        self.pos >= self.b.len()
    }
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes(s.try_into().ok()?))
}

/// Scan `buf` (the whole archive) for a signing block and parse its
/// v2/v3/v3.1 schemes.
pub fn scan(buf: &[u8]) -> SigningScan {
    let mut out = SigningScan {
        block: BlockStatus::Absent,
        pairs: Vec::new(),
        schemes: Vec::new(),
    };
    let (start, end) = match locate(buf) {
        Ok(Some(r)) => r,
        Ok(None) => return out,
        Err(s) => {
            out.block = s;
            return out;
        }
    };
    out.block = BlockStatus::Present {
        offset: start as u64,
        size: (end - start) as u64,
    };
    // pairs live in [start+8, end-24)
    let mut pos = start + 8;
    let pairs_end = end - 24;
    while pos < pairs_end {
        if out.pairs.len() >= MAX_PAIRS {
            out.block = BlockStatus::Malformed(format!("more than {MAX_PAIRS} pairs"));
            return out;
        }
        // A pair header is `u64 len | u32 id | value`: 8 bytes of length
        // plus at least 4 bytes of id. Anything shorter cannot be read
        // and must not be subtracted against (audit F02: `pairs_end - pos
        // - 8` underflowed when 1..7 bytes were left).
        let Some(rem) = pairs_end.checked_sub(pos + 8) else {
            out.block =
                BlockStatus::Malformed(format!("pair header overruns block at offset {pos}"));
            return out;
        };
        let Some(len) = u64_at(buf, pos) else {
            out.block = BlockStatus::Malformed("truncated pair header".into());
            return out;
        };
        let rem = rem as u64;
        if len < 4 || len > rem {
            out.block =
                BlockStatus::Malformed(format!("pair length {len} invalid at offset {pos}"));
            return out;
        }
        let id = u32::from_le_bytes([buf[pos + 8], buf[pos + 9], buf[pos + 10], buf[pos + 11]]);
        let vstart = pos + 12;
        let vend = pos + 8 + len as usize;
        out.pairs.push(PairInfo {
            id,
            value_len: len - 4,
        });
        let name = match id {
            ID_V2 => Some(("v2", false)),
            ID_V3 => Some(("v3", true)),
            ID_V31 => Some(("v3.1", true)),
            _ => None,
        };
        if let Some((name, v3)) = name {
            let (signers, error) = parse_signers(&buf[vstart..vend], v3);
            out.schemes.push(SchemeBlock {
                id,
                name,
                signers,
                error: error.map(str::to_string),
            });
        }
        pos = vend;
    }
    out
}

/// `Ok(Some((block_start, cd_offset)))`, `Ok(None)` = no block.
fn locate(buf: &[u8]) -> Result<Option<(usize, usize)>, BlockStatus> {
    let eocd = crate::zip::locate_eocd(buf, buf.len())
        .map_err(|e: ApkError| BlockStatus::Malformed(format!("EOCD: {e}")))?;
    let cd_off = u32::from_le_bytes([
        buf[eocd + 16],
        buf[eocd + 17],
        buf[eocd + 18],
        buf[eocd + 19],
    ]);
    if cd_off == u32::MAX {
        return Err(BlockStatus::Unsupported(
            "ZIP64 archive: signing block scan not supported".into(),
        ));
    }
    let cd = cd_off as usize;
    if cd > buf.len() {
        return Err(BlockStatus::Malformed(
            "central directory offset beyond EOF".into(),
        ));
    }
    if cd < 32 || &buf[cd - 16..cd] != MAGIC {
        return Ok(None);
    }
    let size = u64_at(buf, cd - 24).unwrap_or(0);
    // total = size + 8 (leading size field); size covers pairs + trailer.
    let Some(start) = (size < cd as u64 - 8 && size >= 24).then(|| cd - size as usize - 8) else {
        return Err(BlockStatus::Malformed(format!(
            "block size {size} inconsistent with central directory offset {cd}"
        )));
    };
    if u64_at(buf, start) != Some(size) {
        return Err(BlockStatus::Malformed(
            "leading and trailing block size fields disagree".into(),
        ));
    }
    Ok(Some((start, cd)))
}

fn parse_signers(value: &[u8], v3: bool) -> (Vec<SignerBlock>, Option<&'static str>) {
    let mut signers = Vec::new();
    let mut top = Rd { b: value, pos: 0 };
    let seq = match top.lp() {
        Ok(s) => s,
        Err(e) => return (signers, Some(e)),
    };
    let mut r = Rd { b: seq, pos: 0 };
    while !r.done() {
        if signers.len() >= MAX_SIGNERS {
            return (signers, Some("more than 16 signers; rest ignored"));
        }
        let body = match r.lp() {
            Ok(b) => b,
            Err(e) => return (signers, Some(e)),
        };
        match parse_signer(body, v3) {
            Ok(s) => signers.push(s),
            Err((s, e)) => {
                signers.push(s);
                return (signers, Some(e));
            }
        }
    }
    (signers, None)
}

fn parse_signer(body: &[u8], v3: bool) -> Result<SignerBlock, (SignerBlock, &'static str)> {
    let mut s = SignerBlock::default();
    let mut r = Rd { b: body, pos: 0 };
    macro_rules! tri {
        ($e:expr) => {
            match $e {
                Ok(v) => v,
                Err(e) => return Err((s, e)),
            }
        };
    }
    let signed = tri!(r.lp());
    if v3 {
        // Unsigned copies of minSdk/maxSdk sit between signed data and
        // signatures; the signed copies inside signed data are kept.
        tri!(r.u32());
        tri!(r.u32());
    }
    let sigs = tri!(r.lp());
    let _public_key = tri!(r.lp());
    let mut sd = Rd { b: signed, pos: 0 };
    let digests = tri!(sd.lp());
    let certs = tri!(sd.lp());
    if v3 {
        s.min_sdk = Some(tri!(sd.u32()));
        s.max_sdk = Some(tri!(sd.u32()));
    }
    s.digest_algs = tri!(alg_ids(digests));
    s.signature_algs = tri!(alg_ids(sigs));
    let mut c = Rd { b: certs, pos: 0 };
    while !c.done() {
        if s.certs.len() >= MAX_CERTS {
            return Err((s, "more than 16 certificates; rest ignored"));
        }
        let der = tri!(c.lp());
        if der.len() > MAX_CERT_LEN {
            return Err((s, "certificate exceeds 64 KiB cap"));
        }
        s.certs.push(der.to_vec());
    }
    Ok(s)
}

/// Sequence of `u32 len | u32 algorithm_id | u32 len | data` records → IDs.
fn alg_ids(seq: &[u8]) -> Result<Vec<u32>, &'static str> {
    let mut r = Rd { b: seq, pos: 0 };
    let mut ids = Vec::new();
    while !r.done() {
        if ids.len() >= MAX_ALGS {
            return Err("more than 64 algorithm records");
        }
        let rec = r.lp()?;
        let mut rr = Rd { b: rec, pos: 0 };
        ids.push(rr.u32()?);
        rr.lp()?;
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lp(b: &[u8]) -> Vec<u8> {
        let mut v = (b.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(b);
        v
    }
    fn rec(alg: u32, data: &[u8]) -> Vec<u8> {
        lp(&[alg.to_le_bytes().to_vec(), lp(data)].concat())
    }
    fn signer(v3: bool, alg: u32, certs: &[&[u8]]) -> Vec<u8> {
        let mut sd = lp(&rec(alg, b"digest"));
        sd.extend(lp(&certs.iter().flat_map(|c| lp(c)).collect::<Vec<_>>()));
        if v3 {
            sd.extend(28u32.to_le_bytes());
            sd.extend(u32::MAX.to_le_bytes());
        }
        sd.extend(lp(&[]));
        let mut s = lp(&sd);
        if v3 {
            s.extend(28u32.to_le_bytes());
            s.extend(u32::MAX.to_le_bytes());
        }
        s.extend(lp(&rec(alg, b"sig")));
        s.extend(lp(b"pubkey"));
        lp(&s)
    }
    /// Archive = junk + signing block + minimal EOCD pointing right after it.
    fn apk(pairs: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut p = Vec::new();
        for (id, v) in pairs {
            p.extend(((v.len() + 4) as u64).to_le_bytes());
            p.extend(id.to_le_bytes());
            p.extend(v);
        }
        let size = (p.len() + 24) as u64;
        let mut b = vec![0u8; 40];
        b.extend(size.to_le_bytes());
        b.extend(&p);
        b.extend(size.to_le_bytes());
        b.extend(MAGIC);
        let cd = b.len() as u32;
        b.extend(0x0605_4b50u32.to_le_bytes());
        b.extend([0u8; 12]);
        b.extend(cd.to_le_bytes());
        b.extend([0u8; 2]);
        b
    }

    /// `apk()` plus `extra` junk bytes at the tail of the pairs region
    /// (audit F02: fewer than 8 bytes left before the trailing size
    /// field, so the next pair header cannot be read).
    fn apk_with_pair_tail(pairs: &[(u32, Vec<u8>)], extra: usize) -> Vec<u8> {
        let mut p = Vec::new();
        for (id, v) in pairs {
            p.extend(((v.len() + 4) as u64).to_le_bytes());
            p.extend(id.to_le_bytes());
            p.extend(v);
        }
        p.extend(vec![0x5au8; extra]);
        let size = (p.len() + 24) as u64;
        let mut b = vec![0u8; 40];
        b.extend(size.to_le_bytes());
        b.extend(&p);
        b.extend(size.to_le_bytes());
        b.extend(MAGIC);
        let cd = b.len() as u32;
        b.extend(0x0605_4b50u32.to_le_bytes());
        b.extend([0u8; 12]);
        b.extend(cd.to_le_bytes());
        b.extend([0u8; 2]);
        b
    }

    #[test]
    fn pair_region_with_fewer_than_eight_bytes_left_is_malformed() {
        for extra in 1..=7usize {
            let buf = apk_with_pair_tail(&[(0x1234, vec![0; 4])], extra);
            let s = scan(&buf);
            assert!(
                matches!(s.block, BlockStatus::Malformed(_)),
                "tail={extra}: expected Malformed, got {:?}",
                s.block
            );
        }
    }

    #[test]
    fn v2_v3_and_unknown_pair() {
        let v2 = lp(&signer(false, 0x0103, &[b"c1", b"c2"]));
        let v3 = lp(&signer(true, 0xdead_beef, &[b"c1"]));
        let s = scan(&apk(&[
            (ID_V2, v2),
            (0x4272_6577, vec![1, 2, 3]),
            (ID_V3, v3),
        ]));
        assert!(matches!(s.block, BlockStatus::Present { .. }));
        assert_eq!(s.pairs.len(), 3);
        assert_eq!(s.pairs[1].id, 0x4272_6577); // unknown pair id kept verbatim
        assert_eq!(s.schemes.len(), 2);
        assert_eq!(
            s.schemes[0].signers[0].certs,
            [b"c1".to_vec(), b"c2".to_vec()]
        );
        // Algorithm IDs keep all 32 bits.
        assert_eq!(s.schemes[1].signers[0].signature_algs, [0xdead_beef]);
        assert_eq!(s.schemes[1].signers[0].min_sdk, Some(28));
        assert!(s.schemes.iter().all(|x| x.error.is_none()));
    }

    #[test]
    fn absent_and_malformed_are_distinct() {
        // No footer -> Absent (v1-only or unsigned: not decided here).
        let mut plain = vec![0u8; 64];
        plain.extend(0x0605_4b50u32.to_le_bytes());
        plain.extend([0u8; 18]);
        assert_eq!(scan(&plain).block, BlockStatus::Absent);
        // Corrupt leading size field -> Malformed, not Absent.
        let mut b = apk(&[(ID_V2, lp(&signer(false, 1, &[b"c"])))]);
        b[40] ^= 0xff;
        assert!(matches!(scan(&b).block, BlockStatus::Malformed(_)));
        // Pair longer than the block.
        let mut b = apk(&[(0x1234, vec![0; 8])]);
        b[48] = 0xff;
        assert!(matches!(scan(&b).block, BlockStatus::Malformed(_)));
        // Truncated signer keeps the scheme visible with an error.
        let mut v2 = lp(&signer(false, 1, &[b"c"]));
        v2.truncate(v2.len() - 3);
        let s = scan(&apk(&[(ID_V2, v2)]));
        assert!(s.schemes[0].error.is_some());
    }
}
