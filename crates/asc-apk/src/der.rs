//! Bounded, display-only DER walker: X.509 certificate fields and the
//! certificate set of a PKCS#7 `SignedData` (JAR v1 `.RSA/.DSA/.EC`).
//!
//! Nothing here verifies signatures, digests or trust. Unsupported forms
//! come back as an `Err(reason)` or a visible `<unsupported …>` marker,
//! never as a guessed value. Supported: single-byte tags, definite lengths
//! up to 4 bytes; string types UTF8/Printable/IA5/T61(latin-1)/BMP;
//! UTCTime and GeneralizedTime in `…Z` form.

use std::fmt::Write as _;

const MAX_ITEMS: usize = 256;
const MAX_ARCS: usize = 24;

/// One DER TLV. `raw` includes the header.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub raw: &'a [u8],
}

/// Read one TLV from the front of `b`; returns it and the remaining bytes.
pub fn tlv(b: &[u8]) -> Result<(Tlv<'_>, &[u8]), &'static str> {
    let tag = *b.first().ok_or("truncated tag")?;
    if tag & 0x1f == 0x1f {
        return Err("high-tag-number form unsupported");
    }
    let l0 = *b.get(1).ok_or("truncated length")?;
    let (len, hdr) = if l0 < 0x80 {
        (l0 as usize, 2)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 {
            return Err("indefinite length is not DER");
        }
        if n > 4 {
            return Err("length wider than 4 bytes");
        }
        let bytes = b.get(2..2 + n).ok_or("truncated length")?;
        (
            bytes.iter().fold(0usize, |a, &x| (a << 8) | x as usize),
            2 + n,
        )
    };
    let end = hdr.checked_add(len).ok_or("length overflow")?;
    if end > b.len() {
        return Err("length exceeds buffer");
    }
    Ok((
        Tlv {
            tag,
            content: &b[hdr..end],
            raw: &b[..end],
        },
        &b[end..],
    ))
}

/// Children of a constructed value, at most [`MAX_ITEMS`].
pub fn items(mut c: &[u8]) -> Result<Vec<Tlv<'_>>, &'static str> {
    let mut v = Vec::new();
    while !c.is_empty() {
        if v.len() >= MAX_ITEMS {
            return Err("too many child items");
        }
        let (t, rest) = tlv(c)?;
        v.push(t);
        c = rest;
    }
    Ok(v)
}

fn expect(t: Option<&Tlv<'_>>, tag: u8, what: &'static str) -> Result<(), String> {
    match t {
        Some(t) if t.tag == tag => Ok(()),
        Some(t) => Err(format!(
            "{what}: expected tag 0x{tag:02x}, found 0x{:02x}",
            t.tag
        )),
        None => Err(format!("{what}: missing")),
    }
}

/// Dotted OID text from DER content bytes.
pub fn oid_string(c: &[u8]) -> Result<String, &'static str> {
    if c.is_empty() {
        return Err("empty OID");
    }
    let mut arcs: Vec<u64> = Vec::new();
    let mut v: u64 = 0;
    let mut cont = false;
    for &b in c {
        if v > (u64::MAX >> 8) {
            return Err("OID arc too large");
        }
        v = (v << 7) | u64::from(b & 0x7f);
        cont = b & 0x80 != 0;
        if !cont {
            if arcs.is_empty() {
                let (a, r) = match v {
                    0..=39 => (0, v),
                    40..=79 => (1, v - 40),
                    _ => (2, v - 80),
                };
                arcs.extend([a, r]);
            } else {
                arcs.push(v);
            }
            if arcs.len() > MAX_ARCS {
                return Err("too many OID arcs");
            }
            v = 0;
        }
    }
    if cont {
        return Err("truncated OID arc");
    }
    Ok(arcs
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join("."))
}

/// Friendly name for the OIDs seen in APK signing; dotted form otherwise.
fn oid_label(oid: &str) -> String {
    match oid {
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "1.2.840.113549.1.9.1" => "emailAddress",
        "1.2.840.113549.1.1.1" => "rsaEncryption",
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "rsassa-pss",
        "1.2.840.10045.2.1" => "id-ecPublicKey",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10040.4.1" => "dsa",
        "1.2.840.10040.4.3" => "dsa-with-sha1",
        "1.3.101.112" => "Ed25519",
        _ => return oid.to_string(),
    }
    .to_string()
}

fn alg_name(t: &Tlv<'_>) -> Result<String, String> {
    if t.tag != 0x30 {
        return Err("AlgorithmIdentifier is not a SEQUENCE".into());
    }
    let it = items(t.content).map_err(str::to_string)?;
    expect(it.first(), 0x06, "algorithm OID")?;
    Ok(oid_label(
        &oid_string(it[0].content).map_err(str::to_string)?,
    ))
}

fn string_value(t: &Tlv<'_>) -> String {
    match t.tag {
        0x0c | 0x13 | 0x16 => String::from_utf8_lossy(t.content).into_owned(),
        0x14 => t.content.iter().map(|&b| b as char).collect(),
        0x1e if t.content.len().is_multiple_of(2) => char::decode_utf16(
            t.content
                .chunks(2)
                .map(|p| u16::from_be_bytes([p[0], p[1]])),
        )
        .map(|r| r.unwrap_or('\u{fffd}'))
        .collect(),
        tag => format!("<unsupported string tag 0x{tag:02x}>"),
    }
}

/// `SEQUENCE OF SET OF SEQUENCE { OID, value }` rendered `CN=x, O=y`.
fn name_string(t: &Tlv<'_>) -> Result<String, String> {
    if t.tag != 0x30 {
        return Err("Name is not a SEQUENCE".into());
    }
    let mut parts = Vec::new();
    for rdn in items(t.content).map_err(str::to_string)? {
        if rdn.tag != 0x31 {
            return Err("RDN is not a SET".into());
        }
        for atv in items(rdn.content).map_err(str::to_string)? {
            let it = items(atv.content).map_err(str::to_string)?;
            expect(it.first(), 0x06, "attribute OID")?;
            let oid = oid_label(&oid_string(it[0].content).map_err(str::to_string)?);
            let val = it
                .get(1)
                .map(string_value)
                .ok_or_else(|| "attribute value missing".to_string())?;
            parts.push(format!("{oid}={val}"));
        }
    }
    Ok(parts.join(", "))
}

/// UTCTime / GeneralizedTime → `YYYY-MM-DD HH:MM:SS UTC`. Only the `Z`
/// forms with seconds are supported; anything else is an error.
fn time_string(t: &Tlv<'_>) -> Result<String, String> {
    let s = std::str::from_utf8(t.content).map_err(|_| "time is not ASCII".to_string())?;
    let (year, rest) = match t.tag {
        0x17 if s.len() == 13 => {
            let yy: u32 = s[..2].parse().map_err(|_| "bad UTCTime year".to_string())?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &s[2..])
        }
        0x18 if s.len() == 15 => (
            s[..4]
                .parse()
                .map_err(|_| "bad GeneralizedTime year".to_string())?,
            &s[4..],
        ),
        0x17 | 0x18 => return Err(format!("unsupported time form '{s}'")),
        tag => return Err(format!("unsupported time tag 0x{tag:02x}")),
    };
    let (body, z) = rest.split_at(rest.len() - 1);
    if z != "Z" || !body.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("unsupported time form '{s}'"));
    }
    Ok(format!(
        "{year:04}-{}-{} {}:{}:{} UTC",
        &body[0..2],
        &body[2..4],
        &body[4..6],
        &body[6..8],
        &body[8..10]
    ))
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Display fields of one X.509 certificate.
#[derive(Debug, Clone)]
pub struct CertFields {
    /// `None` = v1 (no explicit version field).
    pub version: Option<u32>,
    pub serial_hex: String,
    pub signature_algorithm: String,
    pub issuer: String,
    pub subject: String,
    /// Positional: first validity time is notBefore, second notAfter, each
    /// parsed by its own tag. `Err` text is kept visible.
    pub not_before: Result<String, String>,
    pub not_after: Result<String, String>,
    pub key_algorithm: String,
    /// Raw DER of the issuer Name and serial INTEGER content (matching
    /// against PKCS#7 `IssuerAndSerialNumber`).
    pub issuer_raw: Vec<u8>,
    pub serial_raw: Vec<u8>,
}

/// Parse `der` as an X.509 `Certificate`.
pub fn parse_cert(der: &[u8]) -> Result<CertFields, String> {
    let (cert, rest) = tlv(der).map_err(str::to_string)?;
    if cert.tag != 0x30 {
        return Err("Certificate is not a SEQUENCE".into());
    }
    if !rest.is_empty() {
        return Err("trailing bytes after Certificate".into());
    }
    let top = items(cert.content).map_err(str::to_string)?;
    expect(top.first(), 0x30, "tbsCertificate")?;
    let tbs = items(top[0].content).map_err(str::to_string)?;
    let (version, i) = match tbs.first() {
        Some(t) if t.tag == 0xA0 => {
            let (v, _) = tlv(t.content).map_err(str::to_string)?;
            if v.tag != 0x02 || v.content.len() != 1 {
                return Err("unsupported version encoding".into());
            }
            (Some(u32::from(v.content[0]) + 1), 1)
        }
        _ => (None, 0),
    };
    let field = |k: usize, tag: u8, what: &'static str| -> Result<Tlv<'_>, String> {
        expect(tbs.get(i + k), tag, what)?;
        Ok(tbs[i + k])
    };
    let serial = field(0, 0x02, "serialNumber")?;
    let sigalg = field(1, 0x30, "signature algorithm")?;
    let issuer = field(2, 0x30, "issuer")?;
    let validity = field(3, 0x30, "validity")?;
    let subject = field(4, 0x30, "subject")?;
    let spki = field(5, 0x30, "subjectPublicKeyInfo")?;
    let times = items(validity.content).map_err(str::to_string)?;
    if times.len() != 2 {
        return Err("validity does not have exactly 2 times".into());
    }
    let spki_items = items(spki.content).map_err(str::to_string)?;
    let key_algorithm = alg_name(spki_items.first().ok_or("SPKI algorithm missing")?)?;
    let s = serial.content;
    let shown = if s.len() > 1 && s[0] == 0 && s[1] & 0x80 != 0 {
        &s[1..]
    } else {
        s
    };
    Ok(CertFields {
        version,
        serial_hex: hex(shown),
        signature_algorithm: alg_name(&sigalg)?,
        issuer: name_string(&issuer)?,
        subject: name_string(&subject)?,
        not_before: time_string(&times[0]),
        not_after: time_string(&times[1]),
        key_algorithm,
        issuer_raw: issuer.raw.to_vec(),
        serial_raw: s.to_vec(),
    })
}

/// Certificates and signer identifiers of a PKCS#7 `SignedData`.
#[derive(Debug, Clone, Default)]
pub struct Pkcs7 {
    /// Raw DER of each certificate in the set, in order.
    pub certs: Vec<Vec<u8>>,
    /// `(issuer Name DER, serial INTEGER content)` per SignerInfo.
    pub signer_ids: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Locate the certificate set (`[0] IMPLICIT`, tag 0xA0) of a CMS
/// `ContentInfo{SignedData}` by tag, not by index.
pub fn parse_pkcs7(der: &[u8]) -> Result<Pkcs7, String> {
    let (ci, _) = tlv(der).map_err(str::to_string)?;
    if ci.tag != 0x30 {
        return Err("ContentInfo is not a SEQUENCE".into());
    }
    let ci_items = items(ci.content).map_err(str::to_string)?;
    expect(ci_items.first(), 0x06, "contentType")?;
    expect(ci_items.get(1), 0xA0, "content [0]")?;
    let (sd, _) = tlv(ci_items[1].content).map_err(str::to_string)?;
    if sd.tag != 0x30 {
        return Err("SignedData is not a SEQUENCE".into());
    }
    let it = items(sd.content).map_err(str::to_string)?;
    let mut out = Pkcs7::default();
    for t in it.iter().skip(3) {
        if t.tag == 0xA0 {
            for c in items(t.content).map_err(str::to_string)? {
                out.certs.push(c.raw.to_vec());
            }
        }
    }
    // signerInfos: the last SET after the version/digestAlgorithms/contentInfo.
    if let Some(si) = it.iter().skip(3).rev().find(|t| t.tag == 0x31) {
        for s in items(si.content).map_err(str::to_string)? {
            let f = items(s.content).map_err(str::to_string)?;
            // [1] IssuerAndSerialNumber; a [0] SubjectKeyIdentifier form is skipped.
            if let Some(ias) = f.get(1).filter(|t| t.tag == 0x30) {
                let p = items(ias.content).map_err(str::to_string)?;
                if let (Some(iss), Some(ser)) = (p.first(), p.get(1)) {
                    out.signer_ids
                        .push((iss.raw.to_vec(), ser.content.to_vec()));
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(tag: u8, c: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        if c.len() < 0x80 {
            v.push(c.len() as u8);
        } else {
            v.extend_from_slice(&[0x82, (c.len() >> 8) as u8, c.len() as u8]);
        }
        v.extend_from_slice(c);
        v
    }
    fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.concat()
    }
    fn atv(oid: &[u8], val: &[u8]) -> Vec<u8> {
        t(0x31, &t(0x30, &cat(&[t(0x06, oid), t(0x0c, val)])))
    }
    const SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    const CN: &[u8] = &[0x55, 0x04, 0x03];

    fn cert(nb: Vec<u8>, na: Vec<u8>) -> Vec<u8> {
        let alg = t(0x30, &cat(&[t(0x06, SHA256_RSA), t(0x05, &[])]));
        let name = t(0x30, &atv(CN, b"btchat333"));
        let tbs = t(
            0x30,
            &cat(&[
                t(0xA0, &t(0x02, &[2])),
                t(0x02, &[0x00, 0x80]),
                alg.clone(),
                name.clone(),
                t(0x30, &cat(&[nb, na])),
                name,
                t(0x30, &cat(&[alg.clone(), t(0x03, &[0, 1])])),
            ]),
        );
        t(0x30, &cat(&[tbs, alg, t(0x03, &[0, 1])]))
    }

    #[test]
    fn times_are_positional_and_tag_independent() {
        let utc = t(0x17, b"240101000000Z");
        let gen_ = t(0x18, b"20500101000000Z");
        // UTC+Generalized, Generalized+UTC, UTC+UTC: each slot parsed by its own tag.
        for (a, b, na_exp) in [
            (utc.clone(), gen_.clone(), "2050-01-01 00:00:00 UTC"),
            (gen_.clone(), utc.clone(), "2024-01-01 00:00:00 UTC"),
            (utc.clone(), utc.clone(), "2024-01-01 00:00:00 UTC"),
        ] {
            let f = parse_cert(&cert(a, b)).unwrap();
            assert_eq!(f.not_after.as_deref(), Ok(na_exp));
            assert!(f.not_before.is_ok());
        }
    }

    #[test]
    fn fields_and_visible_failures() {
        let f = parse_cert(&cert(t(0x17, b"990101000000Z"), t(0x17, b"240101000000Z"))).unwrap();
        assert_eq!(f.version, Some(3));
        assert_eq!(f.serial_hex, "80"); // leading 00 sign byte dropped
        assert_eq!(f.subject, "CN=btchat333");
        assert_eq!(f.issuer, f.subject); // equal text is NOT a self-signed claim
        assert_eq!(f.signature_algorithm, "sha256WithRSAEncryption");
        assert_eq!(f.not_before.as_deref(), Ok("1999-01-01 00:00:00 UTC"));
        // Unsupported time offset is reported, not guessed.
        let f = parse_cert(&cert(
            t(0x17, b"2401010000+0100"),
            t(0x17, b"240101000000Z"),
        ))
        .unwrap();
        assert!(f.not_before.is_err());
        assert!(f.not_after.is_ok());
        // Structural errors.
        assert!(parse_cert(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(parse_cert(&[0x30, 0x80]).is_err());
        assert!(parse_cert(&[]).is_err());
    }

    #[test]
    fn pkcs7_cert_set_found_by_tag() {
        let c = cert(t(0x17, b"240101000000Z"), t(0x17, b"240101000000Z"));
        let ias = t(0x30, &cat(&[t(0x30, &atv(CN, b"x")), t(0x02, &[1])]));
        let si = t(0x30, &cat(&[t(0x02, &[1]), ias, t(0x30, &[])]));
        let sd = t(
            0x30,
            &cat(&[
                t(0x02, &[1]),
                t(0x31, &[]),
                t(0x30, &t(0x06, &[0x2a])),
                t(0xA0, &c),
                t(0x31, &si),
            ]),
        );
        let ci = t(0x30, &cat(&[t(0x06, &[0x2a]), t(0xA0, &sd)]));
        let p = parse_pkcs7(&ci).unwrap();
        assert_eq!(p.certs, [c]);
        assert_eq!(p.signer_ids.len(), 1);
        assert_eq!(p.signer_ids[0].1, [1]);
        assert!(parse_pkcs7(&ci[..ci.len() - 3]).is_err());
    }
}
