//! Corpus-free tests for `asc_core::cert::run_cert`.
//!
//! Every archive here is built byte by byte: a hand-rolled minimal X.509 /
//! PKCS#7 SignedData, a STORED ZIP writer, and the APK Signing Block layout
//! from the v2/v3 spec (`u64 size | pairs | u64 size | "APK Sig Block 42"`).
//! Nothing is read from `corpus/`, so the suite is self-contained.
//!
//! Signatures are never built or checked: `run_cert` is display-only, and
//! the tests only assert what it reports about the bytes it was given.

use std::path::{Path, PathBuf};

use asc_apk::signing::BlockStatus;
use asc_core::cert::{CertInfo, CertReport, SchemeReport};
use asc_core::{CoreError, format_cert_text, run_cert};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------- DER builders

/// DER TLV with a definite length (1-4 length bytes, as `asc-apk::der` supports).
fn tlv(tag: u8, c: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    if c.len() < 0x80 {
        v.push(c.len() as u8);
    } else {
        v.extend_from_slice(&[0x82, (c.len() >> 8) as u8, c.len() as u8]);
    }
    v.extend_from_slice(c);
    v
}

const OID_SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];

fn alg_id(oid: &[u8]) -> Vec<u8> {
    tlv(0x30, &tlv(0x06, oid))
}

fn name(cn: &[u8]) -> Vec<u8> {
    tlv(
        0x30,
        &tlv(
            0x31,
            &tlv(0x30, &[tlv(0x06, OID_CN), tlv(0x0c, cn)].concat()),
        ),
    )
}

fn utc_time(s: &[u8]) -> Vec<u8> {
    tlv(0x17, s)
}

/// Minimal v3 X.509 certificate; the raw issuer Name lives in `serial.1`.
struct Cert {
    der: Vec<u8>,
    issuer: Vec<u8>,
    serial: Vec<u8>,
}

impl Cert {
    fn serial_hex(&self) -> String {
        self.serial.iter().map(|b| format!("{b:02x}")).collect()
    }
}

fn cert(cn: &[u8], serial: &[u8]) -> Cert {
    let alg = alg_id(OID_SHA256_RSA);
    let issuer = name(cn);
    let tbs = tlv(
        0x30,
        &[
            tlv(0xA0, &tlv(0x02, &[2])), // explicit version v3
            tlv(0x02, serial),
            alg.clone(),
            issuer.clone(),
            tlv(
                0x30,
                &[utc_time(b"240101000000Z"), utc_time(b"490101000000Z")].concat(),
            ),
            issuer.clone(),
            tlv(
                0x30,
                &[alg.clone(), tlv(0x03, &[0x01, 0x02, 0x03])].concat(),
            ),
        ]
        .concat(),
    );
    Cert {
        der: tlv(0x30, &[tbs, alg, tlv(0x03, &[0x00])].concat()),
        issuer,
        serial: serial.to_vec(),
    }
}

/// `SEQUENCE { version, digestAlgorithms, contentInfo, [0] certs, [1] signerInfos }`
/// (RFC 5652 §5.1). `certs` are raw `Certificate` DER, `signers` raw
/// `SignerInfo` DER; the `0xA0` wrapper is the IMPLICIT `certificates [0]`.
fn pkcs7(certs: &[&Cert], signers: &[Vec<u8>]) -> Vec<u8> {
    let sd = tlv(
        0x30,
        &[
            tlv(0x02, &[1]),
            tlv(0x31, &[]),
            tlv(0x30, &tlv(0x06, OID_SIGNED_DATA)),
            tlv(
                0xA0,
                &certs
                    .iter()
                    .map(|c| c.der.clone())
                    .collect::<Vec<_>>()
                    .concat(),
            ),
            tlv(0x31, &signers.concat()),
        ]
        .concat(),
    );
    tlv(0x30, &[tlv(0x06, OID_SIGNED_DATA), tlv(0xA0, &sd)].concat())
}

fn signer_info(signer: &Cert) -> Vec<u8> {
    let ias = tlv(
        0x30,
        &[signer.issuer.clone(), tlv(0x02, &signer.serial)].concat(),
    );
    tlv(
        0x30,
        &[
            tlv(0x02, &[1]),
            ias,
            tlv(0x30, &tlv(0x06, OID_SHA256_RSA)),
            tlv(0x04, &[0xde, 0xad, 0xbe, 0xef]),
        ]
        .concat(),
    )
}

// --------------------------------------------------------- signing-block bytes

const MAGIC: &[u8; 16] = b"APK Sig Block 42";
const ID_V2: u32 = 0x7109_871a;

/// One `u32` length prefix followed by `b`.
fn lp_bytes(b: &[u8]) -> Vec<u8> {
    let mut v = (b.len() as u32).to_le_bytes().to_vec();
    v.extend_from_slice(b);
    v
}

/// `sequence-of` blob: one `u32` length for the whole sequence, the
/// length-prefixed members concatenated raw inside it.
fn seq(members: &[Vec<u8>]) -> Vec<u8> {
    lp_bytes(&members.concat())
}

/// One v2 signer (APK Signature Scheme v2, `signer` grammar):
///
/// ```text
/// signer      := signed-data   signatures   public-key
/// signed-data := digests       certificates
/// signatures  := sequence-of (uint32 algorithm-id, length-prefixed signature)
/// public-key  := length-prefixed bytes
/// ```
///
/// Every field carries exactly one length prefix. The layout is walked
/// byte by byte in `v2_block_layout_matches_the_spec`, so a missing or
/// doubled prefix fails there instead of silently reaching the scanner.
fn v2_signer(certs: &[&Cert]) -> Vec<u8> {
    let digests = seq(&[lp_bytes(
        &[0x0103u32.to_le_bytes().to_vec(), lp_bytes(b"digest")].concat(),
    )]);
    let certificates = seq(&certs.iter().map(|c| lp_bytes(&c.der)).collect::<Vec<_>>());
    let signed_data = [digests, certificates].concat();
    let signatures = seq(&[lp_bytes(
        &[0x0103u32.to_le_bytes().to_vec(), lp_bytes(b"sig")].concat(),
    )]);
    [lp_bytes(&signed_data), signatures, lp_bytes(b"pubkey")].concat()
}

fn v2_value(certs: &[&Cert]) -> Vec<u8> {
    seq(&[lp_bytes(&v2_signer(certs))])
}

// ------------------------------------------------------------- archive assembly

/// STORED ZIP: local entries, central directory, `trailing` bytes, EOCD.
/// `trailing` is where the APK Signing Block goes (per spec: between the
/// last local entry and the central directory). `cd_off_override` replaces
/// the 32-bit central-directory offset that the EOCD advertises.
fn zip(parts: &[(&str, Vec<u8>)], trailing: Vec<u8>, cd_off_override: Option<u32>) -> Vec<u8> {
    let (mut out, mut cd) = (Vec::new(), Vec::new());
    for (name, data) in parts {
        let off = out.len() as u32;
        let name_b = name.as_bytes();
        let name_len = (name_b.len() as u16).to_le_bytes();
        // Local file header: version, flags, method (STORED = 0), time, date.
        let mut lh = 0x0403_4b50u32.to_le_bytes().to_vec();
        lh.extend_from_slice(&20u16.to_le_bytes());
        lh.extend_from_slice(&0u16.to_le_bytes());
        lh.extend_from_slice(&0u16.to_le_bytes());
        lh.extend_from_slice(&0u16.to_le_bytes());
        lh.extend_from_slice(&0u16.to_le_bytes());
        lh.extend_from_slice(&0u32.to_le_bytes()); // crc32
        lh.extend_from_slice(&(data.len() as u32).to_le_bytes());
        lh.extend_from_slice(&(data.len() as u32).to_le_bytes());
        lh.extend_from_slice(&name_len);
        lh.extend_from_slice(&0u16.to_le_bytes()); // extra length
        out.extend(lh);
        out.extend_from_slice(name_b);
        out.extend_from_slice(data);
        // Central directory header: version made by / needed, …, disk numbers.
        let mut ch = 0x0201_4b50u32.to_le_bytes().to_vec();
        ch.extend_from_slice(&20u16.to_le_bytes());
        ch.extend_from_slice(&20u16.to_le_bytes());
        ch.extend_from_slice(&0u16.to_le_bytes());
        ch.extend_from_slice(&0u16.to_le_bytes());
        ch.extend_from_slice(&0u16.to_le_bytes());
        ch.extend_from_slice(&0u16.to_le_bytes());
        ch.extend_from_slice(&0u32.to_le_bytes()); // crc32
        ch.extend_from_slice(&(data.len() as u32).to_le_bytes());
        ch.extend_from_slice(&(data.len() as u32).to_le_bytes());
        ch.extend_from_slice(&name_len);
        ch.extend_from_slice(&0u16.to_le_bytes()); // extra length
        ch.extend_from_slice(&0u16.to_le_bytes()); // comment length
        ch.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        ch.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        ch.extend_from_slice(&0u32.to_le_bytes()); // external attributes
        ch.extend_from_slice(&off.to_le_bytes());
        ch.extend_from_slice(name_b);
        cd.extend(ch);
    }
    let cd_off = out.len() + trailing.len();
    out.extend(trailing);
    let cd_size = cd.len() as u32;
    out.extend(cd);
    let mut e = 0x0605_4b50u32.to_le_bytes().to_vec();
    e.extend_from_slice(&[0, 0, 0, 0]);
    e.extend_from_slice(&(parts.len() as u16).to_le_bytes());
    e.extend_from_slice(&(parts.len() as u16).to_le_bytes());
    e.extend_from_slice(&cd_size.to_le_bytes());
    e.extend_from_slice(&cd_off_override.unwrap_or(cd_off as u32).to_le_bytes());
    e.extend_from_slice(&[0, 0]);
    out.extend(e);
    out
}

/// `u64 size | pairs | u64 size | "APK Sig Block 42"` (size covers pairs+trailer).
fn signing_block(pairs: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut p = Vec::new();
    for (id, v) in pairs {
        p.extend_from_slice(&((v.len() + 4) as u64).to_le_bytes());
        p.extend_from_slice(&id.to_le_bytes());
        p.extend(v);
    }
    let size = (p.len() + 24) as u64;
    [
        size.to_le_bytes().to_vec(),
        p,
        size.to_le_bytes().to_vec(),
        MAGIC.to_vec(),
    ]
    .concat()
}

/// A plain v1 APK: one STORED `META-INF/CERT.RSA` plus a `classes.dex` stub.
fn v1_apk(certs: &[&Cert], signers: &[Vec<u8>]) -> Vec<u8> {
    zip(
        &[
            ("classes.dex", b"dex\n035\0stub".to_vec()),
            ("META-INF/CERT.RSA", pkcs7(certs, signers)),
        ],
        Vec::new(),
        None,
    )
}

/// v1 APK plus a v2 signing block holding `certs`.
fn v1_v2_apk(certs: &[&Cert], signers: &[Vec<u8>], v2_certs: &[&Cert]) -> Vec<u8> {
    zip(
        &[
            ("classes.dex", b"dex\n035\0stub".to_vec()),
            ("META-INF/CERT.RSA", pkcs7(certs, signers)),
        ],
        signing_block(&[(ID_V2, v2_value(v2_certs))]),
        None,
    )
}

fn write_apk(tag: &str, bytes: &[u8]) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("asc_cert_synth_{}_{}.apk", std::process::id(), tag));
    std::fs::write(&path, bytes).unwrap();
    path
}

/// `run_cert` on a temp APK, then delete it.
fn run(tag: &str, bytes: &[u8]) -> CertReport {
    let p = write_apk(tag, bytes);
    let r = run_cert(&p);
    std::fs::remove_file(&p).ok();
    r.unwrap_or_else(|e| panic!("{tag}: run_cert: {e}"))
}

fn hex_sha256(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn scheme<'a>(r: &'a CertReport, name: &str) -> &'a SchemeReport {
    r.schemes
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| {
            panic!(
                "no scheme {name}: {:?}",
                r.schemes
                    .iter()
                    .map(|s| (s.name, s.status))
                    .collect::<Vec<_>>()
            )
        })
}

fn signer_cert(s: &SchemeReport) -> &CertInfo {
    s.signers
        .first()
        .expect("no signer report")
        .certs
        .iter()
        .find(|c| c.role == "signer")
        .expect("no cert with role signer")
}

// --------------------------------------------------------------------- cases

#[test]
fn v1_only_reports_the_signer_and_its_own_sha256() {
    let c = cert(b"v1 signer", &[0x2a]);
    let apk = v1_apk(&[&c], &[signer_info(&c)]);
    let r = run("v1", &apk);

    let v1 = scheme(&r, "v1");
    assert_eq!(v1.status, "present", "{}", format_cert_text(&r));
    assert!(v1.errors.is_empty(), "{:?}", v1.errors);
    assert_eq!(v1.signers.len(), 1);
    assert_eq!(v1.signers[0].source, "META-INF/CERT.RSA");
    assert_eq!(v1.signers[0].certs.len(), 1);

    let got = signer_cert(v1);
    assert_eq!(got.role, "signer");
    // Computed here over the same DER bytes, not read back from the report.
    assert_eq!(got.sha256, hex_sha256(&c.der));
    assert_eq!(got.der_len, c.der.len());
    assert_eq!(got.subject.as_deref(), Some("CN=v1 signer"));
    assert_eq!(got.serial.as_deref(), Some(c.serial_hex().as_str()));
    assert_eq!(got.x509_version, Some(3));
    assert!(got.parse_errors.is_empty(), "{:?}", got.parse_errors);

    for name in ["v2", "v3", "v3.1"] {
        assert_eq!(scheme(&r, name).status, "absent", "{name}");
        assert!(scheme(&r, name).signers.is_empty());
    }
    assert_eq!(r.block_status, "absent");
    assert_eq!(r.block_offset, None);
    assert!(r.pairs.is_empty());
    // One v1 signer alone -> nothing to compare it against.
    assert!(r.comparison.is_empty(), "{:?}", r.comparison);
    assert!(r.note.is_none(), "{:?}", r.note);
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert!(r.complete);
    assert_eq!(r.verification, "not_performed");
    // A report that says nothing was verified must not imply validity.
    let text = format_cert_text(&r);
    assert!(text.contains("verification: not_performed"), "{text}");
    assert!(!text.to_lowercase().contains(" is valid"), "{text}");
    assert!(!text.to_lowercase().contains("trusted"), "{text}");
}

/// The SignerInfo points at the second certificate: only that one is `signer`.
#[test]
fn v1_signs_the_second_certificate_of_two() {
    let a = cert(b"first", &[0x01]);
    let b = cert(b"second", &[0x02]);
    let apk = v1_apk(&[&a, &b], &[signer_info(&b)]);
    let r = run("v1two", &apk);

    let certs = &scheme(&r, "v1").signers[0].certs;
    assert_eq!(certs.len(), 2);
    assert_eq!(
        certs.iter().map(|c| c.role).collect::<Vec<_>>(),
        ["chain", "signer"]
    );
    assert_eq!(certs[1].sha256, hex_sha256(&b.der));
    assert_eq!(certs[0].sha256, hex_sha256(&a.der));
    assert_ne!(certs[0].sha256, certs[1].sha256);
    assert!(r.complete, "{:?}", r.errors);
}

/// No certificate matches the IssuerAndSerialNumber -> nobody is the signer.
#[test]
fn v1_signer_info_matching_no_certificate_is_unmatched() {
    let a = cert(b"first", &[0x01]);
    let b = cert(b"second", &[0x02]);
    let stranger = cert(b"stranger", &[0x7f]);
    let apk = v1_apk(&[&a, &b], &[signer_info(&stranger)]);
    let r = run("v1none", &apk);

    let certs = &scheme(&r, "v1").signers[0].certs;
    assert_eq!(certs.len(), 2);
    assert_eq!(
        certs.iter().map(|c| c.role).collect::<Vec<_>>(),
        ["unmatched", "unmatched"]
    );
    // No signer identified -> no cross-scheme claim is made.
    assert!(r.comparison.is_empty(), "{:?}", r.comparison);
    assert!(r.complete, "{:?}", r.errors);
}

#[test]
fn v2_comparison_reports_difference_and_equality_separately() {
    let v1c = cert(b"v1 signer", &[0x0a]);
    let v2c = cert(b"v2 signer", &[0x0b]);

    // Same certificate under both schemes -> match, no DIFFER wording.
    // v2 carries two certificates: the first is the signer, the second the
    // chain, and only the first may enter the comparison.
    let chain = cert(b"v2 chain", &[0x0c]);
    let same = v1_v2_apk(&[&v1c], &[signer_info(&v1c)], &[&v1c, &chain]);
    let r = run("v2same", &same);
    assert_eq!(
        scheme(&r, "v2").status,
        "present",
        "{}",
        format_cert_text(&r)
    );
    assert_eq!(scheme(&r, "v2").signers[0].certs.len(), 2);
    assert_eq!(scheme(&r, "v2").signers[0].certs[1].role, "chain");
    assert_eq!(signer_cert(scheme(&r, "v2")).sha256, hex_sha256(&v1c.der));
    assert_eq!(r.comparison.len(), 1, "{:?}", r.comparison);
    assert!(r.comparison[0].contains("v1 and v2"), "{:?}", r.comparison);
    assert!(r.comparison[0].contains("match"), "{:?}", r.comparison);
    assert!(!r.comparison[0].contains("DIFFER"), "{:?}", r.comparison);
    assert!(r.complete, "{:?}", r.errors);

    // A different certificate under v2 -> the difference is stated.
    let diff = v1_v2_apk(&[&v1c], &[signer_info(&v1c)], &[&v2c, &chain]);
    let r = run("v2diff", &diff);
    assert_eq!(signer_cert(scheme(&r, "v2")).sha256, hex_sha256(&v2c.der));
    assert_eq!(r.comparison.len(), 1, "{:?}", r.comparison);
    assert!(r.comparison[0].contains("DIFFER"), "{:?}", r.comparison);
    assert!(!r.comparison[0].contains("match"), "{:?}", r.comparison);
}

/// Sizes and counts that overrun the block: a contained report, no panic.
#[test]
fn malformed_signing_block_is_reported_as_malformed() {
    let c = cert(b"v2 signer", &[0x03]);
    // The block sits right before the central directory; its trailing size
    // field is 24 bytes (8 + magic) before the CD offset stored in the EOCD.
    let tail_of = |a: &[u8]| {
        let cd = u32::from_le_bytes(a[a.len() - 6..a.len() - 2].try_into().unwrap());
        cd as usize - 24
    };
    let good = zip(
        &[("classes.dex", b"dex\n035\0stub".to_vec())],
        signing_block(&[(ID_V2, v2_value(&[&c]))]),
        None,
    );
    assert_eq!(scheme(&run("blkok", &good), "v2").status, "present");

    // Trailing size field set to u64::MAX: the block cannot be located.
    let mut broken = good.clone();
    let at = tail_of(&good);
    broken[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    let r = run("blkbad", &broken);
    assert_eq!(r.block_status, "malformed");
    assert!(!r.complete);
    assert!(
        r.errors
            .iter()
            .any(|e| e.contains("signing block:") && e.contains("inconsistent")),
        "{:?}",
        r.errors
    );
    assert!(r.note.is_none(), "{:?}", r.note);

    // Leading size field altered -> leading/trailing size fields disagree.
    let mut disagree = good.clone();
    let at = tail_of(&good);
    let size = u64::from_le_bytes(good[at..at + 8].try_into().unwrap());
    let lead = at + 24 - (size as usize + 8);
    disagree[lead..lead + 8].copy_from_slice(&(size + 1).to_le_bytes());
    let r = run("blkdis", &disagree);
    assert_eq!(r.block_status, "malformed");
    assert!(
        r.errors
            .iter()
            .any(|e| e.contains("leading and trailing block size fields disagree")),
        "{:?}",
        r.errors
    );

    // Signer length larger than the pair value: scheme v2 becomes `malformed`
    // with its error surfaced, while v1 is still inventoried normally.
    let mut overlong = v2_value(&[&c]);
    let too_long = (overlong.len() + 64) as u32;
    overlong[0..4].copy_from_slice(&too_long.to_le_bytes());
    let v1c = cert(b"v1 signer", &[0x0a]);
    let apk = zip(
        &[
            ("classes.dex", b"dex\n035\0stub".to_vec()),
            ("META-INF/CERT.RSA", pkcs7(&[&v1c], &[signer_info(&v1c)])),
        ],
        signing_block(&[(ID_V2, overlong)]),
        None,
    );
    let r = run("signerlen", &apk);
    assert_eq!(r.block_status, "present");
    let v1 = scheme(&r, "v1");
    let v2 = scheme(&r, "v2");
    assert_eq!(v1.status, "present", "v1 data still reported");
    assert_eq!(v1.signers.len(), 1);
    assert_eq!(signer_cert(v1).sha256, hex_sha256(&v1c.der));
    assert_eq!(v2.status, "malformed", "{}", format_cert_text(&r));
    assert!(!v2.errors.is_empty(), "malformed detail must be visible");
    assert!(!r.complete);
    assert!(
        r.errors.iter().any(|e| e.starts_with("v2: ")),
        "{:?}",
        r.errors
    );
    assert!(r.comparison.is_empty(), "no equality claim without signers");
}

/// A well-formed ZIP64 EOCD64 + locator archive: `run_cert` errors, and the
/// error is the ZIP layer refusing it — never a `CertReport` claiming the
/// signing block is absent. When the same EOCD64 layout is scanned directly,
/// the block status is `unsupported` (not `absent`) and v2/v3 are `unknown`.
#[test]
fn zip64_eocd_with_locator_is_unsupported_never_absent() {
    const SIG_EOCD64: u32 = 0x0606_4b50;
    const SIG_LOCATOR64: u32 = 0x0706_4b50;
    let apk = zip(
        &[("classes.dex", b"dex\n035\0stub".to_vec())],
        Vec::new(),
        None,
    );
    // One entry, so the central directory is a single 46+name header.
    let cd_size = 46 + "classes.dex".len();
    let cd_off = apk.len() - 22 - cd_size;
    let e64_at = apk.len() - 22; // the EOCD64 record replaces the EOCD
    let mut b = apk[..apk.len() - 22].to_vec();
    b.extend(SIG_EOCD64.to_le_bytes());
    b.extend(44u64.to_le_bytes()); // size of the EOCD64 record after itself
    b.extend(45u16.to_le_bytes()); // version made by
    b.extend(45u16.to_le_bytes()); // version needed
    b.extend(0u32.to_le_bytes()); // this disk
    b.extend(0u32.to_le_bytes()); // disk with the central directory
    b.extend(1u64.to_le_bytes()); // entries on this disk
    b.extend(1u64.to_le_bytes()); // total entries
    b.extend((cd_size as u64).to_le_bytes());
    b.extend((cd_off as u64).to_le_bytes());
    b.extend(SIG_LOCATOR64.to_le_bytes());
    b.extend(0u32.to_le_bytes()); // disk with the EOCD64
    b.extend((e64_at as u64).to_le_bytes());
    b.extend(1u32.to_le_bytes()); // total disks
    // EOCD with the ZIP64 placeholders the ZIP layer keys on.
    b.extend(0x0605_4b50u32.to_le_bytes());
    b.extend(0u16.to_le_bytes()); // this disk
    b.extend(0u16.to_le_bytes()); // disk with the central directory
    b.extend(0xFFFFu16.to_le_bytes()); // entries on this disk
    b.extend(0xFFFFu16.to_le_bytes()); // total entries
    // Only the offset is a placeholder: `parse_directory` then wants the
    // ZIP64 locator, fails to find one 20 bytes earlier and refuses the
    // archive. The signing-block scanner reads the EOCD offset only, so it
    // still reaches its own ZIP64 branch and reports `unsupported`.
    b.extend((cd_size as u32).to_le_bytes()); // central directory size
    b.extend(0xFFFF_FFFFu32.to_le_bytes()); // central directory offset
    b.extend(0u16.to_le_bytes()); // comment length

    let p = write_apk("z64eocd", &b);
    let out = run_cert(&p);
    std::fs::remove_file(&p).ok();
    match out {
        Ok(r) => assert_zip64_verdict(&r),
        Err(e) => assert!(
            matches!(e, CoreError::Apk(_)) && e.to_string().to_uppercase().contains("ZIP64"),
            "a ZIP64 archive must never be reported as unsigned or unsigned-like: {e}"
        ),
    }
}

/// The only verdict a ZIP64-framed APK may get: the signing block is
/// `unsupported` (never `absent`) and the v2/v3 schemes are `unknown`.
fn assert_zip64_verdict(r: &CertReport) {
    assert_eq!(r.block_status, "unsupported", "{}", format_cert_text(r));
    assert!(
        r.block_detail
            .as_deref()
            .is_some_and(|d| d.contains("ZIP64")),
        "{:?}",
        r.block_detail
    );
    for name in ["v2", "v3", "v3.1"] {
        assert_eq!(scheme(r, name).status, "unknown", "{name}");
    }
    assert!(!r.complete);
}

#[test]
fn no_signing_material_is_not_reported_as_unsigned() {
    let apk = zip(
        &[("classes.dex", b"dex\n035\0stub".to_vec())],
        Vec::new(),
        None,
    );
    let r = run("bare", &apk);
    assert_eq!(r.block_status, "absent");
    assert!(r.pairs.is_empty());
    assert!(r.schemes.iter().all(|s| s.status == "absent"));
    assert!(r.comparison.is_empty(), "{:?}", r.comparison);
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert!(r.complete, "an absence of errors is not a positive claim");

    let note = r.note.as_deref().expect("no-signing-material note");
    assert!(note.contains("no signing material found"), "{note}");
    assert!(note.contains("does not establish"), "{note}");
    // "unsigned" may only appear inside the sentence that denies it.
    assert_eq!(note.matches("unsigned").count(), 1, "{note}");
    let text = format_cert_text(&r).to_lowercase();
    assert!(text.contains("note: no signing material found"), "{text}");
    // The only claim about the APK's state is the note's denial, so the
    // attribute may appear exactly once, right after "that the apk is".
    assert_eq!(text.matches("unsigned").count(), 1, "{text}");
    assert!(text.contains("that the apk is unsigned"), "{text}");
    assert!(text.contains("not_performed"), "{text}");
}

#[test]
fn raw_dex_input_is_a_usage_error() {
    let p = write_apk("dex", b"dex\n035\0not an apk");
    let err = run_cert(&p);
    std::fs::remove_file(&p).ok();
    match err {
        Err(CoreError::Usage(msg)) => {
            assert!(msg.contains("requires an APK"), "msg: {msg}");
            assert!(msg.contains("raw DEX"), "msg: {msg}");
        }
        other => panic!("expected CoreError::Usage, got {other:?}"),
    }
}

#[test]
fn missing_file_is_reported_not_panicked() {
    let p: &Path = &std::env::temp_dir().join("asc_cert_synth_does_not_exist.apk");
    assert!(run_cert(p).is_err());
}

/// The v2 block this file builds is walked byte by byte here so a layout
/// mistake in `v2_signer` cannot pass unnoticed: every field is checked
/// against the spec grammar (each field length-prefixed exactly once) and
/// the real scanner must accept the result with no error.
#[test]
fn v2_block_layout_matches_the_spec() {
    let c = cert(b"v1 signer", &[0x0a]);
    let value = v2_value(&[&c]);
    // Saturating reader: a bad length prefix panics here with the field
    // name, instead of somewhere deep inside the scanner.
    let take = |b: &[u8], at: &mut usize, what: &str| {
        assert!(*at + 4 <= b.len(), "{what}: no length prefix in {b:02x?}");
        let n = u32::from_le_bytes(b[*at..*at + 4].try_into().unwrap()) as usize;
        assert!(
            *at + 4 + n <= b.len(),
            "{what}: length {n} overruns the {}-byte field",
            b.len()
        );
        let out = b[*at + 4..*at + 4 + n].to_vec();
        *at += 4 + n;
        out
    };
    // value = signers sequence = one length-prefixed signer.
    let mut p = 0;
    let seq_body = take(&value, &mut p, "signers sequence");
    assert_eq!(p, value.len(), "trailing bytes after the signers sequence");
    let mut p = 0;
    let signer = take(&seq_body, &mut p, "signer");
    assert_eq!(p, seq_body.len(), "more than one signer");

    // signer = signed-data | signatures | public-key.
    let mut p = 0;
    let signed = take(&signer, &mut p, "signed-data");
    let signatures = take(&signer, &mut p, "signatures");
    let public_key = take(&signer, &mut p, "public key");
    assert_eq!(p, signer.len(), "trailing bytes after the signer");

    // signed-data = digests | certificates.
    let mut p = 0;
    let digests = take(&signed, &mut p, "digests");
    let certificates = take(&signed, &mut p, "certificates");
    assert_eq!(p, signed.len(), "trailing bytes after signed-data");

    // digests / signatures are `sequence-of` blobs holding one record of
    // (length-prefixed algorithm id, length-prefixed value); certificates
    // is a blob of length-prefixed certificate DER.
    let alg_of = |blob: &[u8], what: &str| {
        let mut p = 0;
        let rec = take(blob, &mut p, what);
        assert_eq!(p, blob.len(), "trailing bytes in {what}");
        let alg = u32::from_le_bytes(rec[..4].try_into().unwrap());
        let mut q = 4;
        let value = take(&rec, &mut q, what);
        assert_eq!(q, rec.len(), "trailing bytes in the {what}");
        (alg, value)
    };
    let (digest_alg, digest_val) = alg_of(&digests, "the digest record");
    assert_eq!(digest_alg, 0x0103, "RSASSA-PKCS1-v1_5 with SHA-256");
    assert_eq!(digest_val, b"digest");
    let mut p = 0;
    let cert_der = take(&certificates, &mut p, "certificate");
    assert_eq!(p, certificates.len());
    assert_eq!(cert_der, c.der, "signed-data carries the certificate DER");
    let (sig_alg, sig_val) = alg_of(&signatures, "the signature record");
    assert_eq!(sig_alg, 0x0103);
    assert_eq!(sig_val, b"sig");
    assert_eq!(public_key, b"pubkey");

    // And the scanner must read all of that without an error.
    let apk = zip(
        &[("classes.dex", b"dex\n035\0stub".to_vec())],
        signing_block(&[(ID_V2, value)]),
        None,
    );
    let scan = asc_apk::signing::scan(&apk);
    assert!(
        matches!(scan.block, BlockStatus::Present { .. }),
        "{:?}",
        scan.block
    );
    assert_eq!(scan.pairs.len(), 1);
    assert_eq!(scan.schemes.len(), 1);
    let sb = &scan.schemes[0];
    assert!(sb.error.is_none(), "scan error: {:?}", sb.error);
    assert_eq!(sb.signers.len(), 1);
    assert_eq!(sb.signers[0].certs, std::slice::from_ref(&c.der));
    assert_eq!(sb.signers[0].digest_algs, [0x0103]);
    assert_eq!(sb.signers[0].signature_algs, [0x0103]);
}
