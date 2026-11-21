//! Corpus-free tests for `asc_core::cert::run_cert`.
//!
//! Every archive here is built byte by byte: a hand-rolled minimal X.509 /
//! PKCS#7 SignedData, a STORED ZIP writer, and the APK Signing Block layout
//! from the v2/v3 spec (`u64 size | pairs | u64 size | "APK Sig Block 42"`).
//! Nothing is read from `corpus/`, so the suite is self-contained.
//!
//! No real signature is built: v2/v3 signers here carry junk keys and
//! signatures, so their verification must come out `failed` (the positive
//! and tamper cases run against the real F-Droid APK in `cert_inventory`).

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
    // No MANIFEST.MF and a SignerInfo without a signature: v1 is checked
    // and fails; it must never read as valid.
    assert_eq!(r.verification, "v1");
    let v = v1.signers[0].verification.as_ref().unwrap();
    assert_eq!(v.status, "failed", "{:?}", v.checks);
    let text = format_cert_text(&r);
    assert!(text.contains("verification: failed"), "{text}");
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

/// A v2 signer whose signature, key and digest are junk must never come
/// out `verified`: the signed key differs from the certificate and the
/// content digest is wrong, so the signer fails rather than skipping.
#[test]
fn forged_v2_signer_fails_verification() {
    let c = cert(b"v2 forger", &[0x01]);
    let r = run("forged_v2", &v1_v2_apk(&[&c], &[signer_info(&c)], &[&c]));
    assert_eq!(r.verification, "v1_v2_v3");
    let v = scheme(&r, "v2").signers[0].verification.as_ref().unwrap();
    assert_eq!(v.status, "failed", "{:?}", v.checks);
    assert!(
        v.checks
            .iter()
            .any(|c| c == "FAIL: signed public key matches the first certificate")
    );
    assert!(v.checks.iter().any(|c| c == "FAIL: content digest 0x0103"));
    let v1 = scheme(&r, "v1").signers[0].verification.as_ref().unwrap();
    assert_eq!(v1.status, "failed", "{:?}", v1.checks);
}

// ------------------------------------------------------ real v1 JAR signatures

fn b64(b: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                s.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// A P-256 self-signed-shaped certificate whose SPKI is the real key, and a
/// v1 APK (`MANIFEST.MF`, `CERT.SF`, `CERT.EC`) signed with it. `tamper`
/// rewrites the parts after signing.
fn signed_v1_apk(tamper: impl Fn(&mut Vec<(&'static str, Vec<u8>)>)) -> Vec<u8> {
    signed_v1_apk_with(None, tamper)
}

/// `entry`: the MANIFEST.MF body after the main section (default: one
/// correct `classes.dex` section). The `.SF` signs it as one section, so
/// the signature and the whole-manifest digest always hold.
fn signed_v1_apk_with(
    entry: Option<&str>,
    tamper: impl Fn(&mut Vec<(&'static str, Vec<u8>)>),
) -> Vec<u8> {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    // SubjectPublicKeyInfo { id-ecPublicKey, prime256v1 } + uncompressed point.
    let point = key.verifying_key().to_encoded_point(false);
    let spki = tlv(
        0x30,
        &[
            tlv(
                0x30,
                &[
                    tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
                    tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
                ]
                .concat(),
            ),
            tlv(0x03, &[&[0u8][..], point.as_bytes()].concat()),
        ]
        .concat(),
    );
    let issuer = name(b"v1 real signer");
    let alg = alg_id(OID_ECDSA_SHA256);
    let tbs = tlv(
        0x30,
        &[
            tlv(0xA0, &tlv(0x02, &[2])),
            tlv(0x02, &[0x33]),
            alg.clone(),
            issuer.clone(),
            tlv(
                0x30,
                &[utc_time(b"240101000000Z"), utc_time(b"490101000000Z")].concat(),
            ),
            issuer.clone(),
            spki,
        ]
        .concat(),
    );
    let c = Cert {
        der: tlv(0x30, &[tbs, alg, tlv(0x03, &[0x00])].concat()),
        issuer,
        serial: vec![0x33],
    };
    let dex = b"dex\n035\0stub".to_vec();
    let entry = entry.map_or_else(
        || {
            format!(
                "Name: classes.dex\r\nSHA-256-Digest: {}\r\n\r\n",
                b64(&Sha256::digest(&dex))
            )
        },
        str::to_string,
    );
    let mf = format!("Manifest-Version: 1.0\r\n\r\n{entry}");
    let sf = format!(
        "Signature-Version: 1.0\r\nSHA-256-Digest-Manifest: {}\r\n\r\nName: classes.dex\r\nSHA-256-Digest: {}\r\n\r\n",
        b64(&Sha256::digest(mf.as_bytes())),
        b64(&Sha256::digest(entry.as_bytes()))
    );
    let sig: Signature = key.sign(sf.as_bytes());
    let si = tlv(
        0x30,
        &[
            tlv(0x02, &[1]),
            tlv(0x30, &[c.issuer.clone(), tlv(0x02, &c.serial)].concat()),
            alg_id(OID_SHA256),
            tlv(0x30, &tlv(0x06, OID_ECDSA_SHA256)),
            tlv(0x04, sig.to_der().as_bytes()),
        ]
        .concat(),
    );
    let mut parts = vec![
        ("classes.dex", dex),
        ("META-INF/MANIFEST.MF", mf.into_bytes()),
        ("META-INF/CERT.SF", sf.into_bytes()),
        ("META-INF/CERT.EC", pkcs7(&[&c], &[si])),
    ];
    tamper(&mut parts);
    zip(&parts, Vec::new(), None)
}

fn v1_status(r: &CertReport) -> (&'static str, Vec<String>) {
    let v = scheme(r, "v1").signers[0]
        .verification
        .as_ref()
        .expect("v1 signer verified");
    (v.status, v.checks.clone())
}

#[test]
fn real_v1_signature_verifies() {
    let r = run("v1_real", &signed_v1_apk(|_| {}));
    assert_eq!(r.verification, "v1");
    let (status, checks) = v1_status(&r);
    assert_eq!(status, "verified", "{checks:?}");
    assert!(checks.iter().all(|c| !c.starts_with("FAIL")), "{checks:?}");
    assert!(format_cert_text(&r).contains("verification: v1 ("));
}

#[test]
fn tampered_v1_entry_fails() {
    let r = run(
        "v1_tamper_dex",
        &signed_v1_apk(|p| p[0].1 = b"dex\n035\0evil".to_vec()),
    );
    let (status, checks) = v1_status(&r);
    assert_eq!(status, "failed", "{checks:?}");
    assert!(
        checks
            .iter()
            .any(|c| c == "FAIL: classes.dex: SHA-256-Digest does not match the entry"),
        "{checks:?}"
    );
}

#[test]
fn v1_entry_added_after_signing_fails() {
    let r = run(
        "v1_extra",
        &signed_v1_apk(|p| p.push(("assets/payload.bin", b"x".to_vec()))),
    );
    let (status, checks) = v1_status(&r);
    assert_eq!(status, "failed", "{checks:?}");
    assert!(
        checks
            .iter()
            .any(|c| c == "FAIL: assets/payload.bin is not covered by MANIFEST.MF"),
        "{checks:?}"
    );
}

#[test]
fn v1_signature_over_edited_sf_fails() {
    let r = run(
        "v1_sf",
        &signed_v1_apk(|p| p[2].1.extend_from_slice(b"X-Extra: 1\r\n")),
    );
    let (status, checks) = v1_status(&r);
    assert_eq!(status, "failed", "{checks:?}");
    assert!(
        checks
            .iter()
            .any(|c| c.starts_with("FAIL: signature over META-INF/CERT.SF")),
        "{checks:?}"
    );
}

/// Review finding: a section without a supported digest must not count
/// as coverage, or the entry is never hashed and can be swapped freely.
#[test]
fn v1_section_without_supported_digest_is_not_coverage() {
    let entry = "Name: classes.dex\r\nMD5-Digest: AAAA\r\n\r\n";
    let r = run(
        "v1_md5_only",
        &signed_v1_apk_with(Some(entry), |p| p[0].1 = b"evil".to_vec()),
    );
    let (status, checks) = v1_status(&r);
    assert_eq!(status, "failed", "{checks:?}");
    assert!(
        checks
            .iter()
            .any(|c| c == "FAIL: classes.dex is not covered by MANIFEST.MF"),
        "{checks:?}"
    );
}

/// Review finding: a repeated section is rejected (and hashed once).
#[test]
fn v1_repeated_manifest_section_fails() {
    let one = format!(
        "Name: classes.dex\r\nSHA-256-Digest: {}\r\n\r\n",
        b64(&Sha256::digest(b"dex\n035\0stub"))
    );
    let r = run(
        "v1_repeat",
        &signed_v1_apk_with(Some(&one.repeat(3)), |_| {}),
    );
    let (status, checks) = v1_status(&r);
    assert_eq!(status, "failed", "{checks:?}");
    assert!(
        checks
            .iter()
            .any(|c| c == "FAIL: MANIFEST.MF repeats the section for classes.dex"),
        "{checks:?}"
    );
}

/// Review finding: a non-ASCII attribute name must not panic the digest
/// scan (byte offset inside a multi-byte char).
#[test]
fn v1_non_ascii_attribute_name_does_not_panic() {
    let entry = format!(
        "Name: classes.dex\r\né123456: x\r\nSHA-256-Digest: {}\r\n\r\n",
        b64(&Sha256::digest(b"dex\n035\0stub"))
    );
    let r = run("v1_utf8", &signed_v1_apk_with(Some(&entry), |_| {}));
    let (status, checks) = v1_status(&r);
    assert_eq!(status, "verified", "{checks:?}");
}
