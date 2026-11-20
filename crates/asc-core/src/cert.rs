//! `asc-rs cert`: signing inventory (JAR v1 + APK Signature Scheme
//! v2/v3/v3.1). Each v2/v3 signer is verified the way `apksig` does it:
//! every supported signature over the signed data, the signed key against
//! the first certificate, the algorithm lists, the v3 SDK copies and the
//! chunked content digests. v1 JAR signatures, chains, revocation and
//! trust are NOT checked, which every rendering states. Equality between
//! schemes is reported only when the fingerprints actually match, and "no
//! signing material found" never means unsigned or valid.

use std::fmt::Write as _;
use std::path::Path;

use asc_apk::der::{CertFields, parse_cert, parse_pkcs7};
use asc_apk::signing::{BlockStatus, SignerBlock, SigningScan};
use asc_apk::{Apk, InflateLimits};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::pipeline::CoreError;

/// Cap for one v1 signature-block file.
const V1_CAP: usize = 1 << 20;
const MAX_V1_FILES: usize = 16;
const MAX_ERRORS: usize = 100;
const DISCLAIMER: &str = "verification: not_performed (no signature, digest, chain or trust check; \
     fingerprints only identify certificates)";
const V2V3_NOTE: &str = "verification: v2_v3 (v2/v3/v3.1 signatures and content digests checked per \
     signer; v1 JAR, chain, revocation and trust NOT checked)";
const CHUNK: usize = 1 << 20;

#[derive(Debug, Clone, Serialize)]
pub struct CertInfo {
    /// `signer`, `chain` or `unmatched` (v1 signer could not be identified).
    pub role: &'static str,
    pub sha256: String,
    pub sha1: String,
    pub der_len: usize,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub serial: Option<String>,
    pub x509_version: Option<u32>,
    pub signature_algorithm: Option<String>,
    pub key_algorithm: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub parse_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignerReport {
    /// Signature file (v1) or `signer N` (v2/v3).
    pub source: String,
    pub digest_algorithms: Vec<u32>,
    pub signature_algorithms: Vec<u32>,
    pub min_sdk: Option<u32>,
    pub max_sdk: Option<u32>,
    pub certs: Vec<CertInfo>,
    /// v2/v3 only; `None` for v1 (JAR signatures are not verified).
    pub verification: Option<SignerVerification>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignerVerification {
    /// `verified` (>=1 signature and >=1 content digest checked, nothing
    /// failed), `failed`, or `unsupported` (nothing failed, but no
    /// signature or no content digest could be checked).
    pub status: &'static str,
    /// One line per check: `ok: ...`, `FAIL: ...` or `skip: ...`.
    pub checks: Vec<String>,
}

#[derive(Clone, Copy, PartialEq)]
enum Hash {
    S256,
    S512,
}

/// Signature algorithm -> (key kind, signature hash, content digest).
/// `None` content = verity (Merkle) digest, not computed. DSA (0x0301,
/// 0x0425) is unsupported. IDs from AOSP `apksig` `SignatureAlgorithm`.
fn alg_spec(id: u32) -> Option<(&'static str, Hash, Option<Hash>)> {
    Some(match id {
        0x0101 => ("rsa-pss", Hash::S256, Some(Hash::S256)),
        0x0102 => ("rsa-pss", Hash::S512, Some(Hash::S512)),
        0x0103 => ("rsa-pkcs1", Hash::S256, Some(Hash::S256)),
        0x0104 => ("rsa-pkcs1", Hash::S512, Some(Hash::S512)),
        0x0201 => ("ecdsa", Hash::S256, Some(Hash::S256)),
        0x0202 => ("ecdsa", Hash::S512, Some(Hash::S512)),
        0x0421 => ("rsa-pkcs1", Hash::S256, None),
        0x0423 => ("ecdsa", Hash::S256, None),
        _ => return None,
    })
}

/// Outer `Err` = key could not be loaded (a skip, not a failure: e.g. an
/// RSA key above the crate's 4096-bit cap); inner `Err` = signature
/// rejected.
fn verify_sig(
    kind: &str,
    hash: Hash,
    spki: &[u8],
    data: &[u8],
    sig: &[u8],
) -> Result<Result<(), String>, String> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::{Pkcs1v15Sign, Pss, RsaPublicKey};
    let digest = match hash {
        Hash::S256 => Sha256::digest(data).to_vec(),
        Hash::S512 => Sha512::digest(data).to_vec(),
    };
    if kind == "ecdsa" {
        use p256::pkcs8::DecodePublicKey as _;
        if let Ok(k) = p256::ecdsa::VerifyingKey::from_public_key_der(spki) {
            let s = p256::ecdsa::Signature::from_der(sig).map_err(|e| format!("signature: {e}"));
            return Ok(s.and_then(|s| k.verify_prehash(&digest, &s).map_err(|e| e.to_string())));
        }
        if let Ok(k) = p384::ecdsa::VerifyingKey::from_public_key_der(spki) {
            let s = p384::ecdsa::Signature::from_der(sig).map_err(|e| format!("signature: {e}"));
            return Ok(s.and_then(|s| k.verify_prehash(&digest, &s).map_err(|e| e.to_string())));
        }
        return Err("EC key is not P-256/P-384 or is malformed".into());
    }
    let k = RsaPublicKey::from_public_key_der(spki).map_err(|e| format!("RSA key: {e}"))?;
    let r = match (kind, hash) {
        ("rsa-pss", Hash::S256) => k.verify(Pss::new::<Sha256>(), &digest, sig),
        ("rsa-pss", Hash::S512) => k.verify(Pss::new::<Sha512>(), &digest, sig),
        (_, Hash::S256) => k.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, sig),
        (_, Hash::S512) => k.verify(Pkcs1v15Sign::new::<Sha512>(), &digest, sig),
    };
    Ok(r.map_err(|e| e.to_string()))
}

/// APK Signature Scheme v2 chunked content digest: sections
/// `[0, block)`, `[cd, eocd)` and the EOCD with its CD offset rewritten
/// to `block`; 1 MiB chunks hashed as `0xa5|len|data`, then
/// `0x5a|count|chunk digests`.
fn content_digest<D: Digest>(buf: &[u8], (block, cd, eocd): (usize, usize, usize)) -> Vec<u8> {
    let mut tail = buf[eocd..].to_vec();
    tail[16..20].copy_from_slice(&(block as u32).to_le_bytes());
    let mut acc = Vec::new();
    let mut n = 0u32;
    for sec in [&buf[..block], &buf[cd..eocd], &tail[..]] {
        for c in sec.chunks(CHUNK) {
            let mut h = D::new();
            h.update([0xa5]);
            h.update((c.len() as u32).to_le_bytes());
            h.update(c);
            acc.extend_from_slice(&h.finalize());
            n += 1;
        }
    }
    let mut h = D::new();
    h.update([0x5a]);
    h.update(n.to_le_bytes());
    h.update(&acc);
    h.finalize().to_vec()
}

/// Lazily computed content digests, shared by every v2/v3 signer.
struct Digests<'a> {
    buf: &'a [u8],
    layout: Option<(usize, usize, usize)>,
    s256: Option<Vec<u8>>,
    s512: Option<Vec<u8>>,
}

impl Digests<'_> {
    fn get(&mut self, h: Hash) -> Option<&[u8]> {
        let (buf, l) = (self.buf, self.layout?);
        let slot = match h {
            Hash::S256 => &mut self.s256,
            Hash::S512 => &mut self.s512,
        };
        Some(slot.get_or_insert_with(|| match h {
            Hash::S256 => content_digest::<Sha256>(buf, l),
            Hash::S512 => content_digest::<Sha512>(buf, l),
        }))
    }
}

fn verify_signer(s: &SignerBlock, digests: &mut Digests) -> SignerVerification {
    let mut checks = Vec::new();
    let (mut fail, mut sigs_ok, mut digests_ok) = (false, 0, 0);
    let mut check = |ok: bool, msg: String, checks: &mut Vec<String>| {
        fail |= !ok;
        checks.push(format!("{}: {msg}", if ok { "ok" } else { "FAIL" }));
    };
    if s.signatures.is_empty() {
        check(false, "no signatures".into(), &mut checks);
    }
    for (alg, sig) in &s.signatures {
        let Some((kind, hash, _)) = alg_spec(*alg) else {
            checks.push(format!(
                "skip: signature 0x{alg:04x}: unsupported algorithm"
            ));
            continue;
        };
        match verify_sig(kind, hash, &s.public_key, &s.signed_data, sig) {
            Err(e) => checks.push(format!("skip: signature 0x{alg:04x}: {e}")),
            Ok(Ok(())) => {
                sigs_ok += 1;
                check(true, format!("signature 0x{alg:04x} ({kind})"), &mut checks);
            }
            Ok(Err(e)) => check(
                false,
                format!("signature 0x{alg:04x} ({kind}): {e}"),
                &mut checks,
            ),
        }
    }
    check(
        s.digest_algs == s.signature_algs,
        "digest and signature algorithm lists match".into(),
        &mut checks,
    );
    let key_match = s
        .certs
        .first()
        .and_then(|c| parse_cert(c).ok())
        .is_some_and(|f| f.spki_raw == s.public_key);
    check(
        key_match,
        "signed public key matches the first certificate".into(),
        &mut checks,
    );
    if let Some(u) = s.unsigned_sdk {
        check(
            Some(u) == s.min_sdk.zip(s.max_sdk),
            "unsigned and signed SDK range match".into(),
            &mut checks,
        );
    }
    for (alg, want) in &s.digests {
        match alg_spec(*alg) {
            None => checks.push(format!(
                "skip: content digest 0x{alg:04x}: unsupported algorithm"
            )),
            Some((_, _, None)) => checks.push(format!(
                "skip: content digest 0x{alg:04x}: verity digest not computed"
            )),
            Some((_, _, Some(h))) => match digests.get(h) {
                None => checks.push(format!(
                    "skip: content digest 0x{alg:04x}: signing block layout unknown"
                )),
                Some(got) => {
                    let ok = got == want.as_slice();
                    digests_ok += usize::from(ok);
                    check(ok, format!("content digest 0x{alg:04x}"), &mut checks);
                }
            },
        }
    }
    let status = if fail {
        "failed"
    } else if sigs_ok > 0 && digests_ok > 0 {
        "verified"
    } else {
        "unsupported"
    };
    SignerVerification { status, checks }
}

#[derive(Debug, Clone, Serialize)]
pub struct SchemeReport {
    pub name: &'static str,
    /// `present`, `absent`, `malformed` or `unknown` (could not be scanned).
    pub status: &'static str,
    pub errors: Vec<String>,
    pub signers: Vec<SignerReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PairReport {
    pub id: String,
    pub value_len: u64,
    pub known_as: Option<&'static str>,
    /// `signature`, `source-stamp`, `padding` or `metadata` when the
    /// pair ID is known — keeps stamps/Play metadata from being read
    /// as signing certificates.
    pub kind: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertReport {
    pub input: String,
    pub verification: &'static str,
    /// `absent`, `present`, `malformed` or `unsupported`.
    pub block_status: &'static str,
    pub block_offset: Option<u64>,
    pub block_size: Option<u64>,
    pub block_detail: Option<String>,
    pub pairs: Vec<PairReport>,
    pub schemes: Vec<SchemeReport>,
    pub comparison: Vec<String>,
    pub note: Option<String>,
    pub errors: Vec<String>,
    pub complete: bool,
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn cert_info(der: &[u8], role: &'static str, errors: &mut Vec<String>, ctx: &str) -> CertInfo {
    let mut c = CertInfo {
        role,
        sha256: hex(&Sha256::digest(der)),
        sha1: hex(&Sha1::digest(der)),
        der_len: der.len(),
        subject: None,
        issuer: None,
        serial: None,
        x509_version: None,
        signature_algorithm: None,
        key_algorithm: None,
        not_before: None,
        not_after: None,
        parse_errors: Vec::new(),
    };
    match parse_cert(der) {
        Ok(f) => apply(&mut c, f),
        Err(e) => c.parse_errors.push(e),
    }
    for e in &c.parse_errors {
        if errors.len() < MAX_ERRORS {
            errors.push(format!("{ctx}: certificate {}: {e}", &c.sha256[..16]));
        }
    }
    c
}

fn apply(c: &mut CertInfo, f: CertFields) {
    c.subject = Some(f.subject);
    c.issuer = Some(f.issuer);
    c.serial = Some(f.serial_hex);
    c.x509_version = f.version;
    c.signature_algorithm = Some(f.signature_algorithm);
    c.key_algorithm = Some(f.key_algorithm);
    match f.not_before {
        Ok(t) => c.not_before = Some(t),
        Err(e) => c.parse_errors.push(format!("notBefore: {e}")),
    }
    match f.not_after {
        Ok(t) => c.not_after = Some(t),
        Err(e) => c.parse_errors.push(format!("notAfter: {e}")),
    }
}

fn is_v1_sig_file(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("META-INF/") else {
        return false;
    };
    let l = rest.to_ascii_lowercase();
    !rest.contains('/') && (l.ends_with(".rsa") || l.ends_with(".dsa") || l.ends_with(".ec"))
}

fn scheme_from_scan(
    scan: &SigningScan,
    id: u32,
    name: &'static str,
    errors: &mut Vec<String>,
    digests: &mut Digests,
) -> SchemeReport {
    let mut rep = SchemeReport {
        name,
        status: "absent",
        errors: Vec::new(),
        signers: Vec::new(),
    };
    match &scan.block {
        BlockStatus::Malformed(_) => rep.status = "malformed",
        BlockStatus::Unsupported(_) => rep.status = "unknown",
        _ => {}
    }
    // A malformed block may still have yielded schemes parsed before the fault.
    for sb in scan.schemes.iter().filter(|s| s.id == id) {
        rep.status = "present";
        for (i, s) in sb.signers.iter().enumerate() {
            let ctx = format!("{name} signer {i}");
            rep.signers.push(SignerReport {
                source: format!("signer {i}"),
                digest_algorithms: s.digest_algs.clone(),
                signature_algorithms: s.signature_algs.clone(),
                min_sdk: s.min_sdk,
                max_sdk: s.max_sdk,
                certs: s
                    .certs
                    .iter()
                    .enumerate()
                    .map(|(k, d)| {
                        cert_info(d, if k == 0 { "signer" } else { "chain" }, errors, &ctx)
                    })
                    .collect(),
                verification: Some(verify_signer(s, digests)),
            });
        }
        if let Some(e) = &sb.error {
            rep.status = "malformed";
            rep.errors.push(e.clone());
        }
    }
    rep
}

fn v1_scheme(apk: &Apk, errors: &mut Vec<String>) -> SchemeReport {
    let mut rep = SchemeReport {
        name: "v1",
        status: "absent",
        errors: Vec::new(),
        signers: Vec::new(),
    };
    let cap = InflateLimits::with_max_output(V1_CAP).unwrap_or_default();
    let files: Vec<_> = apk.entries().filter(|e| is_v1_sig_file(&e.name)).collect();
    if files.len() > MAX_V1_FILES {
        rep.errors.push(format!(
            "{} signature files; only {MAX_V1_FILES} read",
            files.len()
        ));
    }
    for e in files.iter().take(MAX_V1_FILES) {
        rep.status = "present";
        let bytes = if e.uncompressed_size as usize > V1_CAP {
            Err(format!("exceeds {} KiB cap", V1_CAP >> 10))
        } else {
            apk.read_entry_with_limits(e, cap)
                .map_err(|x| x.to_string())
        };
        let parsed = bytes.and_then(|b| parse_pkcs7(b.as_slice()));
        match parsed {
            Err(x) => rep.errors.push(format!("{}: {x}", e.name)),
            Ok(p) => {
                let infos: Vec<CertInfo> = p
                    .certs
                    .iter()
                    .map(|d| cert_info(d, "unmatched", errors, &e.name))
                    .collect();
                // Identify the signer by IssuerAndSerialNumber; never assume.
                let mut certs = infos;
                for (i, der) in p.certs.iter().enumerate() {
                    if let Ok(f) = parse_cert(der) {
                        let is_signer = p
                            .signer_ids
                            .iter()
                            .any(|(iss, ser)| *iss == f.issuer_raw && *ser == f.serial_raw);
                        certs[i].role = if is_signer { "signer" } else { "chain" };
                    }
                }
                if !p.signer_ids.is_empty() && certs.iter().all(|c| c.role != "signer") {
                    certs.iter_mut().for_each(|c| c.role = "unmatched");
                }
                rep.signers.push(SignerReport {
                    source: e.name.clone(),
                    digest_algorithms: Vec::new(),
                    signature_algorithms: Vec::new(),
                    min_sdk: None,
                    max_sdk: None,
                    certs,
                    verification: None,
                });
            }
        }
    }
    if !rep.errors.is_empty() {
        rep.status = "malformed";
    }
    rep
}

fn signer_prints(s: &SchemeReport) -> Vec<&str> {
    let mut v: Vec<&str> = s
        .signers
        .iter()
        .flat_map(|x| x.certs.iter())
        .filter(|c| c.role == "signer")
        .map(|c| c.sha256.as_str())
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Signing-block pair classification. Verified against AOSP
/// `tools/apksig` (`ApkSigningBlockUtils.VERITY_PADDING_BLOCK_ID`,
/// `SourceStampConstants.{V1,V2}_SOURCE_STAMP_BLOCK_ID`) and Google
/// Play "frosting" documentation for `0x2146444e` (protobuf
/// distribution metadata, not a signature).
fn pair_kind(id: u32) -> Option<(&'static str, &'static str)> {
    match id {
        0x7109_871a => Some(("APK Signature Scheme v2", "signature")),
        0xf053_68c0 => Some(("APK Signature Scheme v3", "signature")),
        0x1b93_ad61 => Some(("APK Signature Scheme v3.1", "signature")),
        0x2b09_189e => Some(("Source Stamp v1", "source-stamp")),
        0x6dff_800d => Some(("Source Stamp v2", "source-stamp")),
        0x4272_6577 => Some(("Verity padding block", "padding")),
        0x2146_444e => Some(("Google Play security metadata (\"frosting\")", "metadata")),
        _ => None,
    }
}

fn pair_name(id: u32) -> Option<&'static str> {
    pair_kind(id).map(|(name, _)| name)
}

/// Inventory the signing material of `path` (an APK).
pub fn run_cert(path: &Path) -> Result<CertReport, CoreError> {
    let apk = Apk::open(path)?;
    if apk.is_raw_dex() {
        return Err(CoreError::Usage(
            "input is a raw DEX; 'cert' requires an APK".into(),
        ));
    }
    let scan = apk.signing_scan();
    let mut errors = Vec::new();
    let push = |e: String, errors: &mut Vec<String>| {
        if errors.len() < MAX_ERRORS {
            errors.push(e);
        }
    };

    let mut digests = Digests {
        buf: apk.bytes(),
        layout: scan
            .layout
            .map(|(b, c, e)| (b as usize, c as usize, e as usize)),
        s256: None,
        s512: None,
    };
    let mut schemes = vec![v1_scheme(&apk, &mut errors)];
    for (id, name) in [
        (0x7109_871a, "v2"),
        (0xf053_68c0, "v3"),
        (0x1b93_ad61, "v3.1"),
    ] {
        schemes.push(scheme_from_scan(&scan, id, name, &mut errors, &mut digests));
    }
    for s in &schemes {
        for e in &s.errors {
            push(format!("{}: {e}", s.name), &mut errors);
        }
    }
    let (block_status, off, size, detail) = match &scan.block {
        BlockStatus::Absent => ("absent", None, None, None),
        BlockStatus::Present { offset, size } => ("present", Some(*offset), Some(*size), None),
        BlockStatus::Malformed(m) => ("malformed", None, None, Some(m.clone())),
        BlockStatus::Unsupported(m) => ("unsupported", None, None, Some(m.clone())),
    };
    if let Some(d) = &detail {
        push(format!("signing block: {d}"), &mut errors);
    }

    let mut comparison = Vec::new();
    for (i, a) in schemes.iter().enumerate() {
        for b in &schemes[i + 1..] {
            let (pa, pb) = (signer_prints(a), signer_prints(b));
            if pa.is_empty() || pb.is_empty() {
                continue;
            }
            comparison.push(if pa == pb {
                format!(
                    "{} and {} signer certificate fingerprints (SHA-256) match",
                    a.name, b.name
                )
            } else {
                format!(
                    "{} and {} signer certificates DIFFER (SHA-256 sets are not equal)",
                    a.name, b.name
                )
            });
        }
    }
    let any_present = schemes.iter().any(|s| s.status == "present");
    let verified_any = schemes
        .iter()
        .flat_map(|s| &s.signers)
        .any(|s| s.verification.is_some());
    let note = (!any_present && errors.is_empty()).then(|| {
        "no signing material found; this does not establish that the APK is unsigned, valid or trusted"
            .to_string()
    });
    Ok(CertReport {
        input: path.display().to_string(),
        verification: if verified_any {
            "v2_v3"
        } else {
            "not_performed"
        },
        block_status,
        block_offset: off,
        block_size: size,
        block_detail: detail,
        pairs: scan
            .pairs
            .iter()
            .map(|p| PairReport {
                id: format!("0x{:08x}", p.id),
                value_len: p.value_len,
                known_as: pair_name(p.id),
                kind: pair_kind(p.id).map(|(_, k)| k),
            })
            .collect(),
        schemes,
        comparison,
        note,
        complete: errors.is_empty(),
        errors,
    })
}

fn algs(v: &[u32]) -> String {
    if v.is_empty() {
        return "-".into();
    }
    v.iter()
        .map(|a| format!("0x{a:08x}"))
        .collect::<Vec<_>>()
        .join(",")
}

pub fn format_cert_text(r: &CertReport) -> String {
    let mut s = String::new();
    let header = if r.verification == "v2_v3" {
        V2V3_NOTE
    } else {
        DISCLAIMER
    };
    let _ = writeln!(s, "input: {}\n{header}", r.input);
    match (r.block_offset, r.block_size) {
        (Some(o), Some(z)) => {
            let _ = writeln!(s, "signing block: present at offset {o}, {z} bytes");
        }
        _ => {
            let _ = writeln!(
                s,
                "signing block: {}{}",
                r.block_status,
                r.block_detail
                    .as_deref()
                    .map(|d| format!(" ({d})"))
                    .unwrap_or_default()
            );
        }
    }
    for p in &r.pairs {
        let kind = p.kind.unwrap_or("unknown");
        let _ = writeln!(
            s,
            "  pair {} {} bytes ({} [{}])",
            p.id,
            p.value_len,
            p.known_as.unwrap_or("not identified"),
            kind
        );
    }
    for sc in &r.schemes {
        let _ = writeln!(s, "scheme {}: {}", sc.name, sc.status);
        for sg in &sc.signers {
            let sdk = match (sg.min_sdk, sg.max_sdk) {
                (Some(a), Some(b)) => format!(", sdk {a}..{b}"),
                _ => String::new(),
            };
            let _ = writeln!(
                s,
                "  {} (digest algs {}, signature algs {}{sdk})",
                sg.source,
                algs(&sg.digest_algorithms),
                algs(&sg.signature_algorithms)
            );
            if let Some(v) = &sg.verification {
                let _ = writeln!(s, "    verification: {}", v.status);
                for c in &v.checks {
                    let _ = writeln!(s, "      {c}");
                }
            }
            for c in &sg.certs {
                let _ = writeln!(
                    s,
                    "    cert [{}] sha256 {}\n      sha1   {}",
                    c.role, c.sha256, c.sha1
                );
                let f = |o: &Option<String>| o.clone().unwrap_or_else(|| "unavailable".into());
                let _ = writeln!(
                    s,
                    "      subject: {}\n      issuer: {}\n      serial: {}, x509 version: {}\n      algorithms: signature {}, key {}\n      valid: {} .. {}",
                    f(&c.subject),
                    f(&c.issuer),
                    f(&c.serial),
                    c.x509_version.map_or("1".to_string(), |v| v.to_string()),
                    f(&c.signature_algorithm),
                    f(&c.key_algorithm),
                    f(&c.not_before),
                    f(&c.not_after),
                );
            }
        }
    }
    for c in &r.comparison {
        let _ = writeln!(s, "comparison: {c}");
    }
    if let Some(n) = &r.note {
        let _ = writeln!(s, "note: {n}");
    }
    for e in &r.errors {
        let _ = writeln!(s, "error: {e}");
    }
    let _ = writeln!(s, "complete: {}", r.complete);
    s
}
