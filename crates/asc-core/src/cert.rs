//! `asc-rs cert`: display-only signing inventory (JAR v1 + APK Signature
//! Scheme v2/v3/v3.1). Fingerprints identify certificates; NOTHING is
//! verified (no signature, digest, chain, validity-at-install or trust
//! check), which every rendering states. Equality between schemes is
//! reported only when the fingerprints actually match, mismatches are
//! shown, and "no signing material found" never means unsigned or valid.

use std::fmt::Write as _;
use std::path::Path;

use asc_apk::der::{CertFields, parse_cert, parse_pkcs7};
use asc_apk::signing::{BlockStatus, SigningScan};
use asc_apk::{Apk, InflateLimits};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::pipeline::CoreError;

/// Cap for one v1 signature-block file.
const V1_CAP: usize = 1 << 20;
const MAX_V1_FILES: usize = 16;
const MAX_ERRORS: usize = 100;
const DISCLAIMER: &str = "verification: not_performed (no signature, digest, chain or trust check; \
     fingerprints only identify certificates)";

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

fn pair_name(id: u32) -> Option<&'static str> {
    match id {
        0x7109_871a => Some("APK Signature Scheme v2"),
        0xf053_68c0 => Some("APK Signature Scheme v3"),
        0x1b93_ad61 => Some("APK Signature Scheme v3.1"),
        _ => None,
    }
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

    let mut schemes = vec![v1_scheme(&apk, &mut errors)];
    for (id, name) in [
        (0x7109_871a, "v2"),
        (0xf053_68c0, "v3"),
        (0x1b93_ad61, "v3.1"),
    ] {
        schemes.push(scheme_from_scan(&scan, id, name, &mut errors));
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
    let note = (!any_present && errors.is_empty()).then(|| {
        "no signing material found; this does not establish that the APK is unsigned, valid or trusted"
            .to_string()
    });
    Ok(CertReport {
        input: path.display().to_string(),
        verification: "not_performed",
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
    let _ = writeln!(s, "input: {}\n{DISCLAIMER}", r.input);
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
        let _ = writeln!(
            s,
            "  pair {} {} bytes ({})",
            p.id,
            p.value_len,
            p.known_as.unwrap_or("not identified")
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
