//! JAR (v1) signature verification, following AOSP `apksig`
//! `V1SchemeVerifier`: the PKCS#7 signature over the `.SF` file (directly
//! or through its signed attributes), the `.SF` digests of `MANIFEST.MF`
//! (whole file, else main attributes + per entry), and the `MANIFEST.MF`
//! digests of every ZIP entry. Every ZIP entry outside the signature files
//! must be covered. Chains, revocation and trust are not checked.

use std::collections::{HashMap, HashSet};

use asc_apk::der::{SignerInfo, parse_cert};
use asc_apk::{Apk, InflateLimits};

use super::{Hash, SignerVerification, hash_bytes, verify_sig};

/// Cap for `MANIFEST.MF` / one `.SF` file.
const MF_CAP: usize = 32 << 20;
/// Entries above this are not hashed (reported as a skip).
const MAX_ENTRY: u64 = 256 << 20;
/// Failure lines kept per category; the rest are counted.
const MAX_LINES: usize = 20;
/// Total entry bytes hashed per APK; the rest are reported as skipped.
const HASH_BUDGET: u64 = 1 << 30;

/// One manifest section: its raw bytes (including the terminating blank
/// line) and its attributes (continuation lines unfolded).
#[derive(Debug)]
pub(super) struct Section<'a> {
    pub raw: &'a [u8],
    pub attrs: Vec<(String, String)>,
}

impl Section<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }
}

/// Split a JAR manifest into its main section and the named sections.
pub(super) fn parse_manifest(b: &[u8]) -> (Section<'_>, Vec<Section<'_>>) {
    let mut sections = Vec::new();
    let (mut start, mut pos) = (0, 0);
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut flush = |start: usize, end: usize, lines: &mut Vec<Vec<u8>>| {
        let attrs = lines
            .drain(..)
            .filter_map(|l| {
                let s = String::from_utf8_lossy(&l).into_owned();
                let (k, v) = s.split_once(':')?;
                Some((k.to_string(), v.strip_prefix(' ').unwrap_or(v).to_string()))
            })
            .collect();
        sections.push(Section {
            raw: &b[start..end],
            attrs,
        });
    };
    while pos < b.len() {
        let nl = b[pos..]
            .iter()
            .position(|&c| c == b'\n' || c == b'\r')
            .map_or(b.len(), |i| pos + i);
        let mut next = nl;
        if next < b.len() {
            next += if b[next] == b'\r' && b.get(next + 1) == Some(&b'\n') {
                2
            } else {
                1
            };
        }
        let line = &b[pos..nl];
        if line.is_empty() {
            if lines.is_empty() && pos == start {
                // Stray blank line between sections: belongs to nothing.
                start = next;
            } else {
                flush(start, next, &mut lines);
                start = next;
            }
        } else if line[0] == b' ' {
            if let Some(last) = lines.last_mut() {
                last.extend_from_slice(&line[1..]);
            }
        } else {
            lines.push(line.to_vec());
        }
        pos = next;
    }
    if start < b.len() {
        flush(start, b.len(), &mut lines);
    }
    let mut it = sections.into_iter();
    let main = it.next().unwrap_or(Section {
        raw: &[],
        attrs: Vec::new(),
    });
    (main, it.collect())
}

/// Standard base64 (RFC 4648), padding optional, whitespace rejected.
pub(super) fn b64(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// JAR digest attribute prefix -> hash (`SHA-256-Digest`, `SHA1-Digest`, ...).
fn jar_hash(prefix: &str) -> Option<Hash> {
    Some(match prefix.to_ascii_uppercase().as_str() {
        "SHA1" | "SHA-1" => Hash::S1,
        "SHA-256" => Hash::S256,
        "SHA-384" => Hash::S384,
        "SHA-512" => Hash::S512,
        _ => return None,
    })
}

/// Every `<ALG><suffix>` attribute of a section with a known algorithm.
fn digests_of(sec: &Section<'_>, suffix: &str) -> Vec<(Hash, String, String)> {
    sec.attrs
        .iter()
        .filter_map(|(k, v)| {
            let p = k.len().checked_sub(suffix.len())?;
            // `get`: a hostile non-ASCII key may put `p` inside a char.
            if !k.get(p..)?.eq_ignore_ascii_case(suffix) {
                return None;
            }
            Some((jar_hash(k.get(..p)?)?, k.clone(), v.clone()))
        })
        .collect()
}

fn oid_hash(oid: &[u8]) -> Option<Hash> {
    Some(match oid {
        [0x2B, 0x0E, 0x03, 0x02, 0x1A] => Hash::S1,
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => Hash::S256,
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02] => Hash::S384,
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] => Hash::S512,
        _ => return None,
    })
}

/// Key kind from the SignerInfo signature algorithm: RSA PKCS#1 v1.5
/// (`1.2.840.113549.1.1.{1,5,11,12,13}`) or ECDSA (`1.2.840.10045.*`).
/// DSA and RSA-PSS are not verified.
fn sig_kind(oid: &[u8]) -> Option<&'static str> {
    const RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01];
    const EC: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D];
    if let Some(&[n]) = oid.strip_prefix(RSA) {
        return matches!(n, 1 | 5 | 11 | 12 | 13).then_some("rsa-pkcs1");
    }
    oid.starts_with(EC).then_some("ecdsa")
}

fn is_sig_related(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("META-INF/") else {
        return false;
    };
    if rest.contains('/') {
        return false;
    }
    let u = rest.to_ascii_uppercase();
    u == "MANIFEST.MF"
        || u.starts_with("SIG-")
        || [".SF", ".RSA", ".DSA", ".EC"]
            .iter()
            .any(|x| u.ends_with(x))
}

/// Outcome of checking `MANIFEST.MF` against the ZIP entries, computed once
/// and shared by every v1 signer.
pub(super) struct EntryCheck {
    lines: Vec<String>,
    fail: bool,
    skip: bool,
}

fn push_capped(lines: &mut Vec<String>, n: &mut usize, msg: String) {
    *n += 1;
    if *n <= MAX_LINES {
        lines.push(msg);
    }
}

pub(super) fn read_capped(apk: &Apk, name: &str) -> Result<Vec<u8>, String> {
    let e = apk.entry(name).ok_or_else(|| format!("{name} missing"))?;
    if e.uncompressed_size > MF_CAP as u64 {
        return Err(format!("{name} exceeds {} MiB cap", MF_CAP >> 20));
    }
    let cap = InflateLimits { max_output: MF_CAP };
    apk.read_entry_with_limits(&e, cap)
        .map(|b| b.as_slice().to_vec())
        .map_err(|x| format!("{name}: {x}"))
}

pub(super) fn check_entries(apk: &Apk, mf: &[u8]) -> EntryCheck {
    let (mut lines, mut fail, mut skip) = (Vec::new(), false, false);
    let (_, sections) = parse_manifest(mf);
    let mut counts: HashMap<&str, usize> = HashMap::new();
    let entries: Vec<_> = apk.entries().collect();
    for e in &entries {
        *counts.entry(e.name.as_str()).or_default() += 1;
    }
    let dups: Vec<_> = counts.iter().filter(|(_, n)| **n > 1).collect();
    if !dups.is_empty() {
        fail = true;
        let mut names: Vec<_> = dups.iter().map(|(k, _)| **k).collect();
        names.sort_unstable();
        lines.push(format!(
            "FAIL: duplicate ZIP entry names (ambiguous content): {}",
            names.join(", ")
        ));
    }
    let (mut ok, mut bad, mut missing, mut skipped) = (0usize, 0, 0, 0);
    let mut covered: HashSet<&str> = HashSet::new();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut budget = HASH_BUDGET;
    for sec in &sections {
        let Some(name) = sec.get("Name") else {
            continue;
        };
        // apksig rejects a repeated section; hashing it again is also free
        // CPU for a hostile manifest.
        if !seen.insert(name) {
            fail = true;
            push_capped(
                &mut lines,
                &mut bad,
                format!("FAIL: MANIFEST.MF repeats the section for {name}"),
            );
            continue;
        }
        let ds = digests_of(sec, "-Digest");
        if ds.is_empty() {
            // No supported digest: the entry is NOT covered (directories
            // and absent names are ignored by the coverage pass anyway).
            continue;
        }
        covered.insert(name);
        let Some(e) = apk.entry(name) else {
            fail = true;
            push_capped(
                &mut lines,
                &mut missing,
                format!("FAIL: MANIFEST.MF names {name}, which is not in the ZIP"),
            );
            continue;
        };
        if e.uncompressed_size > MAX_ENTRY || e.uncompressed_size > budget {
            skip = true;
            push_capped(
                &mut lines,
                &mut skipped,
                format!(
                    "skip: {name} above the {} MiB entry or {} MiB total hashing cap",
                    MAX_ENTRY >> 20,
                    HASH_BUDGET >> 20
                ),
            );
            continue;
        }
        budget -= e.uncompressed_size;
        let limits = InflateLimits {
            max_output: e.uncompressed_size as usize + 1,
        };
        let bytes = match apk.read_entry_with_limits(&e, limits) {
            Ok(b) => b,
            Err(x) => {
                fail = true;
                push_capped(&mut lines, &mut bad, format!("FAIL: {name}: {x}"));
                continue;
            }
        };
        let mut good = true;
        for (h, key, want) in &ds {
            if b64(want).as_deref() != Some(hash_bytes(*h, bytes.as_slice()).as_slice()) {
                good = false;
                push_capped(
                    &mut lines,
                    &mut bad,
                    format!("FAIL: {name}: {key} does not match the entry"),
                );
            }
        }
        if good {
            ok += 1;
        } else {
            fail = true;
        }
    }
    let mut uncovered = 0;
    for e in &entries {
        if e.name.ends_with('/') || is_sig_related(&e.name) || covered.contains(e.name.as_str()) {
            continue;
        }
        fail = true;
        push_capped(
            &mut lines,
            &mut uncovered,
            format!("FAIL: {} is not covered by MANIFEST.MF", e.name),
        );
    }
    for (n, what) in [
        (missing, "missing entries"),
        (bad, "digest mismatches"),
        (uncovered, "uncovered entries"),
        (skipped, "skipped entries"),
    ] {
        if n > MAX_LINES {
            lines.push(format!("... {} more {what}", n - MAX_LINES));
        }
    }
    if ok > 0 {
        lines.insert(0, format!("ok: {ok} entry digest(s) match MANIFEST.MF"));
    }
    EntryCheck { lines, fail, skip }
}

/// Verify one v1 signer: `block` is the PKCS#7 file (`X.RSA`/`.EC`/`.DSA`),
/// `sf_name` its `.SF`, `mf` the `MANIFEST.MF` bytes (or why it is
/// unreadable), `entries` the shared ZIP-entry check.
pub(super) fn verify_v1_signer(
    apk: &Apk,
    block: &str,
    infos: &[SignerInfo],
    signer_ids: usize,
    certs: &[Vec<u8>],
    mf: &Result<Vec<u8>, String>,
    entries: &Option<EntryCheck>,
) -> SignerVerification {
    let mut checks = Vec::new();
    let (mut fail, mut skip) = (false, false);
    let mut check = |ok: bool, msg: String, checks: &mut Vec<String>| {
        fail |= !ok;
        checks.push(format!("{}: {msg}", if ok { "ok" } else { "FAIL" }));
    };
    let stem = &block[..block.rfind('.').unwrap_or(block.len())];
    let sf_name = format!("{stem}.SF");
    let sf = match read_capped(apk, &sf_name) {
        Ok(b) => b,
        Err(e) => {
            check(false, format!("signature file: {e}"), &mut checks);
            return SignerVerification {
                status: "failed",
                checks,
            };
        }
    };
    // 1. PKCS#7 signature over the .SF.
    let mut sig_ok = false;
    // Android accepts exactly one SignerInfo; an unparsable one is not
    // silently replaced by the next.
    if infos.len() != 1 || signer_ids != 1 {
        check(
            false,
            format!(
                "expected exactly one SignerInfo ({signer_ids} declared, {} parsed)",
                infos.len()
            ),
            &mut checks,
        );
    }
    match infos.first().filter(|_| signer_ids == infos.len()) {
        None => check(
            false,
            "no SignerInfo in the signature block".into(),
            &mut checks,
        ),
        Some(si) => {
            let key = certs
                .iter()
                .filter_map(|d| parse_cert(d).ok())
                .find(|f| f.issuer_raw == si.issuer_raw && f.serial_raw == si.serial_raw);
            match (key, oid_hash(&si.digest_oid), sig_kind(&si.signature_oid)) {
                (None, ..) => check(
                    false,
                    "signer certificate not in the block".into(),
                    &mut checks,
                ),
                (_, None, _) | (_, _, None) => {
                    skip = true;
                    checks.push(
                        "skip: signature/digest algorithm not supported (DSA, RSA-PSS or unknown)"
                            .into(),
                    );
                }
                (Some(cert), Some(h), Some(kind)) => {
                    let data = match (&si.signed_attrs, &si.message_digest) {
                        (Some(attrs), Some(md)) => {
                            check(
                                *md == hash_bytes(h, &sf),
                                format!("signed attributes messageDigest matches {sf_name}"),
                                &mut checks,
                            );
                            // Signed over as an explicit SET OF (RFC 5652 5.4).
                            let mut d = attrs.clone();
                            if let Some(t) = d.first_mut() {
                                *t = 0x31;
                            }
                            Some(d)
                        }
                        (Some(_), None) => {
                            check(
                                false,
                                "signed attributes lack messageDigest".into(),
                                &mut checks,
                            );
                            None
                        }
                        (None, _) => Some(sf.clone()),
                    };
                    if let Some(data) = data {
                        match verify_sig(kind, h, &cert.spki_raw, &data, &si.signature) {
                            Err(e) => {
                                skip = true;
                                checks.push(format!("skip: signature: {e}"));
                            }
                            Ok(r) => {
                                sig_ok = r.is_ok();
                                check(
                                    sig_ok,
                                    match r {
                                        Ok(()) => format!("signature over {sf_name} ({kind})"),
                                        Err(e) => format!("signature over {sf_name} ({kind}): {e}"),
                                    },
                                    &mut checks,
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    // 2. .SF digests of MANIFEST.MF.
    match mf {
        Err(e) => check(false, format!("MANIFEST.MF: {e}"), &mut checks),
        Ok(mf) => {
            let (sf_main, sf_secs) = parse_manifest(&sf);
            let whole = digests_of(&sf_main, "-Digest-Manifest");
            let whole_ok = whole
                .iter()
                .any(|(h, _, v)| b64(v).as_deref() == Some(hash_bytes(*h, mf).as_slice()));
            if whole_ok {
                check(
                    true,
                    format!("{sf_name} digest of the whole MANIFEST.MF"),
                    &mut checks,
                );
            } else {
                if !whole.is_empty() {
                    checks.push(format!(
                        "note: {sf_name} whole-manifest digest differs; checking per entry"
                    ));
                }
                let (mf_main, mf_secs) = parse_manifest(mf);
                for (h, key, v) in digests_of(&sf_main, "-Digest-Manifest-Main-Attributes") {
                    check(
                        b64(&v).as_deref() == Some(hash_bytes(h, mf_main.raw).as_slice()),
                        format!("{sf_name} {key}"),
                        &mut checks,
                    );
                }
                let by_name: HashMap<&str, &Section<'_>> = mf_secs
                    .iter()
                    .filter_map(|s| Some((s.get("Name")?, s)))
                    .collect();
                let (mut ok, mut bad) = (0usize, 0usize);
                let mut listed = HashSet::new();
                for s in &sf_secs {
                    let Some(name) = s.get("Name") else { continue };
                    listed.insert(name);
                    let good = by_name.get(name).is_some_and(|m| {
                        let ds = digests_of(s, "-Digest");
                        !ds.is_empty()
                            && ds.iter().all(|(h, _, v)| {
                                b64(v).as_deref() == Some(hash_bytes(*h, m.raw).as_slice())
                            })
                    });
                    if good {
                        ok += 1;
                    } else {
                        bad += 1;
                        if bad <= MAX_LINES {
                            check(
                                false,
                                format!("{sf_name}: section {name} does not match MANIFEST.MF"),
                                &mut checks,
                            );
                        }
                    }
                }
                let unlisted = by_name.keys().filter(|n| !listed.contains(*n)).count();
                if unlisted > 0 {
                    check(
                        false,
                        format!("{unlisted} MANIFEST.MF section(s) not signed by {sf_name}"),
                        &mut checks,
                    );
                }
                if bad > MAX_LINES {
                    checks.push(format!("... {} more section mismatches", bad - MAX_LINES));
                }
                check(
                    ok > 0 || (bad == 0 && unlisted == 0 && by_name.is_empty()),
                    format!("{ok} section digest(s) in {sf_name} match"),
                    &mut checks,
                );
            }
        }
    }
    // 3. MANIFEST.MF digests of the ZIP entries (shared).
    if let Some(ec) = entries {
        fail |= ec.fail;
        skip |= ec.skip;
        checks.extend(ec.lines.iter().cloned());
    }
    let status = if fail {
        "failed"
    } else if sig_ok && !skip {
        "verified"
    } else {
        "unsupported"
    };
    SignerVerification { status, checks }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_known_vectors() {
        assert_eq!(b64("").unwrap(), b"");
        assert_eq!(b64("Zg==").unwrap(), b"f");
        assert_eq!(b64("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(b64("Zm9vYg").unwrap(), b"foob");
        assert!(b64("Zm9v YmFy").is_none());
    }

    #[test]
    fn manifest_sections_keep_raw_bytes_and_unfold_lines() {
        let mf = b"Manifest-Version: 1.0\r\n\r\nName: res/a_very_long_na\r\n me.xml\r\nSHA-256-Digest: AAAA\r\n\r\nName: b\r\nSHA1-Digest: BB==\r\n";
        let (main, secs) = parse_manifest(mf);
        assert_eq!(main.raw, b"Manifest-Version: 1.0\r\n\r\n");
        assert_eq!(secs.len(), 2);
        assert_eq!(secs[0].get("name"), Some("res/a_very_long_name.xml"));
        assert_eq!(
            secs[0].raw,
            b"Name: res/a_very_long_na\r\n me.xml\r\nSHA-256-Digest: AAAA\r\n\r\n"
        );
        // The last section has no blank terminator: it runs to EOF.
        assert_eq!(secs[1].raw, b"Name: b\r\nSHA1-Digest: BB==\r\n");
        let d = digests_of(&secs[1], "-Digest");
        assert_eq!(d.len(), 1);
        assert!(d[0].0 == Hash::S1);
    }

    #[test]
    fn signature_files_are_excluded_from_coverage() {
        assert!(is_sig_related("META-INF/MANIFEST.MF"));
        assert!(is_sig_related("META-INF/CERT.SF"));
        assert!(is_sig_related("META-INF/cert.rsa"));
        assert!(is_sig_related("META-INF/SIG-x"));
        assert!(!is_sig_related("META-INF/a.version"));
        assert!(!is_sig_related("META-INF/sub/CERT.SF"));
        assert!(!is_sig_related("classes.dex"));
    }
}
