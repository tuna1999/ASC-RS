//! `run_cert` against real APKs (each test skips when its fixture is
//! absent). Golden fingerprints were cross-checked with
//! `openssl pkcs7 -print_certs | openssl x509 -fingerprint -sha256`.

use asc_core::cert::run_cert;

/// `true` when the fixture basename matches an entry of the
/// comma-separated `ASC_REQUIRE_CORPUS` list (CI sets it after
/// recreating the corpus fixtures it guarantees; a listed fixture that
/// is still missing must fail, not silently skip).
fn require_corpus(var: &str, p: &std::path::Path) -> bool {
    std::env::var(var).is_ok_and(|req| {
        req.split(',').any(|f| {
            let f = f.trim();
            !f.is_empty()
                && p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(f))
        })
    })
}
fn fixture(name: &str) -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/apk")
        .join(name);
    if !p.exists() {
        eprintln!("skipping: {name} not present");
    }
    if !p.exists() && require_corpus("ASC_REQUIRE_CORPUS", &p) {
        panic!(
            "ASC_REQUIRE_CORPUS is set but fixture missing: {}",
            p.display()
        );
    }
    p.exists().then_some(p)
}

fn signer_sha(r: &asc_core::CertReport, scheme: &str) -> Vec<String> {
    r.schemes
        .iter()
        .filter(|s| s.name == scheme)
        .flat_map(|s| &s.signers)
        .flat_map(|s| &s.certs)
        .filter(|c| c.role == "signer")
        .map(|c| c.sha256.clone())
        .collect()
}

#[test]
fn fdroid_v1_v2_v3_agree_with_openssl_fingerprint() {
    let Some(p) = fixture("org.fdroid.fdroid_1016000.apk") else {
        return;
    };
    let r = run_cert(&p).expect("run_cert");
    assert!(r.complete, "{:?}", r.errors);
    assert_eq!(r.verification, "not_performed");
    let golden =
        "43238d512c1e5eb2d6569f4a3afbf552 3418b82e0a3ed1552770abb9a9c9ccab".replace(' ', "");
    for scheme in ["v1", "v2", "v3"] {
        assert_eq!(
            signer_sha(&r, scheme),
            std::slice::from_ref(&golden),
            "{scheme}"
        );
    }
    assert_eq!(r.comparison.len(), 3);
    // v3 carries the SDK range; v2 does not.
    let v3 = r.schemes.iter().find(|s| s.name == "v3").unwrap();
    assert_eq!(v3.signers[0].min_sdk, Some(24));
    assert_eq!(v3.signers[0].signature_algorithms[0], 0x103);
}

#[test]
fn locket_is_v2_v3_only_and_v1_absent() {
    let Some(p) = fixture("com.locket.Locket.apk") else {
        return;
    };
    let r = run_cert(&p).expect("run_cert");
    assert!(r.complete, "{:?}", r.errors);
    let status = |n: &str| r.schemes.iter().find(|s| s.name == n).unwrap().status;
    assert_eq!(
        (status("v1"), status("v2"), status("v3")),
        ("absent", "present", "present")
    );
    assert!(r.note.is_none());
}

#[test]
fn unsigned_apk_never_claims_unsigned() {
    let Some(p) = fixture("workload.apk") else {
        return;
    };
    let r = run_cert(&p).expect("run_cert");
    assert!(r.complete && r.schemes.iter().all(|s| s.status == "absent"));
    let note = r.note.expect("note");
    assert!(note.contains("does not establish"), "{note}");
}
