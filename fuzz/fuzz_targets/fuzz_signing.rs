//! Contract: `signing::scan`, `der::parse_cert` and `der::parse_pkcs7` never
//! panic on arbitrary bytes and stay within their pair/signer/cert/item
//! budgets. Behind `apk` feature.

use crate::FuzzOutcome;

#[cfg(feature = "apk")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_apk::{der, signing};

    let scan = signing::scan(input);
    assert!(scan.pairs.len() <= 1024);
    for s in &scan.schemes {
        assert!(s.signers.len() <= 16);
        for sg in &s.signers {
            assert!(sg.certs.len() <= 16);
            for c in &sg.certs {
                let _ = der::parse_cert(c);
            }
        }
    }
    let cert = der::parse_cert(input).is_ok();
    let p7 = der::parse_pkcs7(input).is_ok();
    if cert || p7 || !scan.pairs.is_empty() {
        FuzzOutcome::Ok
    } else {
        FuzzOutcome::BoundaryHit("signing_reject")
    }
}

#[cfg(not(feature = "apk"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
