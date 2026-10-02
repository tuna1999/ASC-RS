//! Contract: `asc_manifest::axml::parse_axml` never panics on arbitrary
//! bytes, and when a document does parse, `format_axml_text` walks and
//! renders the whole tree without panicking. Rejections are boundary
//! hits, not failures. Behind `manifest` feature.

use crate::FuzzOutcome;

#[cfg(feature = "manifest")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    let doc = match asc_manifest::axml::parse_axml(input) {
        Ok(doc) => doc,
        Err(_) => return FuzzOutcome::BoundaryHit("axml_reject"),
    };
    let text = asc_manifest::axml::format_axml_text(&doc);
    if doc.root.is_some() {
        // A document with a root element must render something.
        assert!(!text.is_empty());
    }
    FuzzOutcome::Ok
}

#[cfg(not(feature = "manifest"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
