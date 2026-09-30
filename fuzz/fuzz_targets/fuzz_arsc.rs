//! Contract: `asc_resources::parse` never panics on arbitrary bytes, retains
//! at most its item budget, and every entry ID carries its package ID.
//! Behind `resources` feature.

use crate::FuzzOutcome;

#[cfg(feature = "resources")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    let Ok(t) = asc_resources::parse(input) else {
        return FuzzOutcome::BoundaryHit("arsc_reject");
    };
    let mut items = 0usize;
    for p in &t.packages {
        for e in &p.entries {
            assert_eq!(e.id >> 24, p.id);
            assert_eq!(e.id & 0xffff, e.entry_index as u32);
            assert!((e.config as usize) < p.configs.len());
            items += 1;
            if let asc_resources::Value::Bag { items: it, .. } = &e.value {
                items += it.len();
            }
            let _ = p.type_name(e.type_id);
            let _ = p.key_name(e);
        }
        for c in &p.configs {
            let _ = asc_resources::describe_config(c);
        }
    }
    assert!(items <= 1 << 21);
    FuzzOutcome::Ok
}

#[cfg(not(feature = "resources"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
