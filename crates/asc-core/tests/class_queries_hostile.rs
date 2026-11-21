//! Hostile-input bounds of `findrefs extends|impl` and `listmethod`
//! (`asc_core::classes`): many class_def rows pointing at ONE shared
//! type_list / class_data must exhaust the per-DEX work budget and be
//! reported incomplete, not walk the shared list once per row.

mod common;

use asc_core::classes::{HierarchyKind, run_hierarchy, run_listmethods};
use common::{ACC_PUBLIC_STATIC, Dex, OBJECT, write_apk};

const PAD: usize = 300;
const METHODS: usize = 300;
const PARAMS: usize = 300;

fn rd(b: &[u8], off: usize) -> usize {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as usize
}

fn wr(b: &mut [u8], off: usize, v: usize) {
    b[off..off + 4].copy_from_slice(&(v as u32).to_le_bytes());
}

/// `Lh/Big;` defines METHODS methods (one of them takes PARAMS
/// parameters) and PAD one-method classes precede it. `shared` then
/// points every class_def at Big's class_data and at the PARAMS-long
/// parameter type_list as its interface list.
fn dex(shared: bool) -> Vec<u8> {
    let big = "Lh/Big;";
    let wide: Vec<&'static str> = vec![OBJECT; PARAMS];
    let names: Vec<&'static str> = (0..METHODS)
        .map(|i| &*Box::leak(format!("m{i}").into_boxed_str()))
        .collect();
    let pads: Vec<String> = (0..PAD).map(|i| format!("Lpad/P{i};")).collect();
    let mut members: Vec<common::Member> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let params = if i == 0 { wide.clone() } else { vec![] };
            (big.to_string(), *n, ("V", params))
        })
        .collect();
    members.extend(pads.iter().map(|p| (p.clone(), "p", ("V", vec![]))));
    let d = Dex::new(&[OBJECT, big], vec![], members, &[]);
    let mut classes: Vec<common::ClassSpec<'_>> = pads
        .iter()
        .map(|p| {
            (
                p.as_str(),
                vec![],
                vec![("p", ACC_PUBLIC_STATIC, 0, 0, vec![0x000E])],
            )
        })
        .collect();
    let big_methods = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let ins = if i == 0 { PARAMS as u16 } else { 0 };
            (*n, ACC_PUBLIC_STATIC, ins, ins, vec![0x000E])
        })
        .collect();
    classes.push((big, vec![], big_methods));
    let mut b = d.finish(&classes);
    if shared {
        let (protos, nprotos) = (rd(&b, 0x4C), rd(&b, 0x48));
        let params_off = (0..nprotos)
            .map(|i| rd(&b, protos + i * 12 + 8))
            .find(|&o| o != 0 && rd(&b, o) == PARAMS)
            .expect("wide proto type_list");
        let (defs, ndefs) = (rd(&b, 0x64), rd(&b, 0x60));
        let big_data = rd(&b, defs + (ndefs - 1) * 32 + 24);
        for i in 0..ndefs {
            wr(&mut b, defs + i * 32 + 12, params_off);
            wr(&mut b, defs + i * 32 + 24, big_data);
        }
    }
    b
}

#[test]
fn shared_lists_exhaust_the_work_budget() {
    let honest = write_apk("cq_honest", &[("classes.dex", dex(false))]);
    let h = run_hierarchy(&honest, OBJECT, HierarchyKind::Extends, false).unwrap();
    assert!(h.issues.complete, "{:?}", h.issues.errors);
    assert_eq!(h.hits.len(), PAD + 1);
    let m = run_listmethods(&honest, None, None, usize::MAX).unwrap();
    assert!(m.issues.complete, "{:?}", m.issues.errors);
    assert_eq!(m.total_matched, PAD + METHODS);

    let len = dex(true).len();
    assert!(PAD * PARAMS.min(METHODS) > len, "fixture too small");
    let hostile = write_apk("cq_hostile", &[("classes.dex", dex(true))]);
    let h = run_hierarchy(&hostile, OBJECT, HierarchyKind::Impl, false).unwrap();
    assert!(!h.issues.complete);
    assert!(h.issues.errors.iter().any(|e| e.contains("work budget")));
    assert!(h.hits.len() < PAD + 1);
    let m = run_listmethods(&hostile, None, None, usize::MAX).unwrap();
    assert!(!m.issues.complete);
    assert!(m.issues.errors.iter().any(|e| e.contains("work budget")));
    assert!(m.total_matched < (PAD + 1) * METHODS);
}
