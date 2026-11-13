//! `run_call_tree` against a real corpus DEX. Skips silently when the
//! fixture is absent (`corpus/` is gitignored; CI recreates it).

use asc_core::{CallTreeJob, CallTreeOptions, run_call_tree};

const CLASS: &str = "Landroidx/constraintlayout/widget/d;";
const METHOD: &str = "i";

fn dex() -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/dex/aurora_classes.dex");
    if !p.exists() {
        eprintln!("skipping: {} not present", p.display());
    }
    p.exists().then_some(p)
}

#[test]
fn tree_expands_two_hops_and_states_its_depth() {
    let Some(p) = dex() else { return };
    let job = CallTreeJob::new(&p, CLASS, METHOD);
    let out = run_call_tree(
        &job,
        &CallTreeOptions {
            depth: 2,
            max_nodes: 400,
            ..CallTreeOptions::default()
        },
    )
    .expect("tree");
    assert!(!out.nodes.is_empty(), "the root method invokes something");
    assert!(
        out.nodes.iter().all(|n| (1..=2).contains(&n.depth)),
        "no edge may exceed the requested depth"
    );
    assert!(
        out.nodes.iter().any(|n| n.depth == 2),
        "the second hop expands"
    );
    assert_eq!(out.nodes[0].from_class, CLASS, "root edges come first");
}

#[test]
fn node_budget_truncates_instead_of_growing() {
    let Some(p) = dex() else { return };
    let job = CallTreeJob::new(&p, CLASS, METHOD);
    let out = run_call_tree(
        &job,
        &CallTreeOptions {
            depth: 5,
            max_nodes: 20,
            ..CallTreeOptions::default()
        },
    )
    .expect("tree");
    assert!(out.nodes.len() >= 20);
    assert!(out.truncated, "hitting the budget must be reported");
}
