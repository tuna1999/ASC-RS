//! `SharedFlags` are `#[arg(global = true)]`: every one of them is valid
//! before *or* after the positional arguments (the oracle's argparse is
//! equally permissive). A command that only parses with the flag in
//! front is a real break — scripts append flags.
//!
//! No fixture is needed: a missing path fails inside `Apk::open`, so the
//! assertions compare the engine-error path instead of output bytes.

use std::process::Command;

fn run_cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_asc-rs"))
        .args(args)
        .output()
        .expect("spawn asc-rs")
}

#[test]
fn global_flag_after_positional_is_accepted() {
    let before = run_cli(&["listclass", "--format", "json", "no-such-artifact.apk"]);
    let after = run_cli(&["listclass", "no-such-artifact.apk", "--format", "json"]);

    let stderr = String::from_utf8_lossy(&after.stderr).into_owned();
    assert!(
        !stderr.contains("unexpected argument"),
        "flag rejected after the positional: {stderr}"
    );
    assert_eq!(
        after.status.code(),
        before.status.code(),
        "flag position changed the outcome"
    );
    assert_eq!(
        after.status.code(),
        Some(2),
        "missing artifact is an engine error"
    );
    assert_eq!(
        String::from_utf8_lossy(&before.stderr),
        String::from_utf8_lossy(&after.stderr),
        "flag position changed the message"
    );
}

#[test]
fn global_flag_value_is_validated_in_either_position() {
    for args in [
        ["listclass", "--format", "bogus", "no-such-artifact.apk"],
        ["listclass", "no-such-artifact.apk", "--format", "bogus"],
    ] {
        let out = run_cli(&args);
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            stderr.contains("invalid value 'bogus'"),
            "value not validated for {args:?}: {stderr}"
        );
    }
}
