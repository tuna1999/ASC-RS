//! Headless `--selfcheck` path.
//!
//! Opens an APK, lists its DEX entries, builds the per-DEX class
//! cache, runs one `findrefs` query, decompiles one class, and
//! parses the manifest. Prints a one-line summary of every step to
//! stdout and returns `Err` (→ non-zero exit) unless every engine step
//! demonstrably worked — see [`run_selfcheck`] / [`SelfcheckReport::verify`].
//! Used both by the `asc-gui --selfcheck` binary and by the integration
//! test in `tests/integration.rs`.

use std::path::Path;

use asc_core::{CoreError, FindRefsJob, FindRefsOptions, GetClassJob, GetClassOptions};
use asc_query::Query;

use crate::WorkspaceSession;
use crate::session::SessionError;

/// One-line summary of each selfcheck step.
#[derive(Debug)]
pub struct SelfcheckReport {
    pub apk: String,
    pub dex_count: usize,
    pub class_count: usize,
    /// Non-empty when class enumeration was PARTIAL (a DEX or class_def had
    /// to be skipped) — see [`crate::ClassList::warnings`]. A selfcheck on a
    /// clean fixture must not report a partial class list as success.
    pub class_warnings: Vec<String>,
    pub findrefs_query: String,
    pub findrefs_caller_lines: usize,
    pub findrefs_complete: bool,
    pub findrefs_errors: usize,
    pub decompiled_class: String,
    pub decompiled_source_bytes: usize,
    pub manifest_package: Option<String>,
    pub manifest_version_code: Option<u32>,
    /// Set only when the APK *has* an `AndroidManifest.xml` that could not
    /// be decoded. A manifest-less fixture (e.g. the synthetic workload
    /// corpus) leaves both this and the two fields above `None`, and is
    /// NOT a selfcheck failure.
    pub manifest_error: Option<String>,
}

/// Class name the workload corpus's manifest-package expects — the
/// `<application android:name>` value is `com.example.ReferenceApp`
/// per `reference/BEHAVIOR.md` and `docs/CORPUS.md`. We decompile
/// the Google material `ClockFaceView` that ships inside `workload.apk`
/// (verified to exist by `asc-cli`).
const DEFAULT_TARGET_CLASS: &str = "Lcom/google/android/material/timepicker/ClockFaceView;";

/// Default findrefs pattern — substring match against the const-string
/// payloads referenced by the DEX. This is the frozen oracle/golden
/// query for `workload.apk` (`findrefs_string_workload` in
/// `tests/fixtures/golden/cases.json`), which the parity suite pins at
/// 28 result lines. It must keep matching: a selfcheck whose query
/// returns nothing proves nothing about the scanner (the earlier
/// `"ClockFace"` pattern returned zero hits on this fixture, so an
/// engine that returned empty reports for everything still passed).
const DEFAULT_FINDREFS_PATTERN: &str = "Context";

/// Run the full selfcheck path against `apk`.
///
/// Returns `Err` unless every engine step actually *worked*: the session
/// must open, the class list must be non-empty **and complete**, the
/// findrefs scan must complete without per-DEX errors **and find at least
/// one match for its positive-control query**, and getclass must produce
/// source. Engine failures are never flattened into a zero-count
/// "success" — the binary turns any `Err` into a non-zero exit code, and
/// CI relies on that (see `.github/workflows/ci.yml`'s Selfcheck step).
///
/// Manifest absence is tolerated (the synthetic workload fixture has no
/// `AndroidManifest.xml`); a manifest that is present but undecodable is
/// reported in [`SelfcheckReport::manifest_error`] without failing.
pub fn run_selfcheck(apk: &Path) -> Result<SelfcheckReport, SelfcheckError> {
    let session = WorkspaceSession::open(apk)?;
    let dex_count = session.dex_entries().len();
    // Keep the warnings: a partial class list must not read as success.
    let classes = session.all_classes()?;
    let class_count = classes.classes.len();

    // One findrefs: substring search. A hard engine error propagates.
    let query = Query::string(DEFAULT_FINDREFS_PATTERN);
    let label = format!("string \"{DEFAULT_FINDREFS_PATTERN}\"");
    let findrefs_job = FindRefsJob::new(apk, query);
    let find_opts = FindRefsOptions::default();
    let find_report = asc_core::run_findrefs(&findrefs_job, &find_opts)?;

    // One getclass: decompile ClockFaceView. Likewise fatal on error.
    let get_job = GetClassJob::new(apk, DEFAULT_TARGET_CLASS);
    let get_opts = GetClassOptions::default();
    let decompiled = asc_core::run_getclass(&get_job, &get_opts)?;

    // Manifest via asc-manifest: absence is fine, a decode failure is kept
    // (and surfaced) but does not fail the run — DEX analysis is unaffected.
    let (manifest, manifest_error) = crate::task::load_manifest(apk);

    let report = SelfcheckReport {
        apk: apk.display().to_string(),
        dex_count,
        class_count,
        class_warnings: classes.warnings,
        findrefs_query: label,
        findrefs_caller_lines: find_report.total_lines(),
        findrefs_complete: find_report.complete,
        findrefs_errors: find_report.errors.len(),
        decompiled_class: decompiled.dex_name,
        decompiled_source_bytes: decompiled.source.len(),
        manifest_package: manifest.as_ref().and_then(|m| m.package.clone()),
        manifest_version_code: manifest.as_ref().and_then(|m| m.version_code),
        manifest_error,
    };
    report.verify()?;
    Ok(report)
}

/// Errors from the selfcheck path.
#[derive(Debug, thiserror::Error)]
pub enum SelfcheckError {
    /// APK file could not be opened or parsed.
    #[error("apk open: {0}")]
    Apk(#[from] SessionError),

    /// A core engine call returned Err — we always include the
    /// underlying cause for diagnostics.
    #[error("engine: {0}")]
    Core(#[from] CoreError),

    /// An engine call *returned* but the result proves it did not work
    /// (no classes, a scan that skipped DEXes, a decompile with no
    /// source). `--selfcheck` must exit non-zero for these too, otherwise
    /// a silently broken engine would look like a green CI run.
    #[error("selfcheck incomplete: {0}")]
    Incomplete(String),
}

impl SelfcheckReport {
    /// The success criteria: every engine step a selfcheck exists to prove
    /// must actually have produced work.
    fn verify(&self) -> Result<(), SelfcheckError> {
        let fail = |what: &str| Err(SelfcheckError::Incomplete(what.to_string()));
        if self.dex_count == 0 {
            return fail("no DEX entries in the APK");
        }
        if self.class_count == 0 {
            return fail("class enumeration produced no classes");
        }
        if !self.class_warnings.is_empty() {
            return fail("class enumeration was partial");
        }
        if !self.findrefs_complete {
            return fail("findrefs did not scan every DEX");
        }
        if self.findrefs_errors != 0 {
            return fail("findrefs reported per-DEX errors");
        }
        // `complete`/`errors` only say the scan ran; they say nothing about
        // whether it found anything. Without this, an engine that returned
        // empty reports for every query would look healthy.
        if self.findrefs_caller_lines == 0 {
            return fail("findrefs positive-control query returned no matches");
        }
        if self.decompiled_class.is_empty() || self.decompiled_source_bytes == 0 {
            return fail("getclass produced no source");
        }
        Ok(())
    }
}

impl std::fmt::Display for SelfcheckReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "asc-gui {} selfcheck:", env!("CARGO_PKG_VERSION"))?;
        writeln!(f, "  apk               = {}", self.apk)?;
        writeln!(f, "  dex_count         = {}", self.dex_count)?;
        writeln!(f, "  class_count       = {}", self.class_count)?;
        if !self.class_warnings.is_empty() {
            writeln!(
                f,
                "  class_warnings    = {} (partial enumeration)",
                self.class_warnings.len()
            )?;
            for w in &self.class_warnings {
                writeln!(f, "    - {w}")?;
            }
        }
        writeln!(
            f,
            "  findrefs          = query={}, lines={}, complete={}, errors={}",
            self.findrefs_query,
            self.findrefs_caller_lines,
            self.findrefs_complete,
            self.findrefs_errors
        )?;
        writeln!(
            f,
            "  getclass          = dex={}, source_bytes={}",
            self.decompiled_class, self.decompiled_source_bytes
        )?;
        writeln!(
            f,
            "  manifest          = package={:?}, versionCode={:?}",
            self.manifest_package, self.manifest_version_code
        )?;
        if let Some(err) = &self.manifest_error {
            writeln!(f, "  manifest_error    = {err}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A report where every engine step worked, minus the fields a test
    /// overrides. Nothing here is asserted by `verify` beyond the fields
    /// set below.
    fn report(dex_count: usize, class_count: usize) -> SelfcheckReport {
        SelfcheckReport {
            apk: "fixture.apk".into(),
            dex_count,
            class_count,
            class_warnings: Vec::new(),
            findrefs_query: "string \"Context\"".into(),
            findrefs_caller_lines: 3,
            findrefs_complete: true,
            findrefs_errors: 0,
            decompiled_class: "classes.dex".into(),
            decompiled_source_bytes: 1234,
            manifest_package: None,
            manifest_version_code: None,
            manifest_error: None,
        }
    }

    #[test]
    fn a_fully_working_report_verifies() {
        assert!(report(1, 500).verify().is_ok());
    }

    #[test]
    fn verify_rejects_each_engine_step_that_did_not_work() {
        assert!(report(0, 500).verify().is_err(), "no DEX entries");
        assert!(report(1, 0).verify().is_err(), "no classes");

        let mut r = report(1, 500);
        r.findrefs_complete = false;
        assert!(r.verify().is_err(), "findrefs skipped a DEX");

        let mut r = report(1, 500);
        r.findrefs_errors = 2;
        assert!(r.verify().is_err(), "findrefs reported errors");

        // `complete`/`errors` alone do not prove the scan found anything:
        // an engine that returns an empty report for every query satisfies
        // both. The workload's frozen positive control ("Context") has 28
        // hits, so zero hits means the scanner is broken.
        let mut r = report(1, 500);
        r.findrefs_caller_lines = 0;
        assert!(r.verify().is_err(), "positive control matched nothing");

        // A partial class list (a DEX or class_def skipped) is not a
        // complete enumeration of a clean fixture, however many classes
        // were read.
        let mut r = report(1, 500);
        r.class_warnings = vec!["classes2.dex: parse failed (bad header)".into()];
        assert!(r.verify().is_err(), "partial class enumeration");

        let mut r = report(1, 500);
        r.decompiled_source_bytes = 0;
        assert!(r.verify().is_err(), "empty decompile");

        let mut r = report(1, 500);
        r.decompiled_class.clear();
        assert!(r.verify().is_err(), "no winning dex");

        // A manifest that exists but failed to decode is surfaced in the
        // report, NOT turned into a failed selfcheck (DEX analysis is
        // unaffected, and the workload fixture has no manifest at all).
        let mut r = report(1, 500);
        r.manifest_error = Some("manifest decode failed: bad chunk".into());
        assert!(r.verify().is_ok(), "manifest failure is informational");
    }

    /// End-to-end return semantics: an APK with no DEX at all cannot
    /// satisfy a selfcheck. The pre-fix code flattened every engine error
    /// into zero counts and returned `Ok` → the binary exited 0.
    #[test]
    fn dex_less_apk_fails_the_selfcheck() {
        let apk = crate::test_zip::write_temp_apk(
            "selfcheck_no_dex",
            &[("assets/readme.txt", b"no dex here")],
        );
        let outcome = run_selfcheck(&apk);
        let _ = std::fs::remove_file(&apk);
        let err = outcome.expect_err("an APK with no DEX must not pass the selfcheck");
        assert!(!err.to_string().is_empty());
    }
}
