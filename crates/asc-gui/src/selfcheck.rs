//! Headless `--selfcheck` path.
//!
//! Opens an APK, lists its DEX entries, builds the per-DEX class
//! cache, runs one `findrefs` query, decompiles one class, and
//! parses the manifest. Exits 0 on success; prints a one-line summary
//! of every step to stdout. Used both by the `asc-gui --selfcheck`
//! binary and by the integration test in `tests/integration.rs`.

use std::path::Path;

use asc_core::{
    CoreError, FindRefsJob, FindRefsOptions, GetClassJob, GetClassOptions,
};
use asc_query::Query;

use crate::session::SessionError;
use crate::WorkspaceSession;

/// One-line summary of each selfcheck step.
#[derive(Debug)]
pub struct SelfcheckReport {
    pub apk: String,
    pub dex_count: usize,
    pub class_count: usize,
    pub findrefs_query: String,
    pub findrefs_caller_lines: usize,
    pub findrefs_complete: bool,
    pub findrefs_errors: usize,
    pub decompiled_class: String,
    pub decompiled_source_bytes: usize,
    pub manifest_package: Option<String>,
    pub manifest_version_code: Option<u32>,
}

/// Class name the workload corpus's manifest-package expects — the
/// `<application android:name>` value is `com.example.ReferenceApp`
/// per `reference/BEHAVIOR.md` and `corpus/MANIFEST.md`. We decompile
/// the Google material `ClockFaceView` that ships inside `workload.apk`
/// (verified to exist by `asc-cli`).
const DEFAULT_TARGET_CLASS: &str =
    "Lcom/google/android/material/timepicker/ClockFaceView;";

/// Default findrefs pattern — substring match against any string
/// referenced from the chosen target.
const DEFAULT_FINDREFS_PATTERN: &str = "ClockFace";

/// Run the full selfcheck path against `apk`. Returns a
/// `SelfcheckReport` summarizing every step. Designed to never panic
/// on engine errors — engine failures are reflected in the report's
/// fields (zero counts, `complete=false`).
pub fn run_selfcheck(apk: &Path) -> Result<SelfcheckReport, SelfcheckError> {
    let session = WorkspaceSession::open(apk)?;
    let dex_count = session.dex_entries().len();
    let class_count = session.all_classes()?.len();

    // One findrefs: substring search.
    let query = Query::string(DEFAULT_FINDREFS_PATTERN);
    let label = format!("string \"{DEFAULT_FINDREFS_PATTERN}\"");
    let findrefs_job = FindRefsJob::new(apk, query);
    let find_opts = FindRefsOptions::default();
    let find_report = asc_core::run_findrefs(&findrefs_job, &find_opts);
    let (caller_lines, complete, errors) = match find_report {
        Ok(r) => (r.total_lines(), r.complete, r.errors.len()),
        Err(_) => (0, false, 1),
    };

    // One getclass: decompile ClockFaceView.
    let get_job = GetClassJob::new(apk, DEFAULT_TARGET_CLASS);
    let get_opts = GetClassOptions::default();
    let decompiled = asc_core::run_getclass(&get_job, &get_opts);
    let (decompiled_target, source_bytes) = match decompiled {
        Ok(r) => (r.dex_name, r.source.len()),
        Err(_) => (String::new(), 0),
    };

    // Manifest via asc-manifest.
    let manifest_info = asc_manifest::parse_from_apk(apk).ok();

    Ok(SelfcheckReport {
        apk: apk.display().to_string(),
        dex_count,
        class_count,
        findrefs_query: label,
        findrefs_caller_lines: caller_lines,
        findrefs_complete: complete,
        findrefs_errors: errors,
        decompiled_class: decompiled_target,
        decompiled_source_bytes: source_bytes,
        manifest_package: manifest_info.as_ref().and_then(|m| m.package.clone()),
        manifest_version_code: manifest_info.as_ref().and_then(|m| m.version_code),
    })
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
}

impl std::fmt::Display for SelfcheckReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "asc-gui selfcheck:")?;
        writeln!(f, "  apk               = {}", self.apk)?;
        writeln!(f, "  dex_count         = {}", self.dex_count)?;
        writeln!(f, "  class_count       = {}", self.class_count)?;
        writeln!(
            f,
            "  findrefs          = query={}, lines={}, complete={}, errors={}",
            self.findrefs_query, self.findrefs_caller_lines, self.findrefs_complete, self.findrefs_errors
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
        Ok(())
    }
}