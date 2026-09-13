//! Background-thread plumbing for long-running engine operations.
//!
//! Long ops (`findrefs`, `getclass`) must never block the eframe
//! event loop (UI freeze). This module spawns one `std::thread` per
//! job and posts results back via a [`std::sync::mpsc::Sender`].
//!
//! ## Pattern
//!
//! 1. The UI thread captures the user input (query / class target).
//! 2. It spawns a thread that calls the matching
//!    [`asc_core::run_findrefs`] / [`asc_core::run_getclass`].
//! 3. The thread sends a single [`JobResult`] down the channel and
//!    exits.
//! 4. The UI thread polls the receiver in [`crate::app::AscApp::update`]
//!    (called on every eframe frame) and applies the result to the
//!    [`crate::WorkspaceSession`].

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};

use asc_core::{CoreError, FindRefsJob, FindRefsOptions, GetClassJob, GetClassOptions, GetClassResult, SearchReport};
use asc_query::Query;

/// One in-flight job: the engine work the worker thread will run.
#[derive(Debug)]
pub enum Job {
    FindRefs {
        apk: PathBuf,
        query: Query,
        label: String,
    },
    GetClass {
        apk: PathBuf,
        target: String,
    },
}

/// What a worker thread produces. Always a single result per job.
#[derive(Debug)]
pub enum JobResult {
    FindRefs {
        label: String,
        report: Result<SearchReport, CoreError>,
    },
    GetClass {
        target: String,
        result: Result<GetClassResult, CoreError>,
    },
}

/// Spawn the worker thread for `job`. Results arrive on the returned
/// [`Receiver`]; the caller is responsible for polling it on every
/// UI frame.
pub fn spawn_job(job: Job) -> Receiver<JobResult> {
    let (tx, rx): (Sender<JobResult>, Receiver<JobResult>) =
        std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = run_job(job);
        // Ignore send errors: the UI thread may have shut down.
        let _ = tx.send(result);
    });
    rx
}

/// Run a job synchronously on the current thread.
fn run_job(job: Job) -> JobResult {
    match job {
        Job::FindRefs { apk, query, label } => {
            let j = FindRefsJob::new(apk, query);
            let opts = FindRefsOptions::default();
            let report = asc_core::run_findrefs(&j, &opts);
            JobResult::FindRefs { label, report }
        }
        Job::GetClass { apk, target } => {
            let normalized = asc_core::normalize_class_name(&target);
            match normalized {
                Ok(t) => {
                    let j = GetClassJob::new(apk, t);
                    let opts = GetClassOptions::default();
                    let result = asc_core::run_getclass(&j, &opts);
                    JobResult::GetClass { target, result }
                }
                Err(e) => JobResult::GetClass {
                    target,
                    result: Err(CoreError::Class(e)),
                },
            }
        }
    }
}