//! Deterministic background-task plumbing for the GUI.
//!
//! Replaces the old anonymous receiver-per-job model (`worker.rs`,
//! audit F2) with identity-stamped tasks:
//!
//! - Every task carries a unique [`TaskId`] and the
//!   [`SessionGeneration`] of the workspace it was spawned against.
//! - Worker threads send [`TaskEnvelope`]s back; the UI-side
//!   [`TaskManager`] polls them **by identity** and stamps each
//!   completed task with a `stale` verdict (generation mismatch or
//!   superseded/cancelled). Callers drop stale results — a result from
//!   an older APK session or an older request can never mutate newer
//!   application state.
//! - Activation intent lives on the *task*, not in a shared slot, so a
//!   failing older request can no longer clear a newer request's
//!   intent (audit F1).
//! - Starting a new findrefs supersedes the previous one: an old worker
//!   that already started may physically finish, but its result is
//!   discarded on arrival (audit F3); an old job that is still queued is
//!   dropped before it starts. `run_findrefs` is a single blocking engine
//!   call with no cancellation hook (core change deliberately
//!   deferred, see docs/gui-redesign-plan.md), so supersede is
//!   discard-on-arrival, never a UI block.
//! - Duplicate decompiles of the same descriptor are deduplicated:
//!   spawning returns the in-flight task's id instead of fanning out
//!   more threads (audit F10).
//! - Burst protection: at most [`MAX_TASK_THREADS`] worker threads run
//!   at once; overflow jobs wait in a FIFO queue and start as slots
//!   free. A superseded job that is *still queued* is dropped before it
//!   starts ([`TaskManager::pump`] consults the same discard flag and
//!   generation the poll-time verdict does), so stale work can neither
//!   burn an engine scan nor delay the request the user actually wants.
//!   Only a job that already started keeps running: the engine has no
//!   cancellation hook, so the cap bounds thread creation, not CPU.
//!
//! Job execution runs inside `catch_unwind`: the engine is panic-free
//! by invariant, but a panicking worker must degrade into a failed
//! task, not kill the UI.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::time::Instant;

use eframe::egui;

use asc_core::{CoreError, FindRefsJob, FindRefsOptions, GetClassJob, GetClassOptions};
use asc_query::Query;

/// Unique identity of one background task. Monotonic per process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TaskId(pub u64);

/// Identity of a workspace session. Bumped on every APK open/reload;
/// results stamped with an older generation are stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct SessionGeneration(pub u64);

impl SessionGeneration {
    /// First generation.
    pub const INITIAL: Self = Self(0);

    /// Next generation in sequence.
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

/// What kind of engine work a task performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskKind {
    /// Open an APK and enumerate classes (window paints before this
    /// lands — redesign Phase "session/init").
    LoadArtifact,
    /// `run_getclass` for one class descriptor.
    DecompileClass,
    /// `run_findrefs` for one query.
    FindRefs,
    /// `run_findrefs` for "references to the selected class" (Analysis
    /// menu). Routed to the REFERENCES bottom tab, not search results.
    FindRefsClass,
    /// `run_disasm` for one class descriptor (Smali listing).
    Disasm,
    /// `run_callees` for one method (one-hop call fan-out).
    Callees,
    /// `run_class_strings` for one class (its own string constants).
    ClassStrings,
}

impl TaskKind {
    /// Short label for the Tasks view.
    pub fn label(self) -> &'static str {
        match self {
            TaskKind::LoadArtifact => "open",
            TaskKind::DecompileClass => "decompile",
            TaskKind::FindRefs => "findrefs",
            TaskKind::FindRefsClass => "references",
            TaskKind::Disasm => "disasm",
            TaskKind::Callees => "callees",
            TaskKind::ClassStrings => "class strings",
        }
    }

    /// Whether a task of this kind publishes into the shared references
    /// surface (`AscApp::references`, the REFERENCES bottom tab).
    ///
    /// Class references, one-hop callees and class-scoped strings all
    /// write the same surface, so they supersede and dedup each other.
    /// This is the single source of truth for that membership: dedup
    /// ([`TaskManager::references_surface_live`]), supersede
    /// ([`TaskManager::discard_references_surface`]) and every future
    /// lane rule must route through here (audit P1: `ClassStrings` was
    /// missing from both matches, so a late class-strings result could
    /// overwrite a newer references/callees result).
    pub fn uses_references_surface(self) -> bool {
        matches!(
            self,
            TaskKind::FindRefsClass | TaskKind::Callees | TaskKind::ClassStrings
        )
    }
}

/// Successful APK open: everything the workspace needs to become
/// usable, computed off the UI thread.
pub struct LoadedArtifact {
    pub session: crate::session::WorkspaceSession,
    pub manifest: Option<asc_manifest::ManifestInfo>,
    /// Set when the APK *has* an `AndroidManifest.xml` that could not be
    /// parsed. `None` + `manifest: None` means the APK genuinely has none
    /// (e.g. a synthetic corpus fixture) — the two states are never merged.
    pub manifest_error: Option<String>,
    /// All classes (already sorted by descriptor).
    pub classes: Vec<crate::session::ClassEntry>,
    /// Non-empty = the class list is PARTIAL (a DEX or class_defs were
    /// skipped). Surfaced to the user, never silently dropped.
    pub warnings: Vec<String>,
    /// Per-DEX class counts, central-directory order.
    pub dex_counts: Vec<(String, usize)>,
}

/// What a worker thread produced for one task.
pub enum TaskOutcome {
    /// Successful `run_getclass`: a fully built document (source,
    /// line index, spans, outline — all computed here on the worker
    /// thread, never on the UI thread).
    Decompiled(std::sync::Arc<crate::state::documents::Document>),
    /// Successful APK open.
    Loaded(Box<LoadedArtifact>),
    /// Successful `run_disasm`: the Smali listing + winning DEX name.
    Disassembled { dex_name: String, listing: String },
    /// Successful `run_findrefs`.
    Search(asc_core::SearchReport),
    /// Successful `run_callees`: one-hop call fan-out of a method.
    Callees(asc_core::CalleesResult),
    /// Successful `run_class_strings`: string constants of one class.
    ClassStrings(asc_core::ClassStringsResult),
    /// Engine error or worker panic, as a display string.
    Failed(String),
}

/// Message sent from a worker thread back to the UI. Self-describing:
/// carries enough identity for the UI to decide validity without any
/// shared mutable state.
pub struct TaskEnvelope {
    pub task_id: TaskId,
    pub generation: SessionGeneration,
    pub outcome: TaskOutcome,
}

/// One completed task, as handed to the application layer. `stale`
/// tasks must be ignored by state application (their result predates
/// the current session generation, or they were superseded/cancelled).
pub struct CompletedTask {
    pub id: TaskId,
    pub generation: SessionGeneration,
    pub kind: TaskKind,
    /// Human-readable target (descriptor or query label).
    pub label: String,
    pub outcome: TaskOutcome,
    pub elapsed: std::time::Duration,
    /// `true` when the result must be discarded.
    pub stale: bool,
}

/// UI-side bookkeeping for one in-flight task.
struct InFlight {
    id: TaskId,
    generation: SessionGeneration,
    kind: TaskKind,
    label: String,
    started: Instant,
    receiver: Receiver<TaskEnvelope>,
    /// Set by supersede/cancel; result is dropped on arrival.
    discarded: Arc<AtomicBool>,
}

/// One queued job: the worker body plus the identity of the task it
/// belongs to, so [`TaskManager::pump`] can drop it *before* it starts
/// when the task was already superseded (discard flag) or belongs to a
/// retired session generation. Without the identity, a superseded job
/// sitting in the queue still burned a full engine scan the moment a
/// worker slot freed — the result was thrown away on arrival, but the
/// work (and the delay it imposed on newer requests) was real.
struct PendingJob {
    generation: SessionGeneration,
    /// Shared with the task's [`InFlight`] entry: cancelling a task flips
    /// this even while its job is still queued.
    discarded: Arc<AtomicBool>,
    run: Box<dyn FnOnce() + Send + 'static>,
}

/// One entry of the bounded recent-task log (Tasks view).
#[derive(Debug, Clone)]
pub struct TaskLogEntry {
    pub kind: TaskKind,
    pub label: String,
    /// `true` when the result was applied; false when it failed.
    pub ok: bool,
    /// `true` when the result was discarded (stale/superseded).
    pub discarded: bool,
    pub elapsed_ms: u64,
}

/// Upper bound on concurrently-running GUI worker threads.
///
/// Superseded/duplicate work is already deduplicated per lane; this is
/// the backstop that keeps a burst of DISTINCT requests — each `submit`
/// used to spawn its own OS thread — from growing threads without limit.
/// Overflow jobs wait in [`TaskManager::pending`] and start as slots
/// free (each worker drops its slot on completion; the next `poll` picks
/// the queued job up).
///
/// ponytail: one coarse global cap, not per-lane admission (load ≤ 1,
/// search ≤ 1, decompile pool). Per-lane lanes plus cooperative
/// cancellation are the follow-up the audit allows; this bounds the
/// fan-out without touching the scheduling model.
pub const MAX_TASK_THREADS: usize = 32;

/// Owns all background tasks. Poll it once per frame from the eframe
/// `update` callback; it never blocks.
pub struct TaskManager {
    next_id: u64,
    generation: SessionGeneration,
    in_flight: Vec<InFlight>,
    log: std::collections::VecDeque<TaskLogEntry>,
    /// Jobs admitted but not yet started (over the [`MAX_TASK_THREADS`]
    /// cap); FIFO so the oldest *live* request runs first. Entries whose
    /// task was superseded before it started are dropped here, never
    /// spawned.
    pending: std::collections::VecDeque<PendingJob>,
    /// Live worker-thread count. Shared with each worker so it can drop
    /// its own slot on exit; `pump` reads it to admit more work.
    active: Arc<AtomicUsize>,
}

impl Default for TaskManager {
    fn default() -> Self {
        Self::new()
    }
}
impl TaskManager {
    pub fn new() -> Self {
        Self {
            next_id: 0,
            generation: SessionGeneration::INITIAL,
            in_flight: Vec::new(),
            log: std::collections::VecDeque::new(),
            pending: std::collections::VecDeque::new(),
            active: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Current workspace generation.
    pub fn generation(&self) -> SessionGeneration {
        self.generation
    }

    /// Invalidate every in-flight task (APK opened / reloaded). Their
    /// results will arrive stamped `stale`.
    pub fn bump_generation(&mut self) -> SessionGeneration {
        self.generation = self.generation.next();
        for t in &mut self.in_flight {
            t.discarded.store(true, Ordering::Release);
        }
        self.generation
    }

    /// Submit an arbitrary job as a task. `run` executes on a worker
    /// thread and returns the outcome; `ctx` is woken when the result
    /// lands so the next frame sees it immediately.
    ///
    /// Delivery is unconditional; the discard flag and generation are
    /// consulted only at poll time, so there is exactly one staleness
    /// verdict to reason about (and test).
    ///
    /// This is the seam tests use to control completion order; the
    /// engine-backed `spawn_*` methods are thin wrappers over it.
    pub fn submit(
        &mut self,
        kind: TaskKind,
        label: impl Into<String>,
        run: impl FnOnce() -> TaskOutcome + Send + 'static,
        ctx: &egui::Context,
    ) -> TaskId {
        let id = TaskId(self.next_id);
        self.next_id += 1;
        let generation = self.generation;
        let (tx, rx) = channel::<TaskEnvelope>();
        let discarded = Arc::new(AtomicBool::new(false));
        let ctx2 = ctx.clone();
        // The whole worker body is boxed so overflow work can wait in
        // `pending` instead of spawning one OS thread per request.
        let job: Box<dyn FnOnce() + Send + 'static> = Box::new(move || {
            let outcome = match catch_unwind(AssertUnwindSafe(run)) {
                Ok(outcome) => outcome,
                Err(panic) => TaskOutcome::Failed(panic_message(&panic)),
            };
            // A dropped receiver (window closed) is fine to ignore.
            let _ = tx.send(TaskEnvelope {
                task_id: id,
                generation,
                outcome,
            });
            ctx2.request_repaint();
        });
        self.in_flight.push(InFlight {
            id,
            generation,
            kind,
            label: label.into(),
            started: Instant::now(),
            receiver: rx,
            discarded: Arc::clone(&discarded),
        });
        self.pending.push_back(PendingJob {
            generation,
            discarded,
            run: job,
        });
        self.pump();
        id
    }

    /// Start queued jobs while the live-worker count is under
    /// [`MAX_TASK_THREADS`]. Called from [`Self::submit`] (fast path: the
    /// queue is empty and the job starts immediately) and at the top of
    /// [`Self::poll`], so a slot freed by a finishing worker admits the
    /// next queued job on the following frame.
    ///
    /// Superseded jobs are dropped here, *before* they start: the queue
    /// must never spend a worker (or an engine scan) on a result nobody
    /// will read. The check runs before the cap check, so a dead entry at
    /// the head of the queue cannot delay the live request behind it.
    /// Dropping the job also drops the envelope sender, so its [`InFlight`]
    /// slot retires as a discarded completion on the next [`Self::poll`] —
    /// no slot, receiver or flag is left behind.
    fn pump(&mut self) {
        while let Some(job) = self.pending.pop_front() {
            if job.discarded.load(Ordering::Acquire) || job.generation != self.generation {
                continue;
            }
            if self.active.load(Ordering::Acquire) >= MAX_TASK_THREADS {
                self.pending.push_front(job);
                break;
            }
            self.active.fetch_add(1, Ordering::AcqRel);
            let active = Arc::clone(&self.active);
            let run = job.run;
            std::thread::spawn(move || {
                run();
                active.fetch_sub(1, Ordering::AcqRel);
            });
        }
    }

    /// Jobs admitted but queued behind [`MAX_TASK_THREADS`] (tests / UI).
    pub fn queued_count(&self) -> usize {
        self.pending.len()
    }

    /// Spawn a `run_getclass` task for `descriptor` (`paranoid`: decode
    /// Paranoid strings to literals).
    pub fn spawn_decompile(
        &mut self,
        apk: &Path,
        descriptor: impl Into<String>,
        paranoid: bool,
        ctx: &egui::Context,
    ) -> TaskId {
        let descriptor = descriptor.into();
        // Dedup: an identical decompile already in flight.
        if let Some(existing) = self.decompile_in_flight(&descriptor) {
            return existing;
        }
        let apk: PathBuf = apk.to_path_buf();
        let target = descriptor.clone();
        self.submit(
            TaskKind::DecompileClass,
            descriptor,
            move || run_getclass_job(&apk, &target, paranoid),
            ctx,
        )
    }

    /// Spawn an APK-open task: mmap, per-DEX class enumeration and
    /// manifest parse all happen off the UI thread so the window is
    /// interactive immediately (redesign §7: progressive artifact
    /// metadata). Supersedes any previous open.
    pub fn spawn_load(&mut self, apk: &Path, ctx: &egui::Context) -> TaskId {
        for t in &mut self.in_flight {
            if t.kind == TaskKind::LoadArtifact {
                t.discarded.store(true, Ordering::Release);
            }
        }
        let apk: PathBuf = apk.to_path_buf();
        self.submit(
            TaskKind::LoadArtifact,
            apk.display().to_string(),
            move || run_load_job(&apk),
            ctx,
        )
    }

    /// Spawn a `run_findrefs` task. Supersedes any previous findrefs:
    /// the old task's result is discarded on arrival (it cannot block
    /// or replace this one).
    pub fn spawn_findrefs(
        &mut self,
        apk: &Path,
        query: Query,
        label: impl Into<String>,
        paranoid: bool,
        ctx: &egui::Context,
    ) -> TaskId {
        for t in &mut self.in_flight {
            if t.kind == TaskKind::FindRefs {
                t.discarded.store(true, Ordering::Release);
            }
        }
        let apk: PathBuf = apk.to_path_buf();
        self.submit(
            TaskKind::FindRefs,
            label,
            move || run_findrefs_job(&apk, &query, paranoid),
            ctx,
        )
    }

    /// Spawn a `run_findrefs` for references to one class (Analysis menu).
    ///
    /// Supersedes every live task that also publishes into the shared
    /// references surface ([`Self::discard_references_surface`]); global
    /// searches are independent. An identical request that is already
    /// live is reused rather than queued twice, so repeated clicks cannot
    /// fan out into repeated whole-artifact scans.
    pub fn spawn_findrefs_class(
        &mut self,
        apk: &Path,
        descriptor: &str,
        ctx: &egui::Context,
    ) -> TaskId {
        let label = format!("refs {descriptor}");
        if let Some(existing) = self.references_surface_live(&label) {
            return existing;
        }
        self.discard_references_surface();
        let apk: PathBuf = apk.to_path_buf();
        let query = Query::type_(descriptor);
        self.submit(
            TaskKind::FindRefsClass,
            label,
            move || run_findrefs_job(&apk, &query, false),
            ctx,
        )
    }

    /// Spawn a `run_disasm` task. `method = Some(name)` filters the
    /// listing to that method's overloads (ASC-RS-GUI-004). The task
    /// label is the smali document key so `apply_task` can file the
    /// listing under the right tab. Deduplicated like decompiles.
    pub fn spawn_disasm(
        &mut self,
        apk: &Path,
        descriptor: &str,
        method: Option<&str>,
        ctx: &egui::Context,
    ) -> TaskId {
        let key = Self::smali_key(descriptor, method);
        if let Some(existing) = self
            .in_flight
            .iter()
            .find(|t| {
                t.kind == TaskKind::Disasm && t.label == key && !t.discarded.load(Ordering::Acquire)
            })
            .map(|t| t.id)
        {
            return existing;
        }
        let apk: PathBuf = apk.to_path_buf();
        let target = descriptor.to_string();
        let method = method.map(str::to_owned);
        self.submit(
            TaskKind::Disasm,
            key,
            move || run_disasm_job(&apk, &target, method.as_deref()),
            ctx,
        )
    }

    /// Document key for the smali listing of `descriptor` (optionally
    /// filtered to one method).
    pub fn smali_key(descriptor: &str, method: Option<&str>) -> String {
        match method {
            Some(m) => format!("{descriptor}#smali#{m}"),
            None => format!("{descriptor}#smali"),
        }
    }

    /// Spawn a one-hop callee scan for `descriptor::method`
    /// (ASC-RS-GUI-001).
    ///
    /// Shares the references surface with
    /// [`Self::spawn_findrefs_class`], so the two supersede each other and
    /// an identical live request is reused.
    pub fn spawn_callees(
        &mut self,
        apk: &Path,
        descriptor: &str,
        method: &str,
        ctx: &egui::Context,
    ) -> TaskId {
        let label = format!("{descriptor}->{method}");
        if let Some(existing) = self.references_surface_live(&label) {
            return existing;
        }
        self.discard_references_surface();
        let apk: PathBuf = apk.to_path_buf();
        let target = descriptor.to_string();
        let method = method.to_string();
        self.submit(
            TaskKind::Callees,
            label,
            move || run_callees_job(&apk, &target, &method),
            ctx,
        )
    }

    /// Spawn a class-scoped string-constant scan (ASC-RS-GUI-006).
    /// Shares the references surface (supersedes callees /
    /// class-references; identical live request is reused).
    pub fn spawn_class_strings(
        &mut self,
        apk: &Path,
        descriptor: &str,
        ctx: &egui::Context,
    ) -> TaskId {
        let label = descriptor.to_string();
        if let Some(existing) = self.references_surface_live(&label) {
            return existing;
        }
        self.discard_references_surface();
        let apk: PathBuf = apk.to_path_buf();
        let target = descriptor.to_string();
        self.submit(
            TaskKind::ClassStrings,
            label,
            move || run_class_strings_job(&apk, &target),
            ctx,
        )
    }

    /// Whether a *wanted* task is publishing into the shared references
    /// surface ([`TaskKind::uses_references_surface`]) right now.
    ///
    /// The REFERENCES tab uses this for its placeholder, so it asks the same
    /// question the poll-time verdict does: a superseded/cancelled task's
    /// result is discarded on arrival, and claiming "collecting…" for it (or
    /// for a scan whose lane was already taken over by a newer request) would
    /// advertise work the user will never see — same rule as
    /// [`Self::findrefs_live`]. The lane is shared by class-references,
    /// one-hop callees and class strings, so all three count: whichever is
    /// live is what will replace the tab's content.
    pub fn references_surface_busy(&self) -> bool {
        self.in_flight
            .iter()
            .any(|t| t.kind.uses_references_surface() && !t.discarded.load(Ordering::Acquire))
    }

    /// The in-flight decompile task for `descriptor`, if any.
    ///
    /// A superseded or cancelled task does not count (same reasoning as
    /// [`Self::findrefs_live`]): its result is discarded on arrival, so
    /// deduplicating onto it would silently swallow the replacement
    /// request and leave the class permanently unloaded. This is also
    /// the gate `editor`'s automatic retry uses, so a discarded task
    /// must not block a fresh spawn either.
    pub fn decompile_in_flight(&self, descriptor: &str) -> Option<TaskId> {
        self.in_flight
            .iter()
            .find(|t| {
                t.kind == TaskKind::DecompileClass
                    && t.label == descriptor
                    && !t.discarded.load(Ordering::Acquire)
            })
            .map(|t| t.id)
    }

    /// Mark every in-flight task of one kind cancelled (e.g. Esc on a
    /// running search). Results are discarded on arrival.
    pub fn cancel_kind(&mut self, kind: TaskKind) {
        for t in &mut self.in_flight {
            if t.kind == kind {
                t.discarded.store(true, Ordering::Release);
            }
        }
    }

    /// Mark one task cancelled; its result will be discarded.
    pub fn cancel(&mut self, id: TaskId) {
        if let Some(t) = self.in_flight.iter_mut().find(|t| t.id == id) {
            t.discarded.store(true, Ordering::Release);
        }
    }

    /// Whether a findrefs task is currently running.
    pub fn findrefs_running(&self) -> bool {
        self.in_flight.iter().any(|t| t.kind == TaskKind::FindRefs)
    }

    /// Whether a findrefs task is running that is still wanted.
    ///
    /// Same as [`Self::findrefs_running`] except that a superseded or
    /// cancelled task does not count: its worker may still be churning
    /// out a result nobody will read, but it must not block the user
    /// from starting the search they actually asked for.
    pub fn findrefs_live(&self) -> bool {
        self.in_flight
            .iter()
            .any(|t| t.kind == TaskKind::FindRefs && !t.discarded.load(Ordering::Acquire))
    }

    /// The live task publishing `label` into the shared references
    /// surface, if any.
    ///
    /// [`TaskKind::FindRefsClass`] ("references to class X"),
    /// [`TaskKind::Callees`] (one-hop fan-out) and
    /// [`TaskKind::ClassStrings`] all render into `AscApp::references`
    /// and select the REFERENCES tab, so they share one lane
    /// ([`TaskKind::uses_references_surface`]). A superseded task does
    /// not count — its result is discarded on arrival.
    pub fn references_surface_live(&self, label: &str) -> Option<TaskId> {
        self.in_flight
            .iter()
            .find(|t| {
                t.kind.uses_references_surface()
                    && t.label == label
                    && !t.discarded.load(Ordering::Acquire)
            })
            .map(|t| t.id)
    }

    /// Supersede every live references-surface task.
    ///
    /// Without this, a late `Callees` result overwrites a newer "find
    /// references" result (both write `AscApp::references`), and each
    /// superseded worker still runs a full artifact scan to completion,
    /// since supersede is discard-on-arrival rather than cancellation.
    fn discard_references_surface(&mut self) {
        for t in &mut self.in_flight {
            if t.kind.uses_references_surface() {
                t.discarded.store(true, Ordering::Release);
            }
        }
    }

    /// Recent completed tasks (Tasks view), newest first.
    pub fn recent(&self) -> impl Iterator<Item = &TaskLogEntry> {
        self.log.iter().rev()
    }

    /// Whether anything is in flight.
    pub fn has_in_flight(&self) -> bool {
        !self.in_flight.is_empty()
    }

    /// In-flight count (for the Tasks view).
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Drain every task whose result has arrived. Never blocks.
    /// Returns tasks in **arrival order**; each is stamped with its
    /// staleness verdict so callers can drop old results.
    pub fn poll(&mut self) -> Vec<CompletedTask> {
        // A finishing worker freed a slot; admit the next queued job
        // (no-op when nothing is queued).
        self.pump();
        let mut done = Vec::new();
        let mut still_pending: Vec<InFlight> = Vec::with_capacity(self.in_flight.len());
        for mut task in std::mem::take(&mut self.in_flight) {
            match task.receiver.try_recv() {
                Ok(envelope) => {
                    let stale = task.discarded.load(Ordering::Acquire)
                        || envelope.generation != self.generation;
                    done.push(CompletedTask {
                        id: envelope.task_id,
                        generation: envelope.generation,
                        kind: task.kind,
                        label: std::mem::take(&mut task.label),
                        outcome: envelope.outcome,
                        elapsed: task.started.elapsed(),
                        stale,
                    });
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => still_pending.push(task),
                // Unreachable for a job that ran (delivery is
                // unconditional) — but a job dropped by `pump` while still
                // queued lands here, and must retire as a discarded
                // completion, exactly as a superseded result would. Also
                // kept defensive for a vanished worker, which must never
                // wedge the slot forever.
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    done.push(CompletedTask {
                        id: task.id,
                        generation: task.generation,
                        kind: task.kind,
                        label: std::mem::take(&mut task.label),
                        outcome: TaskOutcome::Failed("worker exited without a result".into()),
                        elapsed: task.started.elapsed(),
                        stale: task.discarded.load(Ordering::Acquire)
                            || task.generation != self.generation,
                    });
                }
            }
        }
        for t in &done {
            self.log.push_back(TaskLogEntry {
                kind: t.kind,
                label: t.label.clone(),
                ok: !matches!(t.outcome, TaskOutcome::Failed(_)) && !t.stale,
                discarded: t.stale,
                elapsed_ms: t.elapsed.as_millis() as u64,
            });
        }
        while self.log.len() > 32 {
            self.log.pop_front();
        }
        self.in_flight = still_pending;
        done
    }
}

/// Run one getclass engine job (worker-thread body): decompile, then
/// build the document (tokenize + outline) here so the UI thread
/// never pays for it.
fn run_getclass_job(apk: &Path, descriptor: &str, paranoid: bool) -> TaskOutcome {
    let normalized = match asc_core::normalize_class_name(descriptor) {
        Ok(t) => t,
        Err(e) => return TaskOutcome::Failed(e.to_string()),
    };
    let opts = GetClassOptions {
        paranoid,
        ..GetClassOptions::default()
    };
    match asc_core::run_getclass(&GetClassJob::new(apk, normalized), &opts) {
        Ok(r) => {
            let source = with_decompile_warnings(&r.source);
            TaskOutcome::Decompiled(std::sync::Arc::new(crate::state::documents::Document::new(
                descriptor.to_string(),
                r.dex_name,
                source,
            )))
        }
        Err(e) => TaskOutcome::Failed(core_error_string(&e)),
    }
}

/// Prepend a `// warning:` banner when the decompiled Java shows known
/// structurer defect signatures (same heuristics as the CLI). The Java
/// output is a cross-check aid, never ground truth — see
/// `crates/asc-decompile/BACKENDS.md` §11.
fn with_decompile_warnings(source: &str) -> String {
    let mut banner = String::new();
    let unbound = asc_core::unbound_locals(source);
    if !unbound.is_empty() {
        banner.push_str(&format!(
            "// warning: decompiled Java may be incorrect: {} local(s) read but never assigned: {}\n",
            unbound.len(),
            unbound.join(", ")
        ));
    }
    let dup = asc_core::duplicated_catch_bodies(source);
    if dup >= 2 {
        banner.push_str(&format!(
            "// warning: decompiled Java may be incorrect: {dup} identical catch bodies (cross-check with the Smali view)\n"
        ));
    }
    if banner.is_empty() {
        source.to_string()
    } else {
        format!("{banner}{source}")
    }
}

/// Parse the APK manifest, keeping *absence* and *failure* apart.
///
/// `ManifestError::NotFound` (no `AndroidManifest.xml` entry, or a raw DEX)
/// is genuine absence → `(None, None)`. Anything else is a real decode
/// failure and its message is preserved, so the inspector can say the
/// metadata is untrustworthy instead of pretending the APK has no manifest
/// (audit: `Option<T>` conflating "missing" with "failed"; mirrors
/// `asc_core::xapk`'s `manifest` / `manifest_error` pair).
pub(crate) fn load_manifest(path: &Path) -> (Option<asc_manifest::ManifestInfo>, Option<String>) {
    match asc_manifest::parse_from_apk(path) {
        Ok(m) => (Some(m), None),
        Err(asc_manifest::ManifestError::NotFound(_)) => (None, None),
        Err(e) => (None, Some(e.to_string())),
    }
}

/// Run one APK-open job (worker-thread body): open the session,
/// enumerate every DEX's classes, parse the manifest.
fn run_load_job(apk: &Path) -> TaskOutcome {
    let session = match crate::session::WorkspaceSession::open(apk) {
        Ok(s) => s,
        Err(e) => return TaskOutcome::Failed(e.to_string()),
    };
    let (manifest, manifest_error) = load_manifest(session.path());
    // Per-DEX counts come from the DEXes themselves, not from
    // `all_classes()` (which collapses a class shadowed by an earlier DEX
    // and would report such a DEX as empty).
    let dex_counts = session.class_counts_per_dex();
    match session.all_classes() {
        Ok(list) => TaskOutcome::Loaded(Box::new(LoadedArtifact {
            dex_counts,
            session,
            manifest,
            manifest_error,
            classes: list.classes,
            warnings: list.warnings,
        })),
        Err(e) => TaskOutcome::Failed(e.to_string()),
    }
}

/// Run one findrefs engine job (worker-thread body).
fn run_findrefs_job(apk: &Path, query: &Query, paranoid: bool) -> TaskOutcome {
    let opts = FindRefsOptions {
        paranoid,
        ..FindRefsOptions::default()
    };
    match asc_core::run_findrefs(&FindRefsJob::new(apk, query.clone()), &opts) {
        Ok(report) => TaskOutcome::Search(report),
        Err(e) => TaskOutcome::Failed(core_error_string(&e)),
    }
}

/// Run one disasm engine job (worker-thread body): smali listing of
/// one class, optionally narrowed to one method's overloads.
fn run_disasm_job(apk: &Path, descriptor: &str, method: Option<&str>) -> TaskOutcome {
    let job = asc_core::DisasmJob::new(apk, descriptor, method);
    match asc_core::run_disasm(&job, &asc_core::DisasmOptions::default()) {
        Ok(r) => TaskOutcome::Disassembled {
            dex_name: r.dex_name,
            listing: r.listing,
        },
        Err(e) => TaskOutcome::Failed(core_error_string(&e)),
    }
}

/// Run one one-hop callee scan (worker-thread body).
fn run_callees_job(apk: &Path, descriptor: &str, method: &str) -> TaskOutcome {
    match asc_core::run_callees(&asc_core::CalleesJob::new(apk, descriptor, method)) {
        Ok(r) => TaskOutcome::Callees(r),
        Err(e) => TaskOutcome::Failed(core_error_string(&e)),
    }
}

/// Run one class-scoped string scan (worker-thread body).
fn run_class_strings_job(apk: &Path, descriptor: &str) -> TaskOutcome {
    match asc_core::run_class_strings(&asc_core::ClassStringsJob::new(apk, descriptor)) {
        Ok(r) => TaskOutcome::ClassStrings(r),
        Err(e) => TaskOutcome::Failed(core_error_string(&e)),
    }
}

/// `CoreError` has no source chain exposed; format the top level.
fn core_error_string(e: &CoreError) -> String {
    e.to_string()
}
fn panic_message(panic: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        format!("worker panicked: {s}")
    } else if let Some(s) = panic.downcast_ref::<String>() {
        format!("worker panicked: {s}")
    } else {
        "worker panicked".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::RecvTimeoutError;

    fn ctx() -> egui::Context {
        egui::Context::default()
    }

    /// Submit a job that blocks until `release` fires, then returns
    /// `outcome`.
    fn gated(
        mgr: &mut TaskManager,
        kind: TaskKind,
        label: &str,
        outcome: TaskOutcome,
        ctx: &egui::Context,
    ) -> (TaskId, std::sync::mpsc::Sender<()>) {
        let (tx, rx) = channel::<()>();
        let id = mgr.submit(
            kind,
            label,
            move || {
                // Block until the test releases us (bounded to keep
                // a hung test from hanging forever).
                match rx.recv_timeout(std::time::Duration::from_secs(10)) {
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => outcome,
                    Err(RecvTimeoutError::Timeout) => {
                        TaskOutcome::Failed("test gate timeout".into())
                    }
                }
            },
            ctx,
        );
        (id, tx)
    }

    fn ok_source(name: &str) -> TaskOutcome {
        TaskOutcome::Decompiled(std::sync::Arc::new(crate::state::documents::Document::new(
            format!("L{name};"),
            "classes.dex".into(),
            format!("class {name} {{}}"),
        )))
    }

    /// A superseded/cancelled decompile must not be reused by the dedup.
    ///
    /// `Command::ToggleParanoid` cancels the in-flight decompile, clears
    /// the document cache and immediately re-spawns for the active
    /// descriptor. If the dedup matched the discarded task, that result
    /// would be thrown away as stale (the cache is already gone) and the
    /// class would never load. The same guard gates `editor`'s automatic
    /// retry, so a discarded task must not block a fresh spawn either.
    #[test]
    fn spawn_decompile_ignores_discarded_task() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let apk = std::path::Path::new("does-not-exist.apk");

        let first = mgr.spawn_decompile(apk, "Lcom/foo/Bar;", false, &ctx);
        // While live, an identical request still dedups.
        assert_eq!(
            mgr.spawn_decompile(apk, "Lcom/foo/Bar;", false, &ctx),
            first,
            "live task is reused"
        );
        assert!(mgr.decompile_in_flight("Lcom/foo/Bar;").is_some());

        // Supersede it, exactly as ToggleParanoid does.
        mgr.cancel_kind(TaskKind::DecompileClass);
        assert!(
            mgr.decompile_in_flight("Lcom/foo/Bar;").is_none(),
            "a discarded task does not count as in flight"
        );

        // The replacement must be a new task, not the dead one.
        let second = mgr.spawn_decompile(apk, "Lcom/foo/Bar;", true, &ctx);
        assert_ne!(
            second, first,
            "replacement spawned instead of deduping onto the discarded task"
        );
    }

    /// `FindRefsClass` and `Callees` both publish into the shared
    /// references surface (`AscApp::references`, REFERENCES tab), so
    /// spawning one must supersede the other. Otherwise a late result of
    /// the older kind overwrites the newer result, and every superseded
    /// worker still runs a whole-artifact scan to completion.
    #[test]
    fn references_surface_kinds_supersede_each_other() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let apk = std::path::Path::new("does-not-exist.apk");

        let refs = mgr.spawn_findrefs_class(apk, "Lcom/foo/Bar;", &ctx);
        // An identical live request is reused, not queued twice.
        assert_eq!(
            mgr.spawn_findrefs_class(apk, "Lcom/foo/Bar;", &ctx),
            refs,
            "identical request reuses the live task"
        );

        // A callee scan is a different request on the same surface: it
        // supersedes the class-references scan.
        let callees = mgr.spawn_callees(apk, "Lcom/foo/Bar;", "m", &ctx);
        assert_ne!(callees, refs);
        assert!(
            mgr.in_flight
                .iter()
                .any(|t| t.id == refs && t.discarded.load(Ordering::Acquire)),
            "the older surface task is discarded, so its result arrives stale"
        );
        assert_eq!(
            mgr.references_surface_live("Lcom/foo/Bar;->m"),
            Some(callees),
            "only the newest request is live"
        );
        assert_eq!(mgr.references_surface_live("refs Lcom/foo/Bar;"), None);
    }

    #[test]
    fn task_ids_are_unique_and_monotonic() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let a = mgr.submit(TaskKind::DecompileClass, "A", || ok_source("A"), &ctx);
        let b = mgr.submit(TaskKind::DecompileClass, "B", || ok_source("B"), &ctx);
        assert_ne!(a, b);
        assert!(b > a);
        let _ = mgr.poll();
    }

    /// `spawn_findrefs` returns a fresh TaskId and queues a
    /// FindRefs task. Alias for ASC-GUI-010.
    #[test]
    fn run_search_dispatches_findrefs() {
        use asc_query::Query;
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let apk = std::path::Path::new("nonexistent_fixture_for_test.apk");
        let id = mgr.spawn_findrefs(apk, Query::string("hello"), "string \"hello\"", false, &ctx);
        // id.0 is a u64 counter; the first task gets 0 (and is
        // bumped to 1 on next submit). Just assert it is set.
        let _ = id.0;
        assert!(mgr.findrefs_running());
    }

    /// `spawn_findrefs_class` flags a separate FindRefsClass task
    /// (the REFERENCES tab uses this). Alias for ASC-GUI-014.
    #[test]
    fn findrefs_class_runs_type_query() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let apk = std::path::Path::new("nonexistent_fixture_for_test.apk");
        let _id = mgr.spawn_findrefs_class(apk, "Lcom/foo/Bar;", &ctx);
        assert!(mgr.references_surface_busy());
    }

    /// The REFERENCES placeholder asks `references_surface_busy`, which counts
    /// only tasks whose result will actually land: a superseded/cancelled
    /// scan must stop claiming "collecting references…" (the lane is shared,
    /// so a newer callee/class-strings request keeps it busy).
    #[test]
    fn superseded_references_task_is_not_busy() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let apk = Path::new("nonexistent_fixture_for_test.apk");

        let refs = mgr.spawn_findrefs_class(apk, "Lcom/foo/Bar;", &ctx);
        assert!(mgr.references_surface_busy(), "the request is live");

        // A callee scan on the same lane supersedes it — still busy, because
        // the newer request will replace the tab's content.
        let callees = mgr.spawn_callees(apk, "Lcom/foo/Bar;", "m", &ctx);
        assert_ne!(callees, refs);
        assert!(mgr.references_surface_busy(), "the newer request is live");

        // Cancel the newest request: both tasks are still physically in
        // flight, but neither result will ever be applied.
        mgr.cancel(callees);
        assert!(
            mgr.has_in_flight(),
            "the tasks are still in flight (supersede is not cancellation)"
        );
        assert!(
            !mgr.references_surface_busy(),
            "nothing live is left to collect references"
        );
    }

    /// `cancel_kind` removes every in-flight FindRefs task. After
    /// cancellation, `findrefs_running()` is false. Alias for
    /// ASC-GUI-012.
    #[test]
    fn cancel_kind_discards_previous_findrefs() {
        use asc_query::Query;
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let apk = std::path::Path::new("nonexistent_fixture_for_test.apk");
        let _ = mgr.spawn_findrefs(apk, Query::string("a"), "A", false, &ctx);
        let _ = mgr.spawn_findrefs(apk, Query::string("b"), "B", false, &ctx);
        assert!(mgr.findrefs_running());
        mgr.cancel_kind(TaskKind::FindRefs);
        // Cancellation only flips the discarded flag; the in_flight
        // entry stays until it lands. findrefs_running walks
        // in_flight — note that this returns true again because
        // the entry hasn't been polled away. The data-shape
        // contract is: cancel_kind marks the task discarded; the
        // manager drops the entry on the next poll(). The
        // meaningful assertion is therefore on `discarded`.
        let discarded_any = mgr
            .in_flight
            .iter()
            .any(|t| t.discarded.load(std::sync::atomic::Ordering::Acquire));
        assert!(discarded_any, "FindRefs marked discarded");
    }

    /// A cancelled scan keeps *running* (the engine has no cancel hook) but
    /// stops being *live* the moment it is discarded. Every indicator that
    /// means "the request you are waiting for" — the bottom-panel
    /// "searching…" placeholder, the toolbar/search-bar spinners, the
    /// Run-vs-cancel button — must ask `findrefs_live`, or the GUI claims
    /// progress for a result that will be thrown away on arrival.
    #[test]
    fn cancelled_findrefs_runs_but_is_no_longer_live() {
        use asc_query::Query;
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let apk = Path::new("nonexistent_fixture_for_test.apk");
        let _id = mgr.spawn_findrefs(apk, Query::string("hello"), "string \"hello\"", false, &ctx);
        assert!(mgr.findrefs_running(), "in flight");
        assert!(mgr.findrefs_live(), "and still wanted");

        mgr.cancel_kind(TaskKind::FindRefs);

        assert!(
            mgr.findrefs_running(),
            "the worker is still churning; only the result was discarded"
        );
        assert!(
            !mgr.findrefs_live(),
            "a cancelled scan is not what the user is waiting for"
        );
    }

    /// A manifest that is *present but undecodable* must be preserved as an
    /// error. Before the fix the worker used `.ok()`, melting it into
    /// `manifest: None`, which the inspector rendered as "no manifest" —
    /// hiding a real parse failure from the analyst.
    #[test]
    fn load_job_keeps_a_corrupt_manifest_as_an_error() {
        let apk = crate::test_zip::write_temp_apk(
            "load_job_corrupt_manifest",
            &[("AndroidManifest.xml", b"not axml at all")],
        );
        let outcome = run_load_job(&apk);
        let _ = std::fs::remove_file(&apk);

        let TaskOutcome::Loaded(artifact) = outcome else {
            panic!("a corrupt manifest must not fail the whole APK open");
        };
        assert!(artifact.manifest.is_none());
        assert!(
            artifact
                .manifest_error
                .as_deref()
                .is_some_and(|e| e.contains("binary Android XML")),
            "got {:?}",
            artifact.manifest_error
        );
    }

    /// ...while genuine absence stays absence: no error, no manifest.
    #[test]
    fn load_job_reports_an_absent_manifest_as_absence() {
        let apk =
            crate::test_zip::write_temp_apk("load_job_no_manifest", &[("assets/x.txt", b"hi")]);
        let outcome = run_load_job(&apk);
        let _ = std::fs::remove_file(&apk);

        let TaskOutcome::Loaded(artifact) = outcome else {
            panic!("an APK without a manifest still opens");
        };
        assert!(artifact.manifest.is_none());
        assert!(
            artifact.manifest_error.is_none(),
            "absence is not a failure: {:?}",
            artifact.manifest_error
        );
    }

    /// click A, click B, B finishes first, A finishes later → both
    /// arrive; neither is stale (same generation); arrival order is
    /// preserved so the app layer can apply "latest intent wins".
    #[test]
    fn arrival_order_preserved_b_then_a() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let (a, rel_a) = gated(
            &mut mgr,
            TaskKind::DecompileClass,
            "A",
            ok_source("A"),
            &ctx,
        );
        let (_b, rel_b) = gated(
            &mut mgr,
            TaskKind::DecompileClass,
            "B",
            ok_source("B"),
            &ctx,
        );
        // Poll with nothing finished.
        assert!(mgr.poll().is_empty());
        // Release B, then A.
        drop(rel_b);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut done = Vec::new();
        while done.is_empty() && std::time::Instant::now() < deadline {
            done = mgr.poll();
        }
        assert_eq!(done.len(), 1, "only B completed");
        assert_eq!(done[0].label, "B");
        assert!(!done[0].stale);
        drop(rel_a);
        let mut done = Vec::new();
        while done.is_empty() && std::time::Instant::now() < deadline {
            done = mgr.poll();
        }
        assert_eq!(done[0].label, "A");
        assert_eq!(done[0].id, a);
        assert!(!done[0].stale);
        assert!(!mgr.has_in_flight(), "both drained");
    }

    /// Old-APK job completes after a generation bump → arrives stale.
    #[test]
    fn generation_bump_marks_old_results_stale() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let (_id, rel) = gated(
            &mut mgr,
            TaskKind::DecompileClass,
            "X",
            ok_source("X"),
            &ctx,
        );
        mgr.bump_generation();
        drop(rel);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut done = Vec::new();
        while done.is_empty() && std::time::Instant::now() < deadline {
            done = mgr.poll();
        }
        assert_eq!(done.len(), 1, "delivery is unconditional");
        assert!(done[0].stale, "old-generation result must be stale");
        assert_ne!(done[0].generation, mgr.generation());
    }

    /// Superseded findrefs A (late) cannot replace B.
    #[test]
    fn superseded_findrefs_discarded_on_arrival() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let (_a, rel_a) = gated(
            &mut mgr,
            TaskKind::FindRefs,
            "A",
            TaskOutcome::Search(asc_core::SearchReport::empty()),
            &ctx,
        );
        assert!(mgr.findrefs_running());
        // Starting B supersedes A.
        let _b = mgr.spawn_findrefs(
            Path::new("nonexistent.apk"),
            Query::string("b"),
            "B",
            false,
            &ctx,
        );
        assert_eq!(mgr.in_flight_count(), 2);
        // A lands late; B (a real engine job on a nonexistent APK)
        // fails fast and also lands. Drain everything.
        drop(rel_a);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut done = Vec::new();
        while mgr.has_in_flight() && std::time::Instant::now() < deadline {
            done.extend(mgr.poll());
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        done.extend(mgr.poll());
        let a = done.iter().find(|t| t.label == "A").expect("A delivered");
        assert!(a.stale, "superseded findrefs must arrive stale");
        let b = done
            .iter()
            .find(|t| t.label == "B")
            .expect("B delivered (engine failure still completes)");
        assert!(!b.stale, "the newer query must not be superseded");
    }

    /// Duplicate decompile of the same descriptor dedups to one task.
    #[test]
    fn duplicate_decompile_dedups() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let apk = Path::new("x.apk");
        let a = mgr.spawn_decompile(apk, "La;", false, &ctx);
        let b = mgr.spawn_decompile(apk, "La;", false, &ctx);
        assert_eq!(a, b, "same descriptor dedups to the in-flight task");
        let c = mgr.spawn_decompile(apk, "Lb;", false, &ctx);
        assert_ne!(a, c);
        assert_eq!(mgr.in_flight_count(), 2);
    }

    /// Duplicate disasm of the same descriptor dedups to one task,
    /// and the task label is the `#smali` document key.
    #[test]
    fn duplicate_disasm_dedups() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let apk = Path::new("x.apk");
        let a = mgr.spawn_disasm(apk, "La;", None, &ctx);
        let b = mgr.spawn_disasm(apk, "La;", None, &ctx);
        assert_eq!(a, b, "same descriptor dedups to the in-flight task");
        let m = mgr.spawn_disasm(apk, "La;", Some("run"), &ctx);
        assert_ne!(a, m, "method-scoped listing is a distinct task");
        assert_eq!(mgr.in_flight_count(), 2);
        assert_eq!(TaskManager::smali_key("La;", None), "La;#smali");
        assert_eq!(TaskManager::smali_key("La;", Some("run")), "La;#smali#run");
    }

    /// A panicking job degrades to a failed task, not a dead UI.
    #[test]
    fn panicking_job_becomes_failed_task() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let _ = mgr.submit(TaskKind::DecompileClass, "boom", || panic!("kaboom"), &ctx);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut done = Vec::new();
        while done.is_empty() && std::time::Instant::now() < deadline {
            done = mgr.poll();
        }
        assert_eq!(done.len(), 1);
        assert!(!done[0].stale);
        let outcome = std::mem::replace(
            &mut done.into_iter().next().unwrap().outcome,
            TaskOutcome::Failed(String::new()),
        );
        assert!(
            matches!(&outcome, TaskOutcome::Failed(m) if m.contains("kaboom")),
            "panic must surface as a Failed task containing the panic message"
        );
    }

    /// Cancel discards the result.
    #[test]
    fn cancelled_task_result_discarded() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let (id, rel) = gated(
            &mut mgr,
            TaskKind::DecompileClass,
            "C",
            ok_source("C"),
            &ctx,
        );
        mgr.cancel(id);
        drop(rel);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut done = Vec::new();
        while done.is_empty() && std::time::Instant::now() < deadline {
            done = mgr.poll();
        }
        // Either the worker saw the discard flag and never sent
        // (empty poll, slot dropped) or it sent before the flag and we
        // stamp it stale. Both outcomes are safe; assert no non-stale
        // result is ever delivered.
        for t in done {
            assert!(t.stale, "cancelled task must never apply");
        }
        while mgr.has_in_flight() {
            let _ = mgr.poll();
        }
    }

    /// Clean Java gets no banner; the known defect signatures get one
    /// (`// warning:` line prepended, source otherwise untouched).
    #[test]
    fn decompile_warning_banner() {
        let clean = "class A { void f() { int x = 1; g(x); } }";
        assert_eq!(with_decompile_warnings(clean), clean);
        let bad = "class A { void f() { g(v2_3 + v4_1); } }";
        let out = with_decompile_warnings(bad);
        assert!(out.starts_with("// warning:"), "{out}");
        assert!(out.ends_with(bad));
    }

    fn class_strings_outcome() -> TaskOutcome {
        TaskOutcome::ClassStrings(asc_core::ClassStringsResult {
            dex_name: "classes.dex".into(),
            strings: Vec::new(),
            errors: Vec::new(),
            complete: true,
        })
    }

    fn callees_outcome() -> TaskOutcome {
        TaskOutcome::Callees(asc_core::CalleesResult {
            dex_name: "classes.dex".into(),
            callees: Vec::new(),
            errors: Vec::new(),
            complete: true,
        })
    }

    /// `uses_references_surface` must be the ONE definition of the shared
    /// lane; adding a variant there is enough (audit P1: `ClassStrings`
    /// was missing from the two `matches!` sites).
    #[test]
    fn references_surface_membership_is_explicit() {
        assert!(TaskKind::FindRefsClass.uses_references_surface());
        assert!(TaskKind::Callees.uses_references_surface());
        assert!(TaskKind::ClassStrings.uses_references_surface());
        assert!(!TaskKind::FindRefs.uses_references_surface());
        assert!(!TaskKind::DecompileClass.uses_references_surface());
        assert!(!TaskKind::Disasm.uses_references_surface());
        assert!(!TaskKind::LoadArtifact.uses_references_surface());
    }

    /// An identical live `ClassStrings` request returns the SAME task id
    /// and does not spawn a second task.
    #[test]
    fn identical_class_strings_request_is_reused() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let apk = Path::new("does-not-exist.apk");
        let a = mgr.spawn_class_strings(apk, "Lcom/foo/Bar;", &ctx);
        let b = mgr.spawn_class_strings(apk, "Lcom/foo/Bar;", &ctx);
        assert_eq!(a, b, "identical class-strings request reuses the task");
        assert_eq!(mgr.in_flight_count(), 1, "no second task spawned");
    }

    /// Drain every task to completion, returning the `stale` verdict for
    /// `id` (deterministic: the test controls when the gated task lands).
    fn drain_stale_of(mgr: &mut TaskManager, id: TaskId) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut verdict = None;
        while mgr.has_in_flight() && std::time::Instant::now() < deadline {
            for t in mgr.poll() {
                if t.id == id {
                    verdict = Some(t.stale);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        for t in mgr.poll() {
            if t.id == id {
                verdict = Some(t.stale);
            }
        }
        verdict.expect("gated task must eventually be delivered")
    }

    /// ClassStrings → FindRefsClass: the older class-strings result lands
    /// after the newer references request and must arrive stale.
    #[test]
    fn late_class_strings_cannot_beat_newer_references() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let apk = Path::new("does-not-exist.apk");
        let (old, rel) = gated(
            &mut mgr,
            TaskKind::ClassStrings,
            "Lcom/foo/Bar;",
            class_strings_outcome(),
            &ctx,
        );
        let newer = mgr.spawn_findrefs_class(apk, "Lcom/foo/Bar;", &ctx);
        assert_ne!(newer, old);
        drop(rel);
        assert!(drain_stale_of(&mut mgr, old), "old result must be stale");
    }

    /// ClassStrings → Callees: same surface, same supersede rule.
    #[test]
    fn late_class_strings_cannot_beat_newer_callees() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let apk = Path::new("does-not-exist.apk");
        let (old, rel) = gated(
            &mut mgr,
            TaskKind::ClassStrings,
            "Lcom/foo/Bar;",
            class_strings_outcome(),
            &ctx,
        );
        let newer = mgr.spawn_callees(apk, "Lcom/foo/Bar;", "m", &ctx);
        assert_ne!(newer, old);
        drop(rel);
        assert!(drain_stale_of(&mut mgr, old), "old result must be stale");
    }

    /// Callees → ClassStrings: the reverse direction, to prove the lane
    /// is symmetric (ClassStrings can supersede too).
    #[test]
    fn late_callees_cannot_beat_newer_class_strings() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let apk = Path::new("does-not-exist.apk");
        let (old, rel) = gated(
            &mut mgr,
            TaskKind::Callees,
            "Lcom/foo/Bar;->m",
            callees_outcome(),
            &ctx,
        );
        let newer = mgr.spawn_class_strings(apk, "Lcom/foo/Baz;", &ctx);
        assert_ne!(newer, old);
        drop(rel);
        assert!(drain_stale_of(&mut mgr, old), "old result must be stale");
    }

    /// A burst of distinct submissions cannot create unlimited threads:
    /// at most [`MAX_TASK_THREADS`] run at once, the rest wait in the
    /// queue and drain as slots free.
    #[test]
    fn submit_burst_is_capped_and_drains() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let total = MAX_TASK_THREADS + 3;
        let mut releases = Vec::new();
        for i in 0..total {
            let (tx, rx) = channel::<()>();
            let outcome = ok_source(&format!("t{i}"));
            mgr.submit(
                TaskKind::DecompileClass,
                format!("t{i}"),
                move || {
                    let _ = rx.recv_timeout(std::time::Duration::from_secs(10));
                    outcome
                },
                &ctx,
            );
            releases.push(tx);
        }
        assert_eq!(mgr.in_flight_count(), total);
        assert_eq!(
            mgr.queued_count(),
            total - MAX_TASK_THREADS,
            "excess jobs must wait, not spawn a thread each"
        );
        for tx in &releases {
            let _ = tx.send(());
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut done = 0usize;
        while mgr.has_in_flight() && std::time::Instant::now() < deadline {
            done += mgr.poll().len();
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        done += mgr.poll().len();
        assert_eq!(done, total, "every queued job eventually runs");
        assert_eq!(mgr.queued_count(), 0);
    }

    /// Fill every worker slot with a job that blocks until the returned
    /// senders fire. The cap is then exactly saturated, so anything
    /// submitted afterwards is queued — no sleep decides that.
    fn fill_all_slots(
        mgr: &mut TaskManager,
        ctx: &egui::Context,
    ) -> Vec<std::sync::mpsc::Sender<()>> {
        let mut release = Vec::with_capacity(MAX_TASK_THREADS);
        for i in 0..MAX_TASK_THREADS {
            let (_id, tx) = gated(
                mgr,
                TaskKind::DecompileClass,
                &format!("fill{i}"),
                ok_source(&format!("fill{i}")),
                ctx,
            );
            release.push(tx);
        }
        assert_eq!(mgr.active.load(Ordering::Acquire), MAX_TASK_THREADS);
        assert_eq!(mgr.queued_count(), 0, "every filler got a thread");
        release
    }

    /// Poll until nothing is in flight (including jobs admitted by `pump`
    /// during the drain), then wait for the last worker threads to drop
    /// their slots. Returns every completion observed.
    fn drain_all(mgr: &mut TaskManager) -> Vec<CompletedTask> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut done = Vec::new();
        loop {
            done.extend(mgr.poll());
            if !mgr.has_in_flight() || std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        while mgr.active.load(Ordering::Acquire) != 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        done
    }

    /// A job superseded while it is still *queued* must never start: the
    /// queue must not spend a worker (and a whole-artifact engine scan) on
    /// a result that will be discarded on arrival — and it must not sit in
    /// front of the request the user actually asked for.
    #[test]
    fn superseded_queued_job_never_starts() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let release = fill_all_slots(&mut mgr, &ctx);

        // Queued behind the saturated cap: one loser, then one wanted job.
        let ran_dead = Arc::new(AtomicUsize::new(0));
        let ran_live = Arc::new(AtomicUsize::new(0));
        let dead = {
            let ran = Arc::clone(&ran_dead);
            mgr.submit(
                TaskKind::FindRefs,
                "dead",
                move || {
                    ran.fetch_add(1, Ordering::AcqRel);
                    TaskOutcome::Search(asc_core::SearchReport::empty())
                },
                &ctx,
            )
        };
        let live = {
            let ran = Arc::clone(&ran_live);
            mgr.submit(
                TaskKind::FindRefs,
                "live",
                move || {
                    ran.fetch_add(1, Ordering::AcqRel);
                    TaskOutcome::Search(asc_core::SearchReport::empty())
                },
                &ctx,
            )
        };
        assert_eq!(mgr.queued_count(), 2, "both wait for a free slot");
        mgr.cancel(dead);

        for tx in &release {
            let _ = tx.send(());
        }
        let done = drain_all(&mut mgr);

        assert_eq!(
            ran_dead.load(Ordering::Acquire),
            0,
            "a superseded queued job must never execute"
        );
        assert_eq!(
            ran_live.load(Ordering::Acquire),
            1,
            "the live job must still run"
        );
        assert!(
            done.iter()
                .find(|t| t.id == dead)
                .expect("dropped job retires")
                .stale,
            "the dropped job retires as a discarded completion"
        );
        assert!(
            !done
                .iter()
                .find(|t| t.id == live)
                .expect("live job completes")
                .stale,
            "the live job's result must apply"
        );
        assert_eq!(mgr.in_flight_count(), 0, "no task slot leaks");
        assert_eq!(mgr.queued_count(), 0, "the queue drains");
        assert_eq!(
            mgr.active.load(Ordering::Acquire),
            0,
            "no worker slot leaks"
        );
    }

    /// Same rule driven by the generation: a job queued against a session
    /// that was then reloaded (APK opened) must not burn a worker.
    #[test]
    fn generation_bump_skips_queued_job() {
        let mut mgr = TaskManager::new();
        let ctx = ctx();
        let release = fill_all_slots(&mut mgr, &ctx);

        let ran = Arc::new(AtomicUsize::new(0));
        let old = {
            let ran = Arc::clone(&ran);
            mgr.submit(
                TaskKind::FindRefs,
                "old-session",
                move || {
                    ran.fetch_add(1, Ordering::AcqRel);
                    TaskOutcome::Search(asc_core::SearchReport::empty())
                },
                &ctx,
            )
        };
        assert_eq!(mgr.queued_count(), 1);
        let generation = mgr.bump_generation();
        assert_eq!(generation, mgr.generation());

        for tx in &release {
            let _ = tx.send(());
        }
        let done = drain_all(&mut mgr);

        assert_eq!(
            ran.load(Ordering::Acquire),
            0,
            "an old-generation queued job must never execute"
        );
        let retired = done
            .iter()
            .find(|t| t.id == old)
            .expect("old-generation job retires");
        assert!(retired.stale, "its completion must be stale");
        assert_eq!(retired.generation, SessionGeneration::INITIAL);
        assert_eq!(mgr.in_flight_count(), 0);
        assert_eq!(mgr.queued_count(), 0);
        assert_eq!(mgr.active.load(Ordering::Acquire), 0);
    }
}
