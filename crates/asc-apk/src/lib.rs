//! # asc-apk
//!
//! Read-only APK (ZIP) engine over an mmap: EOCD + central directory parsing,
//! `classes*.dex` discovery, bounded STORED/DEFLATE extraction.
//!
//! - Responsible for: ZIP structure parsing, entry listing, dex-entry
//!   discovery (numeric ordering), bounded inflation with configurable
//!   output caps, in-memory variant for fuzzing/differential tests.
//! - Not responsible for: DEX parsing (asc-dex), parallel scan orchestration
//!   (asc-core), deflate bitstream heuristics (V2 concern only).
//! - Invariants: never trusts sizes/offsets without bounds checks; STORED
//!   entries borrow directly from the mmap; DEFLATE output is capped; APIs
//!   are synchronous, `Send`/`Sync`, cancellation-friendly; never panics on
//!   untrusted input.
//!
//! Wave-1 scaffold; implementation lands with the asc-apk agent.
