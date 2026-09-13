//! # asc-bytecode
//!
//! Dalvik opcode metadata and a non-allocating reference walker for ASC-RS.
//!
//! ## Responsibility
//! - Hold the complete `0x00..=0xFF` opcode table: format, width in 16-bit
//!   code units, and reference-slot locations.
//! - Detect the three payload pseudo-instructions (`packed-switch`,
//!   `sparse-switch`, `fill-array-data`) and skip over them safely.
//! - Provide a zero-allocating iterator ([`RefWalker`]) that yields every
//!   reference-bearing instruction in a code body and reports malformed
//!   input via [`BytecodeError`].
//!
//! ## Non-responsibility
//! - DEX container parsing (lives in `asc-dex`).
//! - Code analysis, CFG/SSA, decompilation (lives in `asc-decompile`).
//! - Query orchestration (lives in `asc-query`).
//! - In-place rewriting of the indexes (lives in `asc-rebuild`; this
//!   crate only *locates* them).
//!
//! ## Invariants
//! - The full opcode table is populated for every `0x00..=0xFF` byte.
//!   Unassigned / reserved bytes map to `OpcodeInfo { is_unknown: true,
//!   width_units: 1, .. }` so the walker fails fast rather than silently
//!   skipping a byte.
//! - Every reference-slot position (`unit_off`) is strictly less than the
//!   instruction's declared `width_units` — verified at table-build time.
//! - `RefWalker` never allocates: it holds a `&[u8]` plus three `u32` /
//!   `bool` fields, and emits a `Copy` `RefInstruction` per yield.
//! - No `unwrap` / `expect` / panic on untrusted input. Every code-unit
//!   arithmetic path uses `checked_add` / `checked_mul` so an adversarially
//!   crafted `insns` buffer (e.g. size field = `0xFFFFFFFF`) is reported
//!   as [`BytecodeError::MalformedPayload`], not a crash.
//! - Construction validates `insns.len() == insns_units * 2`; any other
//!   relationship is [`BytecodeError::LengthMismatch`].
//!
//! ## Allocation behavior
//! None. The library is allocation-free on the reference-walk path; the
//! opcode table itself is a `const` array living in static memory.
//!
//! ## Safety
//! Safe Rust only. No `unsafe` blocks.
//!
//! ## DEX-version coverage
//! The reference-bearing opcode set covers DEX 035–041:
//! - DEX 035 +: `const-string` (0x1a), `const-class` (0x1c), `check-cast`
//!   (0x1f), `instance-of` (0x20), `new-instance` (0x22), `new-array`
//!   (0x23), `filled-new-array` (0x24) / `/range` (0x25), `iget/iput`
//!   family (0x52–0x5f), `sget/sput` family (0x60–0x6d), `invoke-*`
//!   family (0x6e–0x72) / `/range` (0x74–0x78).
//! - DEX 038 +: `invoke-polymorphic` (0xfa) / `/range` (0xfb),
//!   `invoke-custom` (0xfc) / `/range` (0xfd).
//! - DEX 039 +: `const-method-handle` (0xfe), `const-method-type` (0xff).
//!
//! ## Example
//!
//! ```no_run
//! use asc_bytecode::{RefWalker, RefInstruction, DexRef};
//!
//! // Bytecode: const-string v0, "hi";  sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;;
//! //            invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
//! let insns: [u8; 12] = [
//!     0x1a, 0x00, 0x10, 0x00, // const-string v0, string@0x0010
//!     0x62, 0x01, 0x20, 0x00, // sget-object v1, field@0x0020
//!     0x6e, 0x12, 0x30, 0x00, // invoke-virtual {v1, v0}, meth@0x0030 (3 units; ignore the rest)
//! ];
//! let walker = RefWalker::new(&insns, (insns.len() / 2) as u32).unwrap();
//! let hits: Vec<_> = walker.filter_map(|r| r.ok()).collect();
//! assert_eq!(hits.len(), 3);
//! assert!(matches!(hits[0].primary, Some(DexRef::String(_))));
//! assert!(matches!(hits[1].primary, Some(DexRef::Field(_))));
//! assert!(matches!(hits[2].primary, Some(DexRef::Method(_))));
//! ```
//!
//! asc-bytecode deliberately imports the typed pool-index contract from
//! `crate::dex_ids`, a verbatim copy of `asc_dex::ids`. At integration
//! the Lead replaces that module body with `pub use asc_dex::ids::*;`;
//! no consumer needs to change.

#![deny(unsafe_op_in_unsafe_fn)]
// `unsafe` is not used inside the crate.

pub mod dex_ids;

pub mod opcode;
pub mod walker;

mod error;

pub use crate::dex_ids::{
    CallSiteIdx, FieldIdx, MethodHandleIdx, MethodIdx, ProtoIdx, StringIdx, TypeIdx,
    NO_INDEX,
};
pub use crate::error::BytecodeError;
pub use crate::opcode::{opcode_info, Format, OpcodeInfo, OPCODE_TABLE, RefKind, RefSlot};
pub use crate::walker::{walk_verify, DexRef, RefInstruction, RefWalker};
