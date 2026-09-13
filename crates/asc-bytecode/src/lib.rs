//! # asc-bytecode
//!
//! Dalvik opcode metadata (formats, instruction widths, reference operand
//! locations) and `RefWalker`, a non-allocating scanner that yields every
//! reference-bearing instruction in a code body.
//!
//! - Responsible for: opcode tables (0x00–0xFF + payload pseudo-instructions
//!   0x0100/0x0200/0x0300), reference extraction (string/type/field/method/
//!   proto/call-site/method-handle), malformed-instruction error reporting.
//! - Not responsible for: DEX container parsing (asc-dex), CFG/SSA/
//!   decompilation, scanning orchestration (asc-query).
//! - Invariants: walking never allocates; unknown opcodes and truncated
//!   instructions are reported as errors, never silently skipped; never
//!   panics on untrusted bytes.
//!
//! Wave-1 scaffold; implementation lands with the asc-bytecode agent.

pub mod dex_ids;
