//! Errors produced by `asc-query`.
//!
//! Every variant records enough context (pool name, code_off, class
//! descriptor) to point a developer at the cause without exposing
//! untrusted bytes back to the caller.

use thiserror::Error;

/// One error recorded during a single-DEX findrefs scan.
///
/// The engine never panics on untrusted input. Bad DEX bytes, broken
/// `code_off`s, and walker failures all surface as [`SearchError`] and
/// mark the report `complete = false`. Partial hits gathered up to the
/// point of failure are preserved.
#[derive(Debug, Error)]
pub enum SearchError {
    /// `DexView` returned a structural error while resolving a query
    /// (e.g. truncated string data, bad mutf8). The `pool` names the
    /// pool the locator was iterating.
    #[error("locator failed in {pool}: {source}")]
    Locator {
        /// Pool the failure happened in (`string_ids`, `type_ids`,
        /// `field_ids`, `method_ids`, `class_data`, …).
        pool: &'static str,
        /// The underlying `DexError`.
        #[source]
        source: asc_dex::error::DexError,
    },

    /// `code_item` could not be read at `code_off`.
    #[error("code_item at code_off 0x{code_off:x} unreadable: {source}")]
    Code {
        /// The `code_off` from the owning class.
        code_off: u32,
        /// The underlying `DexError`.
        #[source]
        source: asc_dex::error::DexError,
    },

    /// `RefWalker::new` rejected the instruction buffer (length
    /// mismatch with `insns_size * 2`).
    #[error("ref_walker init failed at code_off 0x{code_off:x}: {source}")]
    WalkerInit {
        /// The `code_off` the walker was built for.
        code_off: u32,
        #[source]
        source: asc_bytecode::BytecodeError,
    },

    /// The walker reported a malformed opcode at the given code_off /
    /// offset. The walker terminates after the first error.
    #[error("ref_walker error at code_off 0x{code_off:x} insn offset 0x{insn_offset:x}: {source}")]
    Walker {
        /// The `code_off` containing the failure.
        code_off: u32,
        /// Code-unit offset inside `insns` where the failure was
        /// detected (the walker advances strictly in 16-bit units).
        insn_offset: u32,
        #[source]
        source: asc_bytecode::BytecodeError,
    },

    /// A `DexRef::String` decoded by the walker could not be resolved
    /// against `string_ids` (`view.string` failed). The scan keeps the
    /// strings already collected and marks the report incomplete.
    #[error(
        "string ref #{index} unresolvable at code_off 0x{code_off:x} insn offset 0x{insn_offset:x}: {source}"
    )]
    StringRef {
        /// The `code_off` of the body containing the reference.
        code_off: u32,
        /// Code-unit offset of the referencing instruction.
        insn_offset: u32,
        /// The unresolvable `string_ids` index.
        index: u32,
        #[source]
        source: asc_dex::error::DexError,
    },
}
