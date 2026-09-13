//! # asc-dex
//!
//! Zero-copy, lazy reader for DEX files (versions 035–041), including
//! logical DEX views inside DEX-041 physical containers.
//!
//! ## Responsibility
//! - Parse the DEX header and validate every pool extent.
//! - Provide typed (zero-copy) accessors for the string, type, proto,
//!   field, method, call-site, and method-handle pools.
//! - Decode MUTF-8 / ULEB128 / SLEB128.
//! - Expose `class_def_item`, `class_data_item`, `code_item`,
//!   `encoded_value` / `encoded_array` / `encoded_annotation`,
//!   `annotations_directory_item`, `debug_info_item`, and `map_list`.
//! - Discover logical DEX headers inside a DEX-041 container.
//!
//! ## Non-responsibility
//! - Dalvik opcode decoding (lives in `asc-bytecode`).
//! - APK / ZIP handling (lives in `asc-apk`).
//! - Higher-level queries (lives in `asc-query`).
//!
//! ## Invariants
//! - [`DexView::parse`] / [`DexView::parse_at`] are O(1): they read the
//!   header, bounds-check counts and offsets via checked arithmetic, and
//!   return. No pool is walked; no allocation is proportional to pool
//!   counts.
//! - All section offsets stored in the header and in any sub-structure are
//!   interpreted against the physical container (`physical`), never against
//!   `header_off` itself. This matches the DEX-041 encoding where every
//!   logical DEX header carries absolute offsets.
//! - Every accessor takes a typed index ([`crate::ids`]) or an explicit
//!   offset and returns `Result<_, DexError>`. Out-of-range input is
//!   reported, never panicked.
//! - Pool extents are checked once at parse via
//!   `pool_off + count*item_size <= physical.len()` using `checked_mul` /
//!   `checked_add` before any iteration trusts a count.
//!
//! ## Allocation behavior
//! - Per-item accessors do not allocate (they return borrowed slices or
//!   copy-out POD values).
//! - Iterators over pools allocate one `Vec` / owned struct per `next()`
//!   call only when an item genuinely needs owned state (e.g. `class_data`
//!   decoded lists, `EncodedValue::Array`).
//! - `string.decode_lossy` borrows the slice when the MUTF-8 payload is
//!   pure ASCII and allocates only when a replacement happened.
//!
//! ## Borrowing
//! All public views that hold slices (e.g. [`crate::DexStringRef`],
//! [`crate::pools::TypeList`], [`crate::code::CodeItem`]) borrow from the
//! underlying `physical` buffer with lifetime `'a`.
//!
//! ## Untrusted-input safety
//! - `unwrap`, `expect`, `panic`, and unchecked indexing are forbidden in
//!   input-facing code paths. All fixed-width reads go through the
//!   [`crate::read`] helpers, which perform the bounds check exactly once
//!   and return `Err(DexError)` on failure.
//!
//! ## Example
//!
//! ```no_run
//! use asc_dex::DexView;
//!
//! let bytes = std::fs::read("classes.dex").unwrap();
//! let view = DexView::parse(&bytes).unwrap();
//! assert_eq!(view.version().as_str(), "041");
//! for (idx, s) in view.strings() {
//!     let _text = s.decode_lossy();
//!     let _ = idx;
//! }
//! ```

#![doc(html_root_url = "https://docs.rs/asc-dex/0.1.0")]
#![deny(unsafe_op_in_unsafe_fn)]
// `unsafe` is not used inside the crate.

pub mod class;
pub mod code;
pub mod debug;
pub mod encoded;
pub mod error;
pub mod header;
pub mod ids;
pub mod leb;
pub mod map;
pub mod mutf8;
pub mod pools;
pub mod read;
pub mod view;

// Convenience re-exports so callers can `use asc_dex::*`.
pub use crate::class::{ClassData, ClassDef, EncodedField, EncodedMethod};
pub use crate::code::{CatchHandler, CatchHandlerList, CodeItem, TryItem, TriesIter};
pub use crate::debug::{
    DebugInfoHeader, DebugOp, DebugOps, DBG_ADVANCE_LINE, DBG_ADVANCE_PC, DBG_END_LOCAL,
    DBG_END_SEQUENCE, DBG_RESTART_LOCAL, DBG_SET_EPILOGUE_BEGIN, DBG_SET_FILE,
    DBG_SET_PROLOGUE_END, DBG_START_LOCAL, DBG_START_LOCAL_EXTENDED, DBG_LINE_BASE,
    DBG_LINE_RANGE,
};
pub use crate::encoded::{
    AnnotationItem, AnnotationSet, AnnotationSetRefList, AnnotationsDirectory, EncodedAnnotation,
    EncodedValue, FieldAnnotation, MethodAnnotation, ParameterAnnotation, ValueType,
    MAX_DEPTH as ENCODED_VALUE_MAX_DEPTH,
};
pub use crate::error::DexError;
pub use crate::header::{DexHeader, DexVersion};
pub use crate::ids::{
    CallSiteIdx, FieldIdx, MethodHandleIdx, MethodIdx, NO_INDEX, ProtoIdx, StringIdx, TypeIdx,
};
pub use crate::leb::{
    sleb128, sleb128_to_i32, uleb128, uleb128_to_u32, MAX_GENERIC_BYTES, MAX_I32_BYTES,
    MAX_U32_BYTES,
};
pub use crate::map::{MapItem, MapIter};
pub use crate::mutf8::{decode_lossy as decode_mutf8_lossy, find_terminator, MAX_STRING_SCAN};
pub use crate::pools::{
    is_no_index, DexStringRef, FieldIdItem, FieldOrMethod, FieldIter, MethodHandleItem,
    MethodIdItem, MethodIter, ProtoIdItem, ProtoIter, StringIter, TypeIter, TypeList, TypeListIter,
};
pub use crate::view::DexView;
