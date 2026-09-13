//! # asc-dex
//!
//! Zero-copy, lazy reader for DEX files (versions 035–041), including logical
//! DEX views inside DEX-041 physical containers.
//!
//! - Responsible for: header/pool parsing, typed indexes, ULEB128/SLEB128,
//!   MUTF-8, class_defs/class_data, code_items, try/catch handlers,
//!   encoded_values, annotations, debug_info primitives, map_list.
//! - Not responsible for: opcode decoding (asc-bytecode), APK/ZIP handling
//!   (asc-apk), queries (asc-query).
//! - Invariants: `DexView::parse` is O(1); pool access is O(1) per item;
//!   section offsets are always interpreted against the physical container
//!   (never offset by `header_off`); no allocation proportional to pool
//!   counts during parse; never panics on untrusted input.
//!
//! Wave-1 scaffold; implementation lands with the asc-dex agent.

pub mod ids;
