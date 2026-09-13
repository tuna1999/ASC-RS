//! Typed DEX pool indexes re-exported from asc-dex.
//!
//! This module began as a Lead-seeded verbatim copy of the contract so
//! asc-bytecode could be built concurrently with asc-dex; at wave-1
//! integration it became a thin re-export. All imports throughout this
//! crate continue to go through `crate::dex_ids`, so the physical origin
//! of the types stays an implementation detail.

pub use asc_dex::ids::*;
