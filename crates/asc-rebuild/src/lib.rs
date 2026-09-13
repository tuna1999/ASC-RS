//! # asc-rebuild
//!
//! Minimal standalone DEX reconstruction: dependency closure → selected IDs
//! (sorted by original index) → old→new remaps → reference rewriting →
//! valid DEX layout → map_list → SHA-1 signature → Adler32 checksum.
//!
//! Emits standards-valid standalone DEX (never intentionally-zero checksums,
//! never standalone 041).
//!
//! Wave-2 scaffold (starts after asc-dex/asc-bytecode APIs stabilize).
