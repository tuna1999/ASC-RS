//! # asc-core
//!
//! Orchestration: getclass (parallel DEX scan, winner-takes-all) and findrefs
//! (all DEX entries) pipelines over asc-apk/asc-dex/asc-query/asc-rebuild,
//! bounded native worker parallelism, cancellation, `SearchReport`
//! partial-completeness error model, output formatting.
//!
//! Wave-3 scaffold (starts after query + rebuild + decompiler work).
