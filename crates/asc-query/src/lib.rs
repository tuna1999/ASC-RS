//! # asc-query
//!
//! Stateless query engine: string/type/method/field locators, code-owner
//! discovery (method_idx + code_off, deduplicated by code_off), reference
//! scanning via `RefWalker`, result aggregation.
//!
//! Sequential scans for one-shot queries; no global xref preprocessing, no
//! `HashMap<ClassIdx, HashSet<MethodIdx>>` unless benchmarks justify it for
//! GUI/workspace use (kept out of the stateless CLI path).
//!
//! Wave-2 scaffold (starts after asc-dex/asc-bytecode APIs stabilize).
