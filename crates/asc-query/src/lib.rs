//! # asc-query
//!
//! Stateless query engine: string / type / method / field locators,
//! code-owner discovery (method_idx + code_off, deduplicated by code_off),
//! reference scanning via `RefWalker`, and result aggregation.
//!
//! ## Design (see architecture §12 / §13 / §14 / §25)
//!
//! - Sequential scans for one-shot queries; no global xref preprocessing,
//!   no `HashMap<ClassIdx, HashSet<MethodIdx>>` in the engine path.
//! - `find_refs` operates on a single borrowed `&DexView`; the physical
//!   buffer is never copied.
//! - The query resolves to a small set of pool indices; an empty set
//!   short-circuits the scan entirely (no code-item traversal).
//! - Method/field deduplication by `code_off` follows the R8 model:
//!   one `CodeOwner { code_off, methods: SmallVec<[MethodIdx; 2]> }`
//!   per unique code body, scanned once, hits emitted for every owner.
//! - Walker errors and malformed `code_off`s are recorded as
//!   `SearchError`s and mark the report `complete = false`; partial
//!   hits are preserved.
//!
//! ## Non-responsibility
//!
//! - APK / DEX-041 orchestration and parallelism (lives in `asc-core`).
//! - In-place reference rewriting (lives in `asc-rebuild`).
//! - Decompilation (lives in `asc-decompile`).
//!
//! ## Module map
//!
//! - [`query`] — [`Query`] and [`ClassConstraint`].
//! - [`locator`] — [`resolve_target_ids`], [`class_defines`], per-kind
//!   resolvers that walk the pools sequentially.
//! - [`owner`] — [`CodeOwner`] and [`CodeOwners::build`].
//! - [`scan`] — [`find_refs`], [`DexSearchReport`], [`RefHit`],
//!   [`SearchError`], [`TargetSets`].

#![deny(unsafe_op_in_unsafe_fn)]
// No `unsafe` in this crate.

mod callees;
mod error;
mod locator;
mod owner;
mod query;
mod scan;
mod strings_of;
pub use crate::callees::{Callee, callees_of};
pub use crate::error::SearchError;
pub use crate::locator::{class_defines, resolve_target_ids};
pub use crate::owner::{CodeOwner, CodeOwners};
pub use crate::query::{ClassConstraint, Query};
pub use crate::scan::{DexSearchReport, RefHit, TargetSets, find_refs};
pub use crate::strings_of::{ClassString, strings_of_class};
