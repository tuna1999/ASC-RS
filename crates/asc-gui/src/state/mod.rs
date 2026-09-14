//! GUI state modules: headless-testable controllers that own all
//! mutation. UI draw functions read from these and emit commands;
//! they never call the engine and never mutate engine-derived state
//! directly.

pub mod documents;

pub use documents::{DEFAULT_DOCUMENT_BUDGET, Document, DocumentCache};
