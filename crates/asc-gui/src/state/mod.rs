//! GUI state modules: headless-testable controllers that own all
//! mutation. UI draw functions read from these and emit commands;
//! they never call the engine and never mutate engine-derived state
//! directly.

pub mod documents;
pub mod navigation;
pub mod search;
pub mod tabs;

pub use documents::{DEFAULT_DOCUMENT_BUDGET, Document, DocumentCache};
pub use navigation::{NavOrigin, NavigationHistory, NavigationLocation};
pub use search::{SearchController, SearchKind, SearchResults, SearchRow};
pub use tabs::{Tab, TabController, TabKind, TabStatus};
