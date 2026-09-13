//! User-facing query model.
//!
//! A [`Query`] is intentionally small and serializable (the public fields
//! are `String` / `Option<String>` / `Option<ClassConstraint>`). The
//! engine converts a `Query` into a [`crate::TargetSets`] via
//! [`crate::resolve_target_ids`] and then scans code bodies for hits.
//!
//! ## Semantics (matches `reference/BEHAVIOR.md` §3)
//!
//! - `Query::String` — substring match over the MUTF-8 string payload.
//!   The pattern is **never** compiled as a regex; it is treated as a
//!   literal byte sequence. ASCII patterns short-circuit to a fast
//!   `slice::contains` over the raw `mutf8` bytes; non-ASCII patterns
//!   fall back to a `decode_lossy` substring check.
//! - `Query::Type` — substring match over the descriptor text (the
//!   `StringIdx` the `type_id` table points at). No descriptor
//!   normalization is applied; callers pass the descriptor (or fragment
//!   of it) they want to find.
//! - `Query::Method` / `Query::Field` — substring match over the
//!   member's name (`StringIdx` of the `name` field). Optionally
//!   constrained by [`ClassConstraint`]:
//!   - `exact = true` — the class pattern is normalized to the Dalvik
//!     descriptor form (`com.poc.Main` → `Lcom/poc/Main;`) and matched
//!     as an exact descriptor equality.
//!   - `exact = false` — substring match over descriptors.
//! - At least one of `name` or `class` must be supplied for method/field
//!   queries. The CLI layer enforces this; the engine itself returns an
//!   empty target set for a query with both `None`.

use smallvec::SmallVec;

use asc_dex::ids::{FieldIdx, MethodIdx, StringIdx, TypeIdx};

/// A class constraint for method / field queries.
///
/// Construct one via [`ClassConstraint::new`] or [`ClassConstraint::new_exact`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassConstraint {
    /// Raw pattern. For `exact` queries this is the original
    /// `com.poc.Main` form; for fuzzy queries it is whatever substring
    /// the user passed. Normalization happens inside
    /// [`crate::locator`].
    pub pattern: String,
    /// When `true`, the pattern is normalized to Dalvik descriptor form
    /// and matched as full equality. When `false`, the pattern is
    /// substring-matched over descriptors.
    pub exact: bool,
}

impl ClassConstraint {
    /// A fuzzy / substring class constraint.
    #[inline]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            exact: false,
        }
    }

    /// An exact / descriptor-equality class constraint.
    ///
    /// `com.poc.Main`, `Lcom/poc/Main;`, and `Lcom/poc/Main` are all
    /// accepted; the descriptor form is reconstructed inside the
    /// locator.
    #[inline]
    pub fn new_exact(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            exact: true,
        }
    }
}

/// A user-facing findrefs query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    /// Find callers of any opcode that takes a string-id operand
    /// (`const-string`, `const-string/jumbo`) when the referenced
    /// string contains `pattern` as a substring.
    String {
        /// Substring pattern; never a regex.
        pattern: String,
    },
    /// Find callers of any opcode that takes a type-id operand
    /// (`const-class`, `check-cast`, `instance-of`, `new-instance`,
    /// `new-array`, `filled-new-array`, `filled-new-array/range`) when
    /// the referenced type's descriptor contains `pattern`.
    Type {
        /// Substring pattern over the descriptor text.
        pattern: String,
    },
    /// Find callers of any opcode that takes a method-id operand
    /// (`invoke-*`, `invoke-polymorphic`, `invoke-custom`) when the
    /// referenced method's name matches `name` (and `class` filter).
    Method {
        /// Substring pattern over the method name. `None` means "any
        /// name" (only the class filter, if any, applies).
        name: Option<String>,
        /// Optional class filter.
        class: Option<ClassConstraint>,
    },
    /// Find callers of any opcode that takes a field-id operand
    /// (`iget*`, `iput*`, `sget*`, `sput*`) when the referenced
    /// field's name matches `name` (and `class` filter).
    Field {
        /// Substring pattern over the field name. `None` means "any
        /// name" (only the class filter, if any, applies).
        name: Option<String>,
        /// Optional class filter.
        class: Option<ClassConstraint>,
    },
}

impl Query {
    /// Constructs a `Query::String`.
    #[inline]
    pub fn string(pattern: impl Into<String>) -> Self {
        Query::String {
            pattern: pattern.into(),
        }
    }

    /// Constructs a `Query::Type`.
    #[inline]
    pub fn type_(pattern: impl Into<String>) -> Self {
        Query::Type {
            pattern: pattern.into(),
        }
    }

    /// Constructs a `Query::Method`. `name` and `class` are independent:
    /// either or both may be supplied. Passing both `None` produces a
    /// query whose target set is empty (the engine returns an empty
    /// report without scanning).
    #[inline]
    pub fn method(name: Option<impl Into<String>>, class: Option<ClassConstraint>) -> Self {
        Query::Method {
            name: name.map(Into::into),
            class,
        }
    }

    /// Constructs a `Query::Field`. Same conventions as [`Query::method`].
    #[inline]
    pub fn field(name: Option<impl Into<String>>, class: Option<ClassConstraint>) -> Self {
        Query::Field {
            name: name.map(Into::into),
            class,
        }
    }

    /// Returns `true` when this query is structurally empty (neither
    /// name nor class given for method/field variants).
    pub fn is_empty(&self) -> bool {
        match self {
            Query::String { pattern } | Query::Type { pattern } => pattern.is_empty(),
            Query::Method { name, class } | Query::Field { name, class } => {
                name.as_ref().is_none_or(|n| n.is_empty())
                    && class.as_ref().is_none_or(|c| c.pattern.is_empty())
            }
        }
    }
}

/// Result of [`crate::resolve_target_ids`] — the per-kind id sets the
/// query resolved to. All fields default to an empty [`SmallVec`]; the
/// variants of [`Query`] that don't touch a particular kind leave its
/// set empty.
///
/// The engine converts this to a [`crate::TargetSets`] (sorted
/// `Vec<u32>` per kind with binary-search membership) before the scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedTargets {
    /// `StringIdx` set for a `Query::String`.
    pub strings: SmallVec<[StringIdx; 8]>,
    /// `TypeIdx` set for a `Query::Type`.
    pub types: SmallVec<[TypeIdx; 8]>,
    /// `FieldIdx` set for a `Query::Field`.
    pub fields: SmallVec<[FieldIdx; 8]>,
    /// `MethodIdx` set for a `Query::Method`.
    pub methods: SmallVec<[MethodIdx; 8]>,
}

impl ResolvedTargets {
    /// Returns `true` when no id set is populated.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
            && self.types.is_empty()
            && self.fields.is_empty()
            && self.methods.is_empty()
    }

    /// Total number of resolved ids across all kinds.
    #[inline]
    pub fn len(&self) -> usize {
        self.strings.len() + self.types.len() + self.fields.len() + self.methods.len()
    }
}
