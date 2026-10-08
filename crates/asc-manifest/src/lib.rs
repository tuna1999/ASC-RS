//! # asc-manifest
//!
//! Binary AXML (AndroidManifest.xml inside APKs) parsing for display:
//! package/version, permissions, activities/services/receivers/providers
//! (with intent filters incl. `<data>` specs, `autoVerify`, `priority`),
//! `activity-alias`, application attributes and `<meta-data>`, `<queries>`,
//! `<uses-feature>`, and split-APK markers. Read-only, bounds-checked.
//!
//! ## Format overview
//!
//! Android's compiled binary XML is a chunk-based stream:
//!
//! ```text
//! ResChunk_header { type: u16, headerSize: u16, size: u32 }
//! ```
//!
//! The first chunk is the document (`RES_XML_TYPE = 0x0003`); inside it
//! sit (in order) a string pool, an optional resource map, and a sequence
//! of events: namespaces (`0x0100` / `0x0101`), elements (`0x0102` /
//! `0x0103`), and (rarely) CDATA (`0x0104`). String pools are either
//! UTF-16LE (default) or UTF-8 (when the `UTF8_FLAG` bit is set).
//!
//! We model the document as a sequence of element-open / element-close
//! events with a stack of element names; we never build a full XML tree,
//! just enough to extract the summary fields a user-facing display needs.
//!
//! Attribute namespaces are resolved: an attribute only matches an
//! `android:` (or namespace-less) name when its namespace URI is absent
//! or `http://schemas.android.com/apk/res/android`; foreign namespaces
//! (e.g. `tools:`, `dist:`) are recorded but never confused with Android
//! attributes.
//!
//! ## Layout conventions (AOSP)
//!
//! Every chunk starts with an 8-byte `ResChunk_header`. The chunk's
//! type-specific fields are laid out at a chunk-type-specific offset
//! from the chunk's start:
//!
//! | Chunk type                                | Type-specific fields at |
//! |-------------------------------------------|--------------------------|
//! | `RES_STRING_POOL_TYPE` (`0x0001`)         | chunk_start + 8          |
//! | `RES_XML_RESOURCE_MAP_TYPE` (`0x0180`)   | chunk_start + 8          |
//! | `RES_XML_START_NAMESPACE_TYPE` (`0x0100`)| chunk_start + 16 (after `ResXMLTree_node`) |
//! | `RES_XML_END_NAMESPACE_TYPE` (`0x0101`)  | chunk_start + 16         |
//! | `RES_XML_START_ELEMENT_TYPE` (`0x0102`)  | chunk_start + 16         |
//! | `RES_XML_END_ELEMENT_TYPE` (`0x0103`)    | chunk_start + 16         |
//!
//! The `headerSize` field of the chunk header is informational only; we
//! never use it to compute field offsets.
//!
//! ## Invariants
//!
//! - Never panics on untrusted input: every chunk size is bounds-checked
//!   before the body is read; every string index is validated against the
//!   string pool; counts are capped.
//! - Every UTF-8 length prefix is treated as the variable-length encoding
//!   AOSP uses (`< 0x80` → 1 byte, else 2 bytes with the high bit cleared).

use std::fmt;
use std::path::Path;

use thiserror::Error;

// ---------------------------------------------------------------------------
// Constants — see AOSP `frameworks/base/include/androidfw/ResourceTypes.h`.
#[expect(dead_code)] // documented for completeness (magic word byte 3)
const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const RES_XML_CDATA_TYPE: u16 = 0x0104;

const NO_INDEX: u32 = 0xFFFF_FFFF;

/// The Android resource namespace URI every `android:` attribute carries.
pub const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

/// Sanity caps. These are large enough to cover every real APK in the
/// wild (Android's own build emits manifests a few hundred KB at most)
/// while keeping a single chunk from claiming terabytes of input.
const MAX_STRING_COUNT: u32 = 1 << 20;
const MAX_STRING_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CHUNK_BODY: u64 = 64 * 1024 * 1024;
const MAX_CHILDREN: usize = 1 << 20;

/// Offset (relative to the chunk's start) of the type-specific fields
/// for each chunk type we recognize.
const XML_TREE_BODY_OFF: usize = 16; // namespace / element events all use this

// ---------------------------------------------------------------------------
// Public types.
// ---------------------------------------------------------------------------

/// Errors produced by [`parse_manifest`] / [`parse_from_apk`].
#[derive(Debug, Error)]
pub enum ManifestError {
    /// First chunk was not the Android XML document header
    /// (`0x00080003`). Probably not a binary XML file at all.
    #[error("not a binary Android XML file (magic mismatch)")]
    NotAXml,

    /// The input carries no `AndroidManifest.xml` at all: the APK has no
    /// such entry, or the input is a raw DEX (which cannot have one). This
    /// is *absence*, not a parse failure — callers must not report it as
    /// malformed input.
    #[error("no AndroidManifest.xml: {0}")]
    NotFound(String),

    /// A header advertised a size that would read past EOF, or a fixed-
    /// width field read would underflow the remaining bytes.
    #[error("truncated binary XML: {0}")]
    Truncated(String),

    /// The parser refused to consume a chunk that uses an unsupported
    /// feature (UTF-16-only string pools are universally supported;
    /// this is for genuinely novel feature bits).
    #[error("unsupported binary XML feature: {0}")]
    Unsupported(String),

    /// A chunk header is internally inconsistent: its declared
    /// `headerSize` is smaller than the fixed portion of that chunk
    /// type, or its `size` doesn't cover the header.
    #[error("malformed binary XML chunk: {0}")]
    BadChunk(String),

    /// Underlying filesystem / mmap / read failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// One `<uses-permission>` or `<permission>` entry from the manifest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PermissionEntry {
    /// The permission name (e.g. `android.permission.INTERNET`).
    pub name: String,
    /// Declaration type: `uses` (`<uses-permission>`), `uses-sdk-23`
    /// (`<uses-permission-sdk-23>`/`-sdk-m>` — requested only on M+),
    /// or `declares` (`<permission>` — the app *defines* it).
    pub decl: &'static str,
    /// `protectionLevel` attribute (e.g. `"normal"`, `"dangerous"`); `None`
    /// for `<uses-permission>` declarations which never carry one.
    pub protection_level: Option<String>,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// `android:maxSdkVersion` on `<uses-permission>`: the permission is
    /// not requested on newer platforms.
    pub max_sdk: Option<u32>,
}

/// One `<data>` element of an `<intent-filter>` / queries `<intent>`.
/// Every field is `None` when the element did not declare it.
///
/// This is the **raw** representation, kept verbatim for fidelity. It is
/// *not* a list of independent URI alternatives: Android pools every
/// `<data>` element of one filter per attribute dimension, so a scheme
/// declared here can match a host declared on a *different* `<data>` of
/// the same filter — see [`IntentFilter::effective_data`].
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct DataSpec {
    /// `android:scheme` (e.g. `https`).
    pub scheme: Option<String>,
    /// `android:host` (e.g. `locket.app`).
    pub host: Option<String>,
    /// `android:port`.
    pub port: Option<String>,
    /// `android:path`.
    pub path: Option<String>,
    /// `android:pathPrefix`.
    pub path_prefix: Option<String>,
    /// `android:pathPattern`.
    pub path_pattern: Option<String>,
    /// `android:pathAdvancedPattern` (API 31+).
    pub path_advanced_pattern: Option<String>,
    /// `android:pathSuffix` (API 31+).
    pub path_suffix: Option<String>,
    /// `android:mimeType` (e.g. `image/*`).
    pub mime_type: Option<String>,
}

/// Which `<data>` path attribute a [`PathMatcher`] came from; the match
/// semantics differ per kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathMatchKind {
    /// `android:path` — the whole path must equal the value.
    Exact,
    /// `android:pathPrefix` — the value must prefix the path.
    Prefix,
    /// `android:pathPattern` — simple-glob pattern (API 1+).
    Pattern,
    /// `android:pathAdvancedPattern` — regex-like pattern (API 31+).
    AdvancedPattern,
    /// `android:pathSuffix` — the value must suffix the path (API 31+).
    Suffix,
}

/// One pooled path matcher.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PathMatcher {
    pub kind: PathMatchKind,
    pub value: String,
}

/// One pooled authority (`android:host` plus the `android:port` declared on
/// the same `<data>`; `None` = any port).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Authority {
    pub host: String,
    pub port: Option<String>,
}

/// Android's *effective* URI match set for one `<intent-filter>`.
///
/// Every `<data>` element of a filter contributes to the **same** filter:
/// Android pools the attributes per dimension and matches each dimension
/// independently, so a scheme declared in one `<data>` matches a host
/// declared in another. The Android docs state the equivalence directly
/// ("All the `<data>` elements contained within the same `<intent-filter>`
/// element contribute to the same filter",
/// <https://developer.android.com/guide/topics/manifest/data-element>),
/// and `IntentFilter.matchData` confirms it: the scheme list, the
/// authority list and the path list are consulted independently.
///
/// Pooling is not the whole story: the dimensions are *dependent*. Per the
/// same page,
///
/// - "If a `scheme` isn't specified for the intent filter, all the other
///   URI attributes are ignored."
/// - "If a `host` isn't specified for the filter, the `port` attribute and
///   all the path attributes are ignored."
///
/// which AOSP `IntentFilter.matchData` implements by nesting: the authority
/// loop runs inside the `mDataSchemes != null` branch and the path loop
/// inside the authority branch. So a declared host/path can be **inert**;
/// each pool here stays verbatim (fidelity) and [`Self::dependency`] says
/// whether the platform actually consults it. Read the pools through
/// [`Self::effective_authorities`] / [`Self::effective_paths`] to get the
/// live set, and never materialize the cross product: the pools are flat on
/// purpose so a filter with many `<data>` elements cannot explode.
///
/// [`Self::has_uri_relative_groups`](IntentFilter::has_uri_relative_groups)
/// reports API 35 `<uri-relative-filter-group>` children, which this struct
/// does **not** model: when they are present the URI match surface below is
/// incomplete.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct EffectiveData {
    /// Pooled `android:scheme` values (Android dedupes these). Always
    /// effective.
    pub schemes: Vec<String>,
    /// Pooled authorities; host and port are bound per `<data>` element.
    /// Inert unless [`Self::dependency`] is [`UriDependency::Complete`].
    pub authorities: Vec<Authority>,
    /// Pooled path matchers. Inert unless [`Self::dependency`] is
    /// [`UriDependency::Complete`].
    pub paths: Vec<PathMatcher>,
    /// Pooled `android:mimeType` values. Always effective.
    pub mime_types: Vec<String>,
    /// Whether Android consults this filter's hosts/ports/paths at all;
    /// see [`UriDependency`].
    pub dependency: UriDependency,
}

/// How a filter's URI attributes depend on each other, i.e. which of the
/// declared hosts/ports/paths Android actually consults.
///
/// The three states are mutually exclusive and computed at filter level
/// (`scheme` and `host` are looked for anywhere in the filter, not per
/// `<data>` element).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UriDependency {
    /// A scheme *and* a host are declared somewhere in the filter, so every
    /// declared authority and path matcher takes effect.
    #[default]
    Complete,
    /// No `android:scheme` anywhere: Android ignores hosts, ports and paths
    /// ("all the other URI attributes are ignored"), and a MIME-typed
    /// intent is matched through [`EffectiveData::implicit_schemes`].
    NoScheme,
    /// A scheme but no `android:host` anywhere: ports and all path
    /// attributes are ignored.
    NoHost,
}

impl EffectiveData {
    /// Whether any URI attribute (scheme/host/path) is declared. When no
    /// scheme is declared anywhere in the filter, Android ignores hosts and
    /// paths, so `authorities` / `paths` only take effect together with a
    /// scheme.
    pub fn has_uri(&self) -> bool {
        !self.schemes.is_empty() || !self.authorities.is_empty() || !self.paths.is_empty()
    }

    /// Authorities Android actually consults: the pooled hosts when
    /// [`UriDependency::Complete`], otherwise nothing (a host without a
    /// scheme never matches).
    pub fn effective_authorities(&self) -> &[Authority] {
        match self.dependency {
            UriDependency::Complete => &self.authorities,
            UriDependency::NoScheme | UriDependency::NoHost => &[],
        }
    }

    /// Path matchers Android actually consults: the pooled paths when
    /// [`UriDependency::Complete`], otherwise nothing (a path needs both a
    /// scheme and a host).
    pub fn effective_paths(&self) -> &[PathMatcher] {
        match self.dependency {
            UriDependency::Complete => &self.paths,
            UriDependency::NoScheme | UriDependency::NoHost => &[],
        }
    }

    /// Schemes Android assumes when the filter declares a `mimeType` but no
    /// `android:scheme` anywhere: `content:` and `file:` (AOSP
    /// `matchData`: "If the filter does not specify any schemes, it will
    /// implicitly match intents with no scheme, or the schemes *content:* or
    /// *file:*"). Empty in every other case — an explicit scheme, or no
    /// MIME type, suppresses the implicit match.
    pub fn implicit_schemes(&self) -> &'static [&'static str] {
        if self.mime_types.is_empty() || !self.schemes.is_empty() {
            &[]
        } else {
            &["content", "file"]
        }
    }
}

/// Which URI part a `<uri-relative-filter-group>` matcher constrains.
/// `path*`, `fragment*` and `query*` attributes share the same five
/// attribute shapes ([`PathMatchKind`]), hence the reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UriPart {
    /// `android:path` / `pathPrefix` / `pathSuffix` / `pathPattern` /
    /// `pathAdvancedPattern`.
    Path,
    /// `android:fragment*` (API 35).
    Fragment,
    /// `android:query*` (API 35).
    Query,
}

/// One `path*` / `fragment*` / `query*` matcher declared inside a
/// `<uri-relative-filter-group>` `<data>` child.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UriPartMatcher {
    /// Which URI part this matcher constrains.
    pub part: UriPart,
    /// Which attribute shape declared it.
    pub kind: PathMatchKind,
    /// The declared value.
    pub value: String,
}

/// One `<data>` child of a `<uri-relative-filter-group>`.
///
/// Only `path*`, `fragment*` and `query*` attributes are legal here. The
/// `<data>` elements of one group are **ANDed** (unlike the `<data>`
/// elements of the filter itself, which are ORed), so two `path` matchers
/// in one group can never both match — which is exactly why ASC-RS reports
/// a group verbatim instead of folding it into [`EffectiveData`].
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct RelativeDataSpec {
    /// The declared matchers, in attribute order.
    pub parts: Vec<UriPartMatcher>,
}

/// One API 35 `<uri-relative-filter-group>` child of an `<intent-filter>`.
///
/// ASC-RS parses and preserves these so nothing is dropped, but it does
/// **not** evaluate them: the allow/deny ordering, the AND semantics of the
/// group's `<data>` children and their interaction with the filter's own
/// `<data>` (evaluated first, in source order) are not modelled. Treat
/// [`IntentFilter::effective_data`] as incomplete whenever
/// [`IntentFilter::has_uri_relative_groups`] is true.
///
/// The AOSP semantics and the implementation roadmap live in
/// `docs/research/uri-relative-filter-groups.md`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UriRelativeFilterGroup {
    /// `android:allow` — `true` (the platform default) when a matching
    /// group makes the filter match, `false` when it makes the filter
    /// *not* match.
    pub allow: bool,
    /// The group's `<data>` children in declaration order.
    pub data: Vec<RelativeDataSpec>,
}

impl Default for UriRelativeFilterGroup {
    fn default() -> Self {
        // `android:allow` defaults to true on the platform.
        Self {
            allow: true,
            data: Vec::new(),
        }
    }
}

/// One intent filter attached to a component (also reused for `<intent>`
/// entries inside `<queries>`, where `auto_verify` / `priority` stay
/// `None`).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct IntentFilter {
    /// Action URIs (e.g. `android.intent.action.MAIN`).
    pub actions: Vec<String>,
    /// Category names (e.g. `android.intent.category.LAUNCHER`).
    pub categories: Vec<String>,
    /// The **raw** `<data>` elements in source order (fidelity only — read
    /// [`Self::effective_data`] for the match set Android actually uses).
    pub data: Vec<DataSpec>,
    /// The pooled match set (see [`EffectiveData`]); computed at parse time
    /// so JSON consumers cannot misread `data` as independent URI
    /// alternatives.
    pub effective_data: EffectiveData,
    /// API 35 `<uri-relative-filter-group>` children, in declaration order.
    /// Reported raw and **not** evaluated; see
    /// [`UriRelativeFilterGroup`].
    pub uri_relative_groups: Vec<UriRelativeFilterGroup>,
    /// `android:autoVerify` (App Links, API 23+); `None` when undeclared.
    pub auto_verify: Option<bool>,
    /// `android:priority` (integer, may be negative); `None` when undeclared.
    pub priority: Option<i32>,
}

impl IntentFilter {
    /// Pool this filter's `<data>` elements into Android's match set.
    pub fn effective_data(&self) -> EffectiveData {
        let mut eff = EffectiveData::default();
        for d in &self.data {
            push_unique(&mut eff.schemes, d.scheme.as_deref());
            if let Some(host) = &d.host {
                let authority = Authority {
                    host: host.clone(),
                    port: d.port.clone(),
                };
                if !eff.authorities.contains(&authority) {
                    eff.authorities.push(authority);
                }
            }
            for (kind, value) in [
                (PathMatchKind::Exact, &d.path),
                (PathMatchKind::Prefix, &d.path_prefix),
                (PathMatchKind::Pattern, &d.path_pattern),
                (PathMatchKind::AdvancedPattern, &d.path_advanced_pattern),
                (PathMatchKind::Suffix, &d.path_suffix),
            ] {
                if let Some(value) = value {
                    let matcher = PathMatcher {
                        kind,
                        value: value.clone(),
                    };
                    if !eff.paths.contains(&matcher) {
                        eff.paths.push(matcher);
                    }
                }
            }
            push_unique(&mut eff.mime_types, d.mime_type.as_deref());
        }
        // `scheme` and `host` are looked for across the whole filter: a host
        // declared beside no scheme is ignored, and a path needs both.
        eff.dependency = if eff.schemes.is_empty() {
            UriDependency::NoScheme
        } else if eff.authorities.is_empty() {
            UriDependency::NoHost
        } else {
            UriDependency::Complete
        };
        eff
    }

    /// Whether this filter declares API 35 `<uri-relative-filter-group>`
    /// children, i.e. whether [`Self::effective_data`] is an incomplete
    /// description of the URI match surface.
    pub fn has_uri_relative_groups(&self) -> bool {
        !self.uri_relative_groups.is_empty()
    }
}

/// Push `value` when `Some` and not already present (Android also dedupes
/// pooled schemes; de-duplicating the other dimensions keeps the match set
/// small without changing it).
fn push_unique(out: &mut Vec<String>, value: Option<&str>) {
    if let Some(value) = value
        && !out.iter().any(|v| v == value)
    {
        out.push(value.to_string());
    }
}

/// One `<meta-data>` element (application level or inside a component).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct MetaDataEntry {
    /// `android:name`.
    pub name: String,
    /// `android:value` (literal string or rendered typed value).
    pub value: Option<String>,
    /// `android:resource` (rendered `@0x…` reference).
    pub resource: Option<String>,
}

/// How a component's effective `android:exported` was determined, and
/// whether that determination is installable for the app's target SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportedState {
    /// `android:exported` was declared; `exported` is that value.
    Explicit,
    /// The attribute is absent and the manifest is valid: the platform
    /// default applies, so the component is exported iff it declares an
    /// intent filter.
    LegacyInferred,
    /// The attribute is absent on a component that declares an intent
    /// filter while the app targets API 31+ (Android 12): the manifest is
    /// invalid and Android 12+ refuses to install it. `exported` keeps the
    /// legacy inference (`true`) for backwards compatibility.
    MissingRequired,
}

/// One activity / service / receiver declaration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ComponentEntry {
    /// Class name (e.g. `com.aurora.store.MainActivity`).
    pub name: String,
    /// Effective `android:exported`: the declared value when present,
    /// otherwise Android's inference (components with intent filters are
    /// exported, see the post-parse pass in [`parse_manifest`]).
    pub exported: bool,
    /// The explicitly declared `android:exported`; `None` when the
    /// attribute is absent (so `exported` above was inferred).
    pub exported_explicit: Option<bool>,
    /// How `exported` was determined / whether it is installable; see
    /// [`ExportedState::MissingRequired`].
    pub exported_state: ExportedState,
    /// `android:permission` attribute (optional).
    pub permission: Option<String>,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// `android:process` when the component runs in a non-default process.
    pub process: Option<String>,
    /// Nested `<intent-filter>` blocks (in source order).
    pub intent_filters: Vec<IntentFilter>,
    /// Nested `<meta-data>` entries.
    pub meta_data: Vec<MetaDataEntry>,
}

/// One `<activity-alias>` declaration. Carries the same shape as a
/// component plus `android:targetActivity`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ActivityAliasEntry {
    /// `android:targetActivity`.
    pub target_activity: Option<String>,
    /// The alias entry itself (name/exported/filters/…).
    #[serde(flatten)]
    pub component: ComponentEntry,
}

/// One `<provider>` declaration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ProviderEntry {
    /// Class name.
    pub name: String,
    /// `android:authorities` value (optional).
    pub authorities: Option<String>,
    /// Effective `android:exported` (declared value, or the target-SDK
    /// dependent default computed in [`parse_manifest`]).
    pub exported: bool,
    /// The explicitly declared `android:exported`.
    pub exported_explicit: Option<bool>,
    /// `android:permission`.
    pub permission: Option<String>,
    /// `android:readPermission`.
    pub read_permission: Option<String>,
    /// `android:writePermission`.
    pub write_permission: Option<String>,
    /// `android:grantUriPermissions`.
    pub grant_uri_permissions: bool,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// Nested `<meta-data>` entries.
    pub meta_data: Vec<MetaDataEntry>,
}

/// `<application>` attributes with triage value. Boolean fields store the
/// *declared* value (`None` = absent); effective defaults depend on the
/// target SDK and are computed by the `effective_*` helpers on
/// [`ManifestInfo`].
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct ApplicationInfo {
    /// `android:label` (literal string or `@0x…` reference).
    pub label: Option<String>,
    /// `android:allowBackup` (platform default `true`).
    pub allow_backup: Option<bool>,
    /// `android:fullBackupContent` (usually a `@xml/…` reference).
    pub full_backup_content: Option<String>,
    /// `android:dataExtractionRules` (API 31+).
    pub data_extraction_rules: Option<String>,
    /// `android:usesCleartextTraffic` (default: disabled for targetSdk 28+).
    pub uses_cleartext_traffic: Option<bool>,
    /// `android:networkSecurityConfig` (usually a `@xml/…` reference).
    pub network_security_config: Option<String>,
    /// `android:debuggable`.
    pub debuggable: Option<bool>,
    /// `android:testOnly`.
    pub test_only: Option<bool>,
    /// `android:hasCode` (platform default `true`).
    pub has_code: Option<bool>,
    /// `android:extractNativeLibs`.
    pub extract_native_libs: Option<bool>,
    /// `android:requestLegacyExternalStorage`.
    pub request_legacy_external_storage: Option<bool>,
    /// Application-level `<meta-data>` entries.
    pub meta_data: Vec<MetaDataEntry>,
}

/// `<queries>` contents (package-visibility declarations, API 30+).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct QueriesInfo {
    /// `<package android:name="…">` entries.
    pub packages: Vec<String>,
    /// `<intent>` entries (actions/categories/data, reused filter shape).
    pub intents: Vec<IntentFilter>,
    /// `<provider android:authorities="…">` entries (raw attribute value).
    pub providers: Vec<String>,
}

/// One `<uses-feature>` declaration.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct FeatureEntry {
    /// `android:name` (e.g. `android.hardware.camera`); `None` when only
    /// `glEsVersion` is declared.
    pub name: Option<String>,
    /// `android:required` (platform default `true`).
    pub required: Option<bool>,
    /// `android:glEsVersion` (e.g. `0x00030001`), rendered as declared.
    pub gl_es_version: Option<String>,
}

/// Top-level structured view of an Android manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct ManifestInfo {
    /// `package` attribute of the `<manifest>` element.
    pub package: Option<String>,
    /// `versionCode` (decimal `INT_DEC`).
    pub version_code: Option<u32>,
    /// `versionName` (string-pool index → decoded UTF-16/UTF-8).
    pub version_name: Option<String>,
    /// `<uses-sdk minSdkVersion>`.
    pub min_sdk: Option<u32>,
    /// `<uses-sdk targetSdkVersion>`.
    pub target_sdk: Option<u32>,
    /// `<manifest compileSdkVersion>`.
    pub compile_sdk: Option<u32>,
    /// `<manifest compileSdkVersionCodename>`.
    pub compile_sdk_codename: Option<String>,
    /// `<manifest platformBuildVersionCode>`.
    pub platform_build_version_code: Option<u32>,
    /// `<manifest platformBuildVersionName>`.
    pub platform_build_version_name: Option<String>,
    /// Split-APK marker: the plain `split` attribute (e.g.
    /// `config.arm64_v8a`); `None` for a base / standalone APK.
    pub split: Option<String>,
    /// `android:splitTypes` (e.g. `base__abi`).
    pub split_types: Option<String>,
    /// `android:requiredSplitTypes`.
    pub required_split_types: Option<String>,
    /// `android:isSplitRequired` (deprecated in favor of
    /// `requiredSplitTypes`).
    pub is_split_required: Option<bool>,
    /// `android:isFeatureSplit`.
    pub is_feature_split: Option<bool>,
    /// Plain `configForSplit` attribute set by bundletool on config splits.
    pub config_for_split: Option<String>,
    /// `<application android:label>` (resolved only when the value is a
    /// literal string; resource references are stored as `@0x…`).
    pub application_label: Option<String>,
    /// `<application>` attributes (duplicated label for backward
    /// compatibility).
    pub application: ApplicationInfo,
    /// `<permission>` + `<uses-permission>` entries (in source order).
    pub permissions: Vec<PermissionEntry>,
    /// `<uses-feature>` entries.
    pub uses_features: Vec<FeatureEntry>,
    /// `<queries>` element contents; `None` when the element is absent.
    pub queries: Option<QueriesInfo>,
    /// `<activity>` entries.
    pub activities: Vec<ComponentEntry>,
    /// `<service>` entries.
    pub services: Vec<ComponentEntry>,
    /// `<receiver>` entries.
    pub receivers: Vec<ComponentEntry>,
    /// `<provider>` entries.
    pub providers: Vec<ProviderEntry>,
    /// `<activity-alias>` entries.
    pub activity_aliases: Vec<ActivityAliasEntry>,
}

impl ManifestInfo {
    /// Effective `allowBackup`: declared value, else the platform default
    /// (`true`). A `false` here is a declaration, not an inference.
    pub fn effective_allow_backup(&self) -> bool {
        self.application.allow_backup.unwrap_or(true)
    }

    /// Android's *effective* target SDK: `targetSdkVersion` when declared,
    /// else `minSdkVersion`, else 1 (the platform's own fallback — an app
    /// that omits `targetSdkVersion` is treated as targeting `minSdkVersion`).
    /// Every target-SDK-dependent default below keys off this, not off
    /// `target_sdk` alone.
    pub fn effective_target_sdk(&self) -> u32 {
        self.target_sdk.or(self.min_sdk).unwrap_or(1)
    }

    /// Effective `usesCleartextTraffic`: declared value, else the platform
    /// default (allowed only when the effective target SDK is < 28).
    pub fn effective_uses_cleartext_traffic(&self) -> bool {
        self.application
            .uses_cleartext_traffic
            .unwrap_or(self.effective_target_sdk() < 28)
    }

    /// Whether any component is missing the `android:exported` attribute
    /// that its target SDK (31+) requires alongside an intent filter: such
    /// a manifest is rejected by Android 12+ at install time.
    pub fn has_invalid_exported(&self) -> bool {
        components(self).any(|c| c.exported_state == ExportedState::MissingRequired)
    }
}

/// Every filter-bearing component in manifest order.
fn components(info: &ManifestInfo) -> impl Iterator<Item = &ComponentEntry> {
    info.activities
        .iter()
        .chain(&info.services)
        .chain(&info.receivers)
        .chain(info.activity_aliases.iter().map(|a| &a.component))
}

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

/// Parse the raw bytes of an `AndroidManifest.xml` (already inflated out
/// of its containing APK) and extract a structured summary.
pub fn parse_manifest(axml: &[u8]) -> Result<ManifestInfo, ManifestError> {
    let mut parser = Parser::new(axml)?;
    parser.run()?;
    let mut info = parser.info;
    finalize_exported(&mut info);
    finalize_effective_data(&mut info);
    Ok(info)
}

/// Convenience: open `path` as an APK, look up the `AndroidManifest.xml`
/// entry, inflate it, and parse it.
pub fn parse_from_apk(path: impl AsRef<Path>) -> Result<ManifestInfo, ManifestError> {
    let apk = asc_apk::Apk::open(path.as_ref())
        .map_err(|e| ManifestError::Truncated(format!("apk open: {e}")))?;
    if apk.is_raw_dex() {
        return Err(ManifestError::NotFound(
            "input is a raw DEX; 'manifest' requires an APK".into(),
        ));
    }
    let entry = apk
        .entry("AndroidManifest.xml")
        .ok_or_else(|| ManifestError::NotFound("entry not found in the APK".into()))?;
    let bytes = apk
        .read_entry(&entry)
        .map_err(|e| ManifestError::Truncated(format!("read AndroidManifest.xml: {e}")))?;
    parse_manifest(bytes.as_slice())
}

/// Fill in effective `exported` / `exported_state` from the declared
/// tri-state:
///
/// - activity / service / receiver / activity-alias: the declared value,
///   else `true` when the component declares any intent filter
///   (`PackageParser.setDefaultActivityAlias` / `setExported` semantics).
///   When the effective target SDK is >= 31 (Android 12) and the component
///   has intent filters, the absent attribute is *not* a usable default:
///   Android rejects the manifest at install time, so the state records
///   [`ExportedState::MissingRequired`] instead of pretending the legacy
///   inference is installable.
/// - provider: `false` only when the effective target SDK is >= 17;
///   otherwise `true`. Providers have no intent filters, so the API 31
///   requirement never applies and their rule stays separate.
fn finalize_exported(info: &mut ManifestInfo) {
    let effective_target = info.effective_target_sdk();
    let require_explicit = effective_target >= 31; // Build.VERSION_CODES.S
    for c in info
        .activities
        .iter_mut()
        .chain(info.services.iter_mut())
        .chain(info.receivers.iter_mut())
        .chain(info.activity_aliases.iter_mut().map(|a| &mut a.component))
    {
        finalize_component(c, require_explicit);
    }
    for p in &mut info.providers {
        p.exported = p.exported_explicit.unwrap_or(effective_target < 17);
    }
}

/// Effective `exported` + state for one filter-bearing component.
fn finalize_component(c: &mut ComponentEntry, require_explicit: bool) {
    let filtered = !c.intent_filters.is_empty();
    match c.exported_explicit {
        Some(declared) => {
            c.exported = declared;
            c.exported_state = ExportedState::Explicit;
        }
        None if require_explicit && filtered => {
            // The legacy default would be `true`, but the app is not
            // installable on Android 12+. Keep `true` (backwards
            // compatible) and flag the invalid declaration.
            c.exported = true;
            c.exported_state = ExportedState::MissingRequired;
        }
        None => {
            c.exported = filtered;
            c.exported_state = ExportedState::LegacyInferred;
        }
    }
}

/// Recompute the pooled per-filter match set from the raw `<data>`
/// elements, for every filter in the manifest (components and `<queries>`
/// `<intent>` entries alike).
fn finalize_effective_data(info: &mut ManifestInfo) {
    let mut filters = info
        .activities
        .iter_mut()
        .chain(info.services.iter_mut())
        .chain(info.receivers.iter_mut())
        .chain(info.activity_aliases.iter_mut().map(|a| &mut a.component))
        .flat_map(|c| c.intent_filters.iter_mut());
    for f in &mut filters {
        f.effective_data = f.effective_data();
    }
    if let Some(q) = info.queries.as_mut() {
        for f in &mut q.intents {
            f.effective_data = f.effective_data();
        }
    }
}

// ---------------------------------------------------------------------------
// Implementation.
// ---------------------------------------------------------------------------

/// Which component kind a frame belongs to (for routing nested elements
/// like `<intent-filter>` and `<action>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComponentKind {
    Activity,
    Service,
    Receiver,
    ActivityAlias,
    /// Not a [`ComponentEntry`]: providers carry their own meta-data
    /// and never take intent filters, so `component_mut` maps this to
    /// `None` and the meta-data arm routes into `ProviderEntry`.
    Provider,
}

/// A stack frame carries the element's local name plus enough state to
/// route nested `<intent-filter>` / `<action>` / `<category>` / `<data>`
/// events.
#[derive(Debug, Clone)]
struct Frame {
    name: String,
    /// If this frame is an `<activity>` / `<service>` / `<receiver>` /
    /// `<activity-alias>` / `<provider>`, the index of the corresponding
    /// entry in the output vector.
    component: Option<(ComponentKind, usize)>,
    /// If this frame is an `<intent-filter>`, the slot inside its owning
    /// component's `intent_filters` vector.
    filter_slot: Option<usize>,
    /// If this frame is a `<uri-relative-filter-group>` (API 35), the slot
    /// inside its owning filter's `uri_relative_groups` vector. Its nested
    /// `<data>` children route there instead of into `IntentFilter::data`.
    group_slot: Option<usize>,
    /// If this frame is an `<intent>` inside `<queries>`, the slot inside
    /// `queries.intents`.
    queries_intent: Option<usize>,
}

/// A parsed attribute with its resolved namespace URI (`None` = no
/// namespace). Values are pre-rendered strings.
#[derive(Debug, Clone)]
struct XmlAttr {
    ns: Option<String>,
    name: String,
    value: Option<String>,
}

/// Single-pass event walker over the binary XML stream.
struct Parser<'a> {
    bytes: &'a [u8],
    /// Offset of the byte immediately after the root chunk header (i.e.
    /// the first byte of the first child chunk).
    cursor: usize,
    /// Limit: end of the root chunk body (`root_off + root_size`).
    root_end: usize,
    /// String pool, populated after the first chunk is processed.
    strings: Vec<String>,
    /// Stack of currently-open elements (root first).
    stack: Vec<Frame>,
    /// Output accumulator.
    info: ManifestInfo,
}

impl<'a> Parser<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, ManifestError> {
        if bytes.len() < 8 {
            return Err(ManifestError::NotAXml);
        }
        // Root header: type=0x0003, headerSize=8, size=…
        // Android's `ResXMLTree::setTo` never checks the root `type`, and
        // malware zeroes it (`0x00080000`) to break analysers. Mirror the
        // framework: ignore `type`, trust only `headerSize` and `size`.
        let header_size = usize::from(read_u16(bytes, 2)?);
        if header_size != 8 {
            return Err(ManifestError::NotAXml);
        }
        let root_size = read_u32(bytes, 4)? as usize;
        if root_size < 8 {
            return Err(ManifestError::BadChunk(
                "root XML chunk size < header".into(),
            ));
        }
        if root_size > MAX_CHUNK_BODY as usize {
            return Err(ManifestError::BadChunk(format!(
                "root XML chunk size {root_size} exceeds cap {MAX_CHUNK_BODY}"
            )));
        }
        let root_end = match 0usize.checked_add(root_size) {
            Some(v) if v <= bytes.len() => v,
            _ => {
                return Err(ManifestError::Truncated(format!(
                    "root chunk size {root_size} overruns file length {}",
                    bytes.len()
                )));
            }
        };
        Ok(Self {
            bytes,
            cursor: 8,
            root_end,
            strings: Vec::new(),
            stack: Vec::new(),
            info: ManifestInfo::default(),
        })
    }

    fn run(&mut self) -> Result<(), ManifestError> {
        // First inner chunk must be the string pool.
        if self.cursor + 8 > self.root_end {
            return Err(ManifestError::Truncated("missing string pool chunk".into()));
        }
        let (chunk_type, _header_size, chunk_size, _body_off) = self.read_chunk_header()?;
        if chunk_type != RES_STRING_POOL_TYPE {
            return Err(ManifestError::BadChunk(format!(
                "first inner chunk type 0x{chunk_type:04x}, expected string pool 0x0001"
            )));
        }
        self.parse_string_pool()?;
        self.cursor += chunk_size;

        // Subsequent chunks: resource map (optional), then events.
        while self.cursor + 8 <= self.root_end {
            let (chunk_type, _header_size, chunk_size, _body_off) = self.read_chunk_header()?;
            let chunk_start = self.cursor;
            let chunk_end = self
                .cursor
                .checked_add(chunk_size)
                .ok_or_else(|| ManifestError::Truncated("chunk size overflow".into()))?;
            if chunk_end > self.root_end {
                return Err(ManifestError::Truncated(format!(
                    "chunk at {chunk_start} (type 0x{chunk_type:04x}) overruns root end ({chunk_end} > {})",
                    self.root_end
                )));
            }
            match chunk_type {
                RES_XML_RESOURCE_MAP_TYPE => {
                    // Just skip — we don't need resource-id → string
                    // index mapping for display.
                }
                RES_XML_START_NAMESPACE_TYPE => {
                    self.handle_start_namespace(chunk_start, chunk_end)?;
                }
                RES_XML_END_NAMESPACE_TYPE => {
                    self.handle_end_namespace(chunk_start, chunk_end)?;
                }
                RES_XML_START_ELEMENT_TYPE => {
                    self.handle_start_element(chunk_start, chunk_end)?;
                }
                RES_XML_END_ELEMENT_TYPE => {
                    self.handle_end_element(chunk_start)?;
                    // `</manifest>` closed: Android's PackageParser stops
                    // here and never validates what follows, so malware
                    // parks garbage chunks past it. Stop too.
                    if self.stack.is_empty() {
                        return Ok(());
                    }
                }
                // Text nodes carry no manifest data; aapt only emits them
                // for whitespace between elements. Extent is validated by
                // the chunk_end check above, so just consume.
                RES_XML_CDATA_TYPE => {}
                _ => {
                    return Err(ManifestError::Unsupported(format!(
                        "chunk type 0x{chunk_type:04x} not handled"
                    )));
                }
            }
            self.cursor = chunk_end;
        }

        if self.cursor != self.root_end {
            return Err(ManifestError::BadChunk(format!(
                "trailing {} bytes at end of root chunk",
                self.root_end.saturating_sub(self.cursor)
            )));
        }
        Ok(())
    }

    /// Reads the next chunk header at `self.cursor` and returns
    /// `(type, headerSize, size, body_offset)` where `body_offset` is the
    /// absolute offset of the first byte after the 8-byte `ResChunk_header`.
    fn read_chunk_header(&self) -> Result<(u16, u16, usize, usize), ManifestError> {
        if self.cursor + 8 > self.bytes.len() {
            return Err(ManifestError::Truncated(format!(
                "chunk header at {} extends past EOF ({})",
                self.cursor,
                self.bytes.len()
            )));
        }
        let chunk_type = read_u16(self.bytes, self.cursor)?;
        let header_size = read_u16(self.bytes, self.cursor + 2)?;
        let chunk_size = read_u32(self.bytes, self.cursor + 4)? as usize;
        if header_size < 8 {
            return Err(ManifestError::BadChunk(format!(
                "chunk at {} has headerSize {header_size} < 8",
                self.cursor
            )));
        }
        if chunk_size < header_size as usize {
            return Err(ManifestError::BadChunk(format!(
                "chunk at {} has size {chunk_size} < headerSize {header_size}",
                self.cursor
            )));
        }
        let body_off = self.cursor + 8;
        Ok((chunk_type, header_size, chunk_size, body_off))
    }

    /// Parse the leading string-pool chunk (already established as
    /// `RES_STRING_POOL_TYPE` by `run`). The string pool's type-specific
    /// fields live at `STRING_POOL_BODY_OFF` (8 bytes past the chunk
    /// start); the strings themselves live at
    /// `chunk_start + stringsStart`.
    fn parse_string_pool(&mut self) -> Result<(), ManifestError> {
        let chunk_start = self.cursor;
        let chunk_size = read_u32(self.bytes, chunk_start + 4)? as usize;
        let chunk_end = chunk_start
            .checked_add(chunk_size)
            .ok_or_else(|| ManifestError::Truncated("string pool size overflow".into()))?;
        // The string decoding below is bounded by `chunk_end`, so the
        // chunk must lie inside both the root chunk and the file.
        if chunk_end > self.root_end || chunk_end > self.bytes.len() {
            return Err(ManifestError::Truncated(format!(
                "string pool at {chunk_start} overruns root end ({chunk_end} > {}, file {})",
                self.root_end,
                self.bytes.len()
            )));
        }
        let pool = asc_apk::string_pool::parse(
            self.bytes,
            chunk_start,
            chunk_end,
            asc_apk::string_pool::Limits {
                max_count: MAX_STRING_COUNT,
                max_bytes: MAX_STRING_BYTES,
            },
        )
        .map_err(|e| match e {
            asc_apk::string_pool::PoolError::Truncated(s) => ManifestError::Truncated(s),
            asc_apk::string_pool::PoolError::Bad(s) => ManifestError::BadChunk(s),
        })?;
        self.strings = pool.strings;
        Ok(())
    }

    fn handle_start_namespace(
        &self,
        chunk_start: usize,
        chunk_end: usize,
    ) -> Result<(), ManifestError> {
        // ResXMLTree_namespace: chunk_start + 16 (after ResChunk_header
        // and ResXMLTree_node) holds:
        //   u32 prefix
        //   u32 uri
        let body_off = chunk_start + XML_TREE_BODY_OFF;
        if body_off + 8 > chunk_end {
            return Err(ManifestError::Truncated("start-namespace body".into()));
        }
        let prefix = read_u32(self.bytes, body_off)?;
        let uri = read_u32(self.bytes, body_off + 4)?;
        self.validate_string_index(prefix, "start-ns prefix", true)?;
        self.validate_string_index(uri, "start-ns uri", true)?;
        // Namespace events are validated but not tracked: attribute
        // namespace URIs arrive inline in each attribute record, which
        // is all the display layer needs.
        Ok(())
    }

    fn handle_end_namespace(
        &self,
        _chunk_start: usize,
        _chunk_end: usize,
    ) -> Result<(), ManifestError> {
        // Namespace events balance out inside a START_ELEMENT/END_ELEMENT
        // pair; we don't track them, so just consume the bytes by
        // advancing the cursor (the caller already did that).
        Ok(())
    }

    fn handle_start_element(
        &mut self,
        chunk_start: usize,
        chunk_end: usize,
    ) -> Result<(), ManifestError> {
        // ResXMLTree_startElement: chunk_start + 16 (after ResChunk_header
        // and ResXMLTree_node) holds:
        //   u32 ns
        //   u32 name
        //   u16 attributeStart   (offset from chunk_start, in bytes)
        //   u16 attributeSize    (bytes per attribute)
        //   u16 attributeCount
        //   u16 idIndex, classIndex, styleIndex
        let body_off = chunk_start + XML_TREE_BODY_OFF;
        if body_off + 20 > chunk_end {
            return Err(ManifestError::Truncated("start-element body".into()));
        }
        if self.stack.len() >= MAX_CHILDREN {
            return Err(ManifestError::BadChunk(format!(
                "element nesting exceeds cap {MAX_CHILDREN}"
            )));
        }
        let _ns = read_u32(self.bytes, body_off)?;
        let name_idx = read_u32(self.bytes, body_off + 4)?;
        let attr_start = read_u16(self.bytes, body_off + 8)? as usize;
        let attr_size = read_u16(self.bytes, body_off + 10)? as usize;
        let attr_count = read_u16(self.bytes, body_off + 12)? as usize;
        let _id_idx = read_u16(self.bytes, body_off + 14)?;
        let _class_idx = read_u16(self.bytes, body_off + 16)?;
        let _style_idx = read_u16(self.bytes, body_off + 18)?;
        // An attribute is 20 bytes (`ns`, `name`, `rawValue`,
        // `Res_value`{size,res0,dataType,data}); anything smaller can
        // never hold one, and the fixed-offset reads below would index
        // into the next attribute.
        const ATTRIBUTE_MIN_SIZE: usize = 20;
        if attr_size < ATTRIBUTE_MIN_SIZE {
            return Err(ManifestError::BadChunk(format!(
                "start-element attributeSize {attr_size} < {ATTRIBUTE_MIN_SIZE}"
            )));
        }
        self.validate_string_index(name_idx, "start-element name", false)?;
        let name = self.strings[name_idx as usize].clone();
        // First attribute begins at offset `attr_start` past the
        // **attrExt start** (chunk_start + 16), which is `body_off`.
        // AOSP's comment "Offset from start of node" is misleading:
        // the offset is relative to the attrExt, not the chunk.
        let attr_table_off = body_off + attr_start;
        let attrs_needed = attr_count
            .checked_mul(attr_size)
            .ok_or_else(|| ManifestError::BadChunk("attribute table overflow".into()))?;
        let attr_table_end = attr_table_off
            .checked_add(attrs_needed)
            .ok_or_else(|| ManifestError::BadChunk("attribute table overflow".into()))?;
        if attr_table_end > chunk_end {
            return Err(ManifestError::Truncated("attribute table".into()));
        }

        // Owned attribute records so we can release the immutable borrow
        // of `self.strings` before the mutable `process_element_open`
        // call below.
        let mut attrs: Vec<XmlAttr> = Vec::with_capacity(attr_count);
        for i in 0..attr_count {
            let attr_off = attr_table_off + i * attr_size;
            let a_ns = read_u32(self.bytes, attr_off)?;
            let a_name = read_u32(self.bytes, attr_off + 4)?;
            let a_raw = read_u32(self.bytes, attr_off + 8)?;
            let _tv_size = read_u16(self.bytes, attr_off + 12)?;
            let _tv_res0 = self.bytes[attr_off + 14];
            let tv_type = self.bytes[attr_off + 15];
            let tv_data = read_u32(self.bytes, attr_off + 16)?;
            self.validate_string_index(a_name, "attribute name", false)?;
            let ns = if a_ns == NO_INDEX {
                None
            } else {
                self.validate_string_index(a_ns, "attribute ns", false)?;
                Some(self.strings[a_ns as usize].clone())
            };
            let a_name_str = self.strings[a_name as usize].clone();
            let value = self.render_typed_value(tv_type, tv_data, a_raw)?;
            attrs.push(XmlAttr {
                ns,
                name: a_name_str,
                value,
            });
        }

        let frame = self.process_element_open(&name, &attrs)?;
        self.stack.push(frame);
        Ok(())
    }

    fn handle_end_element(&mut self, chunk_start: usize) -> Result<(), ManifestError> {
        // ResXMLTree_endElement: chunk_start + 16 holds u32 ns + u32 name.
        let body_off = chunk_start + XML_TREE_BODY_OFF;
        if body_off + 8 > self.bytes.len() {
            return Err(ManifestError::Truncated("end-element body".into()));
        }
        let name_idx = read_u32(self.bytes, body_off + 4)?;
        self.validate_string_index(name_idx, "end-element name", false)?;
        let name = self.strings[name_idx as usize].clone();
        match self.stack.last() {
            Some(frame) if frame.name == name => {}
            Some(other) => {
                return Err(ManifestError::BadChunk(format!(
                    "end-element <{name}> does not match top of stack <{}>",
                    other.name
                )));
            }
            None => {
                return Err(ManifestError::BadChunk(
                    "end-element with empty stack".into(),
                ));
            }
        }
        self.stack.pop();
        Ok(())
    }

    /// Convert a `(dataType, data, rawValueIndex)` triple into a Rust
    /// `String` suitable for display. Reference / attribute values
    /// become `@0xDEADBEEF`; decimal ints become the digit string;
    /// string references resolve via the string pool; everything else
    /// becomes the raw hex form.
    fn render_typed_value(
        &self,
        data_type: u8,
        data: u32,
        raw_index: u32,
    ) -> Result<Option<String>, ManifestError> {
        render_typed_value_str(&self.strings, data_type, data, raw_index)
    }

    /// Validate a string-pool index. `allow_no_index` is false for
    /// fields that are always dereferenced (element / attribute names);
    /// true for optional ones (namespace URIs, string-typed values,
    /// where AOSP uses `NO_INDEX` to mean "absent").
    fn validate_string_index(
        &self,
        idx: u32,
        ctx: &str,
        allow_no_index: bool,
    ) -> Result<(), ManifestError> {
        validate_string_index_str(&self.strings, idx, ctx, allow_no_index)
    }

    /// Resolve `&mut ComponentEntry` for a routing slot (also covers
    /// activity-alias via its flattened `component` field).
    fn component_mut(&mut self, kind: ComponentKind, idx: usize) -> Option<&mut ComponentEntry> {
        match kind {
            ComponentKind::Activity => self.info.activities.get_mut(idx),
            ComponentKind::Service => self.info.services.get_mut(idx),
            ComponentKind::Receiver => self.info.receivers.get_mut(idx),
            ComponentKind::ActivityAlias => self
                .info
                .activity_aliases
                .get_mut(idx)
                .map(|a| &mut a.component),
            // Providers are not ComponentEntry; their meta-data is
            // routed directly by the caller. They never take intent
            // filters, so this arm only ever maps to `None`.
            ComponentKind::Provider => None,
        }
    }

    fn process_element_open(
        &mut self,
        name: &str,
        attrs: &[XmlAttr],
    ) -> Result<Frame, ManifestError> {
        let parent = self.stack.last().map(|f| {
            (
                f.name.as_str(),
                f.component,
                f.filter_slot,
                f.group_slot,
                f.queries_intent,
            )
        });
        let mut component: Option<(ComponentKind, usize)> = None;
        let mut filter_slot: Option<usize> = None;
        let mut group_slot: Option<usize> = None;
        let mut queries_intent: Option<usize> = None;
        match parent {
            None => self.process_root_element(name, attrs)?,
            Some(("manifest", ..)) => self.process_manifest_child(name, attrs)?,
            Some(("application", ..)) => {
                component = self.process_application_child(name, attrs)?;
            }
            Some(("queries", ..)) => {
                queries_intent = self.process_queries_child(name, attrs);
            }
            Some(("intent-filter", Some((kind, comp_idx)), Some(filter_idx), _, _)) => {
                // <action> / <category> / <data> /
                // <uri-relative-filter-group> inside a filter. This arm must
                // precede the generic component arm: a filter frame also
                // carries its owning component.
                if let Some(comp) = self.component_mut(kind, comp_idx)
                    && let Some(f) = comp.intent_filters.get_mut(filter_idx)
                {
                    match name {
                        "action" => {
                            if let Some(n) = attr(attrs, "name") {
                                f.actions.push(n.to_string());
                            }
                        }
                        "category" => {
                            if let Some(n) = attr(attrs, "name") {
                                f.categories.push(n.to_string());
                            }
                        }
                        "data" => {
                            f.data.push(data_spec_from_attrs(attrs));
                        }
                        "uri-relative-filter-group" => {
                            f.uri_relative_groups
                                .push(uri_relative_group_from_attrs(attrs));
                            group_slot = Some(f.uri_relative_groups.len() - 1);
                            // Carry the route so the group's <data> children
                            // land in the group, not in the filter's own data.
                            component = Some((kind, comp_idx));
                            filter_slot = Some(filter_idx);
                        }
                        _ => {}
                    }
                }
            }
            Some((
                "uri-relative-filter-group",
                Some((kind, comp_idx)),
                Some(filter_idx),
                Some(group_idx),
                _,
            )) => {
                // <data> inside an API 35 <uri-relative-filter-group>: only
                // path*/fragment*/query* attributes are legal there.
                if name == "data"
                    && let Some(comp) = self.component_mut(kind, comp_idx)
                    && let Some(f) = comp.intent_filters.get_mut(filter_idx)
                    && let Some(group) = f.uri_relative_groups.get_mut(group_idx)
                {
                    group.data.push(relative_data_from_attrs(attrs));
                }
            }
            Some((_, Some((kind, comp_idx)), ..)) => {
                // Direct child of a component: intent-filter (creates a
                // slot) or meta-data; anything else is ignored.
                match name {
                    "intent-filter" => {
                        let filter = IntentFilter {
                            auto_verify: tri_bool_attr(attrs, "autoVerify"),
                            priority: int32_attr(attrs, "priority"),
                            ..IntentFilter::default()
                        };
                        if let Some(comp) = self.component_mut(kind, comp_idx) {
                            comp.intent_filters.push(filter);
                            filter_slot = Some(comp.intent_filters.len() - 1);
                        }
                        // Inherit the parent component so nested <action> /
                        // <category> / <data> events route into the slot.
                        component = Some((kind, comp_idx));
                    }
                    "meta-data" => {
                        let md = meta_data_from_attrs(attrs);
                        let target = match kind {
                            ComponentKind::Provider => self
                                .info
                                .providers
                                .get_mut(comp_idx)
                                .map(|p| &mut p.meta_data),
                            _ => self.component_mut(kind, comp_idx).map(|c| &mut c.meta_data),
                        };
                        if let Some(mds) = target {
                            mds.push(md);
                        }
                    }
                    _ => {}
                }
            }
            Some(("intent", _, _, _, Some(qi))) => {
                // <action>/<category>/<data> inside a queries <intent>.
                if let Some(q) = self.info.queries.as_mut()
                    && let Some(f) = q.intents.get_mut(qi)
                {
                    match name {
                        "action" => {
                            if let Some(n) = attr(attrs, "name") {
                                f.actions.push(n.to_string());
                            }
                        }
                        "category" => {
                            if let Some(n) = attr(attrs, "name") {
                                f.categories.push(n.to_string());
                            }
                        }
                        "data" => {
                            f.data.push(data_spec_from_attrs(attrs));
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        Ok(Frame {
            name: name.to_string(),
            component,
            filter_slot,
            group_slot,
            queries_intent,
        })
    }

    /// Process a top-level element (no parent on the stack).
    fn process_root_element(&mut self, name: &str, attrs: &[XmlAttr]) -> Result<(), ManifestError> {
        match name {
            "manifest" => {
                if let Some(p) = attr(attrs, "package") {
                    self.info.package = Some(p.to_string());
                }
                if let Some(v) = int_attr(attrs, "versionCode") {
                    self.info.version_code = Some(v);
                }
                if let Some(v) = attr(attrs, "versionName") {
                    self.info.version_name = Some(v.to_string());
                }
                if let Some(v) = int_attr(attrs, "compileSdkVersion") {
                    self.info.compile_sdk = Some(v);
                }
                if let Some(v) = attr(attrs, "compileSdkVersionCodename") {
                    self.info.compile_sdk_codename = Some(v.to_string());
                }
                if let Some(v) = int_attr(attrs, "platformBuildVersionCode") {
                    self.info.platform_build_version_code = Some(v);
                }
                if let Some(v) = attr(attrs, "platformBuildVersionName") {
                    self.info.platform_build_version_name = Some(v.to_string());
                }
                read_split_attrs(&mut self.info, attrs);
            }
            "uses-sdk" => {
                if let Some(v) = int_attr(attrs, "minSdkVersion") {
                    self.info.min_sdk = Some(v);
                }
                if let Some(v) = int_attr(attrs, "targetSdkVersion") {
                    self.info.target_sdk = Some(v);
                }
            }
            "uses-permission" => push_permission(&mut self.info, "uses", attrs),
            "uses-permission-sdk-23" | "uses-permission-sdk-m" => {
                push_permission(&mut self.info, "uses-sdk-23", attrs);
            }
            "permission" => push_permission(&mut self.info, "declares", attrs),
            "application" => {
                read_application_attrs(&mut self.info, attrs);
            }
            _ => {}
        }
        Ok(())
    }

    /// Process a child of `<manifest>`: SDK declarations, permissions,
    /// features, `<queries>`, and `<application>` itself (the only path a
    /// well-formed manifest takes — see `process_root_element` for the
    /// degenerate root-level variants, kept for malformed-input
    /// tolerance).
    fn process_manifest_child(
        &mut self,
        name: &str,
        attrs: &[XmlAttr],
    ) -> Result<(), ManifestError> {
        match name {
            "uses-sdk" => {
                if let Some(v) = int_attr(attrs, "minSdkVersion") {
                    self.info.min_sdk = Some(v);
                }
                if let Some(v) = int_attr(attrs, "targetSdkVersion") {
                    self.info.target_sdk = Some(v);
                }
            }
            "uses-permission" => push_permission(&mut self.info, "uses", attrs),
            "uses-permission-sdk-23" | "uses-permission-sdk-m" => {
                push_permission(&mut self.info, "uses-sdk-23", attrs);
            }
            "permission" => push_permission(&mut self.info, "declares", attrs),
            "uses-feature" => {
                self.info.uses_features.push(FeatureEntry {
                    name: attr(attrs, "name").map(str::to_string),
                    required: tri_bool_attr(attrs, "required"),
                    gl_es_version: attr(attrs, "glEsVersion").map(str::to_string),
                });
            }
            "queries" => {
                self.info.queries = Some(QueriesInfo::default());
            }
            "application" => {
                read_application_attrs(&mut self.info, attrs);
            }
            _ => {}
        }
        Ok(())
    }

    /// Process a child of `<application>`. Returns the new component
    /// frame context (if any) so the caller can push it onto the stack.
    fn process_application_child(
        &mut self,
        name: &str,
        attrs: &[XmlAttr],
    ) -> Result<Option<(ComponentKind, usize)>, ManifestError> {
        let ctx = match name {
            "activity" => {
                if let Some(p) = attr(attrs, "name") {
                    let entry = component_from_attrs(p, attrs);
                    self.info.activities.push(entry);
                    Some((ComponentKind::Activity, self.info.activities.len() - 1))
                } else {
                    None
                }
            }
            "service" => {
                if let Some(p) = attr(attrs, "name") {
                    let entry = component_from_attrs(p, attrs);
                    self.info.services.push(entry);
                    Some((ComponentKind::Service, self.info.services.len() - 1))
                } else {
                    None
                }
            }
            "receiver" => {
                if let Some(p) = attr(attrs, "name") {
                    let entry = component_from_attrs(p, attrs);
                    self.info.receivers.push(entry);
                    Some((ComponentKind::Receiver, self.info.receivers.len() - 1))
                } else {
                    None
                }
            }
            "activity-alias" => {
                if let Some(p) = attr(attrs, "name") {
                    let entry = ActivityAliasEntry {
                        target_activity: attr(attrs, "targetActivity").map(str::to_string),
                        component: component_from_attrs(p, attrs),
                    };
                    self.info.activity_aliases.push(entry);
                    Some((
                        ComponentKind::ActivityAlias,
                        self.info.activity_aliases.len() - 1,
                    ))
                } else {
                    None
                }
            }
            "provider" => {
                if let Some(p) = attr(attrs, "name") {
                    self.info.providers.push(ProviderEntry {
                        name: p.to_string(),
                        authorities: attr(attrs, "authorities").map(str::to_string),
                        exported: false, // finalize_exported computes the default
                        exported_explicit: tri_bool_attr(attrs, "exported"),
                        permission: attr(attrs, "permission").map(str::to_string),
                        read_permission: attr(attrs, "readPermission").map(str::to_string),
                        write_permission: attr(attrs, "writePermission").map(str::to_string),
                        grant_uri_permissions: bool_attr(attrs, "grantUriPermissions"),
                        label: attr(attrs, "label").map(str::to_string),
                        meta_data: Vec::new(),
                    });
                    Some((ComponentKind::Provider, self.info.providers.len() - 1))
                } else {
                    None
                }
            }
            "meta-data" => {
                let md = meta_data_from_attrs(attrs);
                self.info.application.meta_data.push(md);
                None
            }
            _ => None,
        };
        Ok(ctx)
    }

    /// Process a child of `<queries>`: package / intent / provider.
    /// Returns the `queries.intents` slot when the element is `<intent>`
    /// (so nested action/category/data events can route into it).
    fn process_queries_child(&mut self, name: &str, attrs: &[XmlAttr]) -> Option<usize> {
        let q = self.info.queries.as_mut()?;
        match name {
            "package" => {
                if let Some(n) = attr(attrs, "name") {
                    q.packages.push(n.to_string());
                }
                None
            }
            "intent" => {
                q.intents.push(IntentFilter::default());
                Some(q.intents.len() - 1)
            }
            "provider" => {
                if let Some(a) = attr(attrs, "authorities") {
                    q.providers.push(a.to_string());
                }
                None
            }
            _ => None,
        }
    }
}

/// Read the split-APK markers off `<manifest>`.
fn read_split_attrs(info: &mut ManifestInfo, attrs: &[XmlAttr]) {
    info.split = attr(attrs, "split").map(str::to_string);
    info.split_types = attr(attrs, "splitTypes").map(str::to_string);
    info.required_split_types = attr(attrs, "requiredSplitTypes").map(str::to_string);
    info.is_split_required = tri_bool_attr(attrs, "isSplitRequired");
    info.is_feature_split = tri_bool_attr(attrs, "isFeatureSplit");
    info.config_for_split = attr(attrs, "configForSplit").map(str::to_string);
}

/// Read `<application>` attributes into `info` (both the structured
/// `ApplicationInfo` and the legacy `application_label` mirror).
fn read_application_attrs(info: &mut ManifestInfo, attrs: &[XmlAttr]) {
    let app = &mut info.application;
    app.label = attr(attrs, "label").map(str::to_string);
    info.application_label = app.label.clone();
    app.allow_backup = tri_bool_attr(attrs, "allowBackup");
    app.full_backup_content = attr(attrs, "fullBackupContent").map(str::to_string);
    app.data_extraction_rules = attr(attrs, "dataExtractionRules").map(str::to_string);
    app.uses_cleartext_traffic = tri_bool_attr(attrs, "usesCleartextTraffic");
    app.network_security_config = attr(attrs, "networkSecurityConfig").map(str::to_string);
    app.debuggable = tri_bool_attr(attrs, "debuggable");
    app.test_only = tri_bool_attr(attrs, "testOnly");
    app.has_code = tri_bool_attr(attrs, "hasCode");
    app.extract_native_libs = tri_bool_attr(attrs, "extractNativeLibs");
    app.request_legacy_external_storage = tri_bool_attr(attrs, "requestLegacyExternalStorage");
}

/// Build a `<meta-data>` record.
fn meta_data_from_attrs(attrs: &[XmlAttr]) -> MetaDataEntry {
    MetaDataEntry {
        name: attr(attrs, "name").unwrap_or_default().to_string(),
        value: attr(attrs, "value").map(str::to_string),
        resource: attr(attrs, "resource").map(str::to_string),
    }
}

/// Build a `<data>` spec from a `<data>` element's attributes.
fn data_spec_from_attrs(attrs: &[XmlAttr]) -> DataSpec {
    DataSpec {
        scheme: attr(attrs, "scheme").map(str::to_string),
        host: attr(attrs, "host").map(str::to_string),
        port: attr(attrs, "port").map(str::to_string),
        path: attr(attrs, "path").map(str::to_string),
        path_prefix: attr(attrs, "pathPrefix").map(str::to_string),
        path_pattern: attr(attrs, "pathPattern").map(str::to_string),
        path_advanced_pattern: attr(attrs, "pathAdvancedPattern").map(str::to_string),
        path_suffix: attr(attrs, "pathSuffix").map(str::to_string),
        mime_type: attr(attrs, "mimeType").map(str::to_string),
    }
}

/// The `path*` / `fragment*` / `query*` attributes legal on a `<data>`
/// child of a `<uri-relative-filter-group>`, with the URI part each one
/// constrains (API 35).
const URI_RELATIVE_ATTRS: &[(&str, UriPart, PathMatchKind)] = &[
    ("path", UriPart::Path, PathMatchKind::Exact),
    ("pathPrefix", UriPart::Path, PathMatchKind::Prefix),
    ("pathSuffix", UriPart::Path, PathMatchKind::Suffix),
    ("pathPattern", UriPart::Path, PathMatchKind::Pattern),
    (
        "pathAdvancedPattern",
        UriPart::Path,
        PathMatchKind::AdvancedPattern,
    ),
    ("fragment", UriPart::Fragment, PathMatchKind::Exact),
    ("fragmentPrefix", UriPart::Fragment, PathMatchKind::Prefix),
    ("fragmentSuffix", UriPart::Fragment, PathMatchKind::Suffix),
    ("fragmentPattern", UriPart::Fragment, PathMatchKind::Pattern),
    (
        "fragmentAdvancedPattern",
        UriPart::Fragment,
        PathMatchKind::AdvancedPattern,
    ),
    ("query", UriPart::Query, PathMatchKind::Exact),
    ("queryPrefix", UriPart::Query, PathMatchKind::Prefix),
    ("querySuffix", UriPart::Query, PathMatchKind::Suffix),
    ("queryPattern", UriPart::Query, PathMatchKind::Pattern),
    (
        "queryAdvancedPattern",
        UriPart::Query,
        PathMatchKind::AdvancedPattern,
    ),
];

/// Build a `<uri-relative-filter-group>` from its attributes
/// (`android:allow`, default `true`).
fn uri_relative_group_from_attrs(attrs: &[XmlAttr]) -> UriRelativeFilterGroup {
    UriRelativeFilterGroup {
        allow: tri_bool_attr(attrs, "allow").unwrap_or(true),
        data: Vec::new(),
    }
}

/// Build one `<data>` child of a `<uri-relative-filter-group>`; only the
/// [`URI_RELATIVE_ATTRS`] attributes are legal there, in declaration order.
fn relative_data_from_attrs(attrs: &[XmlAttr]) -> RelativeDataSpec {
    let parts = attrs
        .iter()
        .filter_map(|a| {
            // Only the Android (or an unqualified) attribute is a legal
            // matcher here; a foreign namespace (`tools:path`, or a custom
            // namespace whose local name collides with a matcher) must not
            // be read as Android data. Same policy as `attr()` (audit F1).
            if !a.ns.as_deref().is_none_or(|ns| ns == ANDROID_NS) {
                return None;
            }
            let (_, part, kind) = URI_RELATIVE_ATTRS
                .iter()
                .find(|(name, _, _)| *name == a.name)?;
            Some(UriPartMatcher {
                part: *part,
                kind: *kind,
                value: a.value.clone()?,
            })
        })
        .collect();
    RelativeDataSpec { parts }
}

/// Append one permission entry of the given declaration type. Shared by
/// the manifest-child and degenerate root-level arms.
fn push_permission(info: &mut ManifestInfo, decl: &'static str, attrs: &[XmlAttr]) {
    let Some(p) = attr(attrs, "name") else { return };
    info.permissions.push(PermissionEntry {
        name: p.to_string(),
        decl,
        protection_level: (decl == "declares")
            .then(|| attr(attrs, "protectionLevel"))
            .flatten()
            .map(str::to_string),
        label: attr(attrs, "label").map(str::to_string),
        max_sdk: int_attr(attrs, "maxSdkVersion"),
    });
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Look up an attribute by local name, only when it carries no namespace
/// or the Android resource namespace. Foreign namespaces (`tools:`,
/// `dist:`, …) never match, mirroring PackageParser.
fn attr<'a>(attrs: &'a [XmlAttr], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|a| a.name == name && a.ns.as_deref().is_none_or(|u| u == ANDROID_NS))
        .and_then(|a| a.value.as_deref())
}

fn int_attr(attrs: &[XmlAttr], name: &str) -> Option<u32> {
    attr(attrs, name).and_then(|v| v.parse().ok())
}

fn int32_attr(attrs: &[XmlAttr], name: &str) -> Option<i32> {
    attr(attrs, name).and_then(|v| v.parse().ok())
}

/// Boolean attribute with a real tri-state: `None` when absent or not a
/// boolean, so "declared false" stays distinguishable from "undeclared".
fn tri_bool_attr(attrs: &[XmlAttr], name: &str) -> Option<bool> {
    match attr(attrs, name) {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    }
}

/// Boolean attribute with a `false` default (used where the platform
/// default is false and the declared/undeclared split is not
/// security-relevant).
fn bool_attr(attrs: &[XmlAttr], name: &str) -> bool {
    matches!(attr(attrs, name), Some("true"))
}

fn component_from_attrs(name: &str, attrs: &[XmlAttr]) -> ComponentEntry {
    ComponentEntry {
        name: name.to_string(),
        exported: false, // finalize_exported computes the effective value
        exported_explicit: tri_bool_attr(attrs, "exported"),
        exported_state: ExportedState::LegacyInferred, // ditto
        permission: attr(attrs, "permission").map(str::to_string),
        label: attr(attrs, "label").map(str::to_string),
        process: attr(attrs, "process").map(str::to_string),
        intent_filters: Vec::new(),
        meta_data: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Low-level read helpers (mirrors asc-dex::read for unsigned primitives).
// ---------------------------------------------------------------------------

fn read_u16(bytes: &[u8], off: usize) -> Result<u16, ManifestError> {
    if off + 2 > bytes.len() {
        return Err(ManifestError::Truncated(format!(
            "u16 read at {off} extends past EOF ({})",
            bytes.len()
        )));
    }
    Ok(u16::from_le_bytes([bytes[off], bytes[off + 1]]))
}

fn read_u32(bytes: &[u8], off: usize) -> Result<u32, ManifestError> {
    if off + 4 > bytes.len() {
        return Err(ManifestError::Truncated(format!(
            "u32 read at {off} extends past EOF ({})",
            bytes.len()
        )));
    }
    Ok(u32::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
    ]))
}

// ---------------------------------------------------------------------------
// Free helpers shared with the generic AXML decoder (`axml` module).
// ---------------------------------------------------------------------------

/// [`Parser::validate_string_index`] as a free function over a pool.
pub(crate) fn validate_string_index_str(
    strings: &[String],
    idx: u32,
    ctx: &str,
    allow_no_index: bool,
) -> Result<(), ManifestError> {
    if idx == NO_INDEX {
        if allow_no_index {
            return Ok(());
        }
        return Err(ManifestError::BadChunk(format!(
            "{ctx}: NO_INDEX is not a valid string index"
        )));
    }
    if (idx as usize) >= strings.len() {
        return Err(ManifestError::BadChunk(format!(
            "{ctx}: string index {idx} out of range (pool has {})",
            strings.len()
        )));
    }
    Ok(())
}

/// [`Parser::render_typed_value`] as a free function over a pool:
/// references stay `@0x…`, strings resolve, ints/bools render.
pub(crate) fn render_typed_value_str(
    strings: &[String],
    data_type: u8,
    data: u32,
    raw_index: u32,
) -> Result<Option<String>, ManifestError> {
    const TYPE_NULL: u8 = 0x00;
    const TYPE_REFERENCE: u8 = 0x01;
    const TYPE_ATTRIBUTE: u8 = 0x02;
    const TYPE_STRING: u8 = 0x03;
    const TYPE_INT_DEC: u8 = 0x10;
    const TYPE_INT_HEX: u8 = 0x11;
    const TYPE_INT_BOOLEAN: u8 = 0x12;
    let kind = data_type & 0x7F;
    let result = match kind {
        TYPE_NULL => None,
        TYPE_STRING => {
            // AOSP semantics: for string-typed values `data` *is* the
            // string-pool index; `rawValue` is a convenience copy aapt
            // sets when the source was a literal. Resolve via
            // `rawValue` when present, else via `data`.
            let idx = if raw_index != NO_INDEX {
                raw_index
            } else {
                data
            };
            if idx == NO_INDEX {
                None
            } else {
                validate_string_index_str(strings, idx, "string-typed value", true)?;
                Some(strings[idx as usize].clone())
            }
        }
        TYPE_REFERENCE | TYPE_ATTRIBUTE => Some(format!("@0x{data:08x}")),
        // AOSP TypedValue.coerceToString renders INT_DEC signed
        // (Integer.toString): android:priority="-10" arrives as 0xFFFFFFF6
        // and must render "-10", not "4294967286".
        TYPE_INT_DEC => Some((data as i32).to_string()),
        TYPE_INT_HEX => Some(format!("0x{data:08x}")),
        TYPE_INT_BOOLEAN => Some(if data != 0 { "true" } else { "false" }.to_string()),
        _ => Some(format!("0x{data:08x}")),
    };
    Ok(result)
}

// ---------------------------------------------------------------------------
// Generic binary-AXML decoder (any compiled res XML, not just the
// manifest).
// ---------------------------------------------------------------------------

pub mod axml;
// ---------------------------------------------------------------------------
// Display impl for ManifestInfo — a compact one-line summary, mainly for
// the GUI status bar / tests.
// ---------------------------------------------------------------------------

impl fmt::Display for ManifestInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "package={} versionCode={} versionName={}",
            self.package.as_deref().unwrap_or("?"),
            self.version_code
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".into()),
            self.version_name.as_deref().unwrap_or("?"),
        )
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
