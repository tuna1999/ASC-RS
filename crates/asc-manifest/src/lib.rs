//! # asc-manifest
//!
//! Binary AXML (AndroidManifest.xml inside APKs) parsing for display:
//! package/version, permissions, activities/services/receivers, intent
//! filters. Read-only, bounds-checked.
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

const RES_STRING_POOL_UTF8_FLAG: u32 = 1 << 8;

const NO_INDEX: u32 = 0xFFFF_FFFF;

/// Sanity caps. These are large enough to cover every real APK in the
/// wild (Android's own build emits manifests a few hundred KB at most)
/// while keeping a single chunk from claiming terabytes of input.
const MAX_STRING_COUNT: u32 = 1 << 20;
const MAX_STRING_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CHUNK_BODY: u64 = 64 * 1024 * 1024;
const MAX_CHILDREN: usize = 1 << 20;

/// Offset (relative to the chunk's start) of the type-specific fields
/// for each chunk type we recognize.
const STRING_POOL_BODY_OFF: usize = 8;
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionEntry {
    /// The permission name (e.g. `android.permission.INTERNET`).
    pub name: String,
    /// `protectionLevel` attribute (e.g. `"normal"`, `"dangerous"`); `None`
    /// for `<uses-permission>` declarations which never carry one.
    pub protection_level: Option<String>,
    /// Optional human-readable label.
    pub label: Option<String>,
}

/// One intent filter attached to a component.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntentFilter {
    /// Action URIs (e.g. `android.intent.action.MAIN`).
    pub actions: Vec<String>,
    /// Category names (e.g. `android.intent.category.LAUNCHER`).
    pub categories: Vec<String>,
}

/// One activity / service / receiver declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentEntry {
    /// Class name (e.g. `com.aurora.store.MainActivity`).
    pub name: String,
    /// `android:exported` value (default `false` if not present; the
    /// framework infers the default from intent filters, but we just
    /// record what the manifest says).
    pub exported: bool,
    /// `android:permission` attribute (optional).
    pub permission: Option<String>,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// Nested `<intent-filter>` blocks (in source order).
    pub intent_filters: Vec<IntentFilter>,
}

/// One `<provider>` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEntry {
    /// Class name.
    pub name: String,
    /// `android:authorities` value (optional).
    pub authorities: Option<String>,
    /// `android:exported`.
    pub exported: bool,
    /// `android:permission`.
    pub permission: Option<String>,
    /// `android:grantUriPermissions`.
    pub grant_uri_permissions: bool,
    /// Optional human-readable label.
    pub label: Option<String>,
}

/// Top-level structured view of an Android manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
    /// `<application android:label>` (resolved only when the value is a
    /// literal string; resource references are stored as `@0x…`).
    pub application_label: Option<String>,
    /// `<permission>` + `<uses-permission>` entries (in source order).
    pub permissions: Vec<PermissionEntry>,
    /// `<activity>` entries.
    pub activities: Vec<ComponentEntry>,
    /// `<service>` entries.
    pub services: Vec<ComponentEntry>,
    /// `<receiver>` entries.
    pub receivers: Vec<ComponentEntry>,
    /// `<provider>` entries.
    pub providers: Vec<ProviderEntry>,
}

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

/// Parse the raw bytes of an `AndroidManifest.xml` (already inflated out
/// of its containing APK) and extract a structured summary.
pub fn parse_manifest(axml: &[u8]) -> Result<ManifestInfo, ManifestError> {
    let mut parser = Parser::new(axml)?;
    parser.run()?;
    Ok(parser.info)
}

/// Convenience: open `path` as an APK, look up the `AndroidManifest.xml`
/// entry, inflate it, and parse it.
pub fn parse_from_apk(path: impl AsRef<Path>) -> Result<ManifestInfo, ManifestError> {
    let apk = asc_apk::Apk::open(path.as_ref())
        .map_err(|e| ManifestError::Truncated(format!("apk open: {e}")))?;
    let entry = apk
        .entry("AndroidManifest.xml")
        .ok_or_else(|| ManifestError::Truncated("AndroidManifest.xml entry not found".into()))?;
    let bytes = apk
        .read_entry(&entry)
        .map_err(|e| ManifestError::Truncated(format!("read AndroidManifest.xml: {e}")))?;
    parse_manifest(bytes.as_slice())
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
}

/// A stack frame carries the element's local name plus enough state to
/// route nested `<intent-filter>` / `<action>` / `<category>` events.
#[derive(Debug, Clone)]
struct Frame {
    name: String,
    /// If this frame is an `<activity>` / `<service>` / `<receiver>`,
    /// the index of the corresponding entry in the output vector.
    component: Option<(ComponentKind, usize)>,
    /// If this frame is an `<intent-filter>`, the slot inside its owning
    /// component's `intent_filters` vector.
    filter_slot: Option<usize>,
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
        // The magic AOSP uses is 0x00080003 (type | (headerSize << 16))
        // for an 8-byte `ResChunk_header` over a `RES_XML_TYPE` body.
        let magic = read_u32(bytes, 0)?;
        if magic != 0x0008_0003 {
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
                }
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
        let body_off = chunk_start + STRING_POOL_BODY_OFF;
        if body_off + 20 > self.bytes.len() {
            return Err(ManifestError::Truncated(
                "string pool header overruns EOF".into(),
            ));
        }
        let string_count = read_u32(self.bytes, body_off)?;
        let _style_count = read_u32(self.bytes, body_off + 4)?;
        let flags = read_u32(self.bytes, body_off + 8)?;
        let strings_start = read_u32(self.bytes, body_off + 12)?;
        let _styles_start = read_u32(self.bytes, body_off + 16)?;
        if string_count > MAX_STRING_COUNT {
            return Err(ManifestError::BadChunk(format!(
                "string pool count {string_count} exceeds cap"
            )));
        }
        if strings_start > chunk_size as u32 {
            return Err(ManifestError::BadChunk(format!(
                "stringsStart {strings_start} > chunk_size {chunk_size}"
            )));
        }
        let utf8 = (flags & RES_STRING_POOL_UTF8_FLAG) != 0;
        let mut strings_off = chunk_start + strings_start as usize;
        let mut decoded: Vec<String> = Vec::with_capacity(string_count as usize);
        let mut total_bytes: u64 = 0;
        for i in 0..string_count {
            let s = if utf8 {
                self.read_utf8_string(&mut strings_off, chunk_end)?
            } else {
                self.read_utf16_string(&mut strings_off, chunk_end)?
            };
            total_bytes = total_bytes.saturating_add(s.len() as u64);
            decoded.push(s);
            if total_bytes > MAX_STRING_BYTES {
                return Err(ManifestError::BadChunk(format!(
                    "decoded string pool exceeds cap at index {i}"
                )));
            }
        }
        self.strings = decoded;
        Ok(())
    }

    fn read_utf16_string(
        &self,
        pos: &mut usize,
        chunk_end: usize,
    ) -> Result<String, ManifestError> {
        if *pos + 2 > chunk_end {
            return Err(ManifestError::Truncated("UTF-16 char length".into()));
        }
        let char_len = read_u16(self.bytes, *pos)? as usize;
        *pos += 2;
        let byte_len = char_len
            .checked_mul(2)
            .ok_or_else(|| ManifestError::BadChunk("UTF-16 char length overflow".into()))?;
        if *pos + byte_len + 2 > chunk_end {
            return Err(ManifestError::Truncated("UTF-16 payload".into()));
        }
        let bytes = &self.bytes[*pos..*pos + byte_len];
        let units = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c));
        let out: String = char::decode_utf16(units)
            .map(|r| r.unwrap_or('\u{FFFD}'))
            .collect();
        *pos += byte_len + 2; // skip payload + NUL terminator
        Ok(out)
    }

    fn read_utf8_string(&self, pos: &mut usize, chunk_end: usize) -> Result<String, ManifestError> {
        if *pos + 2 > chunk_end {
            return Err(ManifestError::Truncated("UTF-8 char length".into()));
        }
        let _char_len = decode_uleb128(self.bytes, pos)?;
        let byte_len = decode_uleb128(self.bytes, pos)? as usize;
        if *pos + byte_len + 1 > chunk_end {
            return Err(ManifestError::Truncated("UTF-8 payload".into()));
        }
        let raw = &self.bytes[*pos..*pos + byte_len];
        *pos += byte_len + 1; // +1 for NUL terminator
        Ok(String::from_utf8_lossy(raw).into_owned())
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
        // We do not currently consult the namespace stack at element-
        // open time — namespaced element / attribute names arrive with
        // the **URI** as their ns string-pool index, which is what the
        // display layer cares about. We record nothing here.
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

        // Owned attribute name + value pairs so we can release the
        // immutable borrow of `self.strings` before the mutable
        // `process_element_open` call below.
        let mut attrs: Vec<(String, Option<String>)> = Vec::with_capacity(attr_count);
        for i in 0..attr_count {
            let attr_off = attr_table_off + i * attr_size;
            let _a_ns = read_u32(self.bytes, attr_off)?;
            let a_name = read_u32(self.bytes, attr_off + 4)?;
            let a_raw = read_u32(self.bytes, attr_off + 8)?;
            let _tv_size = read_u16(self.bytes, attr_off + 12)?;
            let _tv_res0 = self.bytes[attr_off + 14];
            let tv_type = self.bytes[attr_off + 15];
            let tv_data = read_u32(self.bytes, attr_off + 16)?;
            self.validate_string_index(a_name, "attribute name", false)?;
            let a_name_str = self.strings[a_name as usize].clone();
            let value = self.render_typed_value(tv_type, tv_data, a_raw)?;
            attrs.push((a_name_str, value));
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
        // The bit layout of `data_type`:
        //   bits 0..6   → kind (TYPE_NULL=0, TYPE_STRING=3, TYPE_INT_DEC=0x10, …)
        //   bit  7      → flag bit (rare)
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
                if raw_index == NO_INDEX {
                    None
                } else {
                    self.validate_string_index(raw_index, "string-typed rawValue", true)?;
                    Some(self.strings[raw_index as usize].clone())
                }
            }
            TYPE_REFERENCE | TYPE_ATTRIBUTE => Some(format!("@0x{data:08x}")),
            TYPE_INT_DEC => Some(data.to_string()),
            TYPE_INT_HEX => Some(format!("0x{data:08x}")),
            TYPE_INT_BOOLEAN => Some(if data != 0 { "true" } else { "false" }.to_string()),
            _ => Some(format!("0x{data:08x}")),
        };
        Ok(result)
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
        if idx == NO_INDEX {
            if allow_no_index {
                return Ok(());
            }
            return Err(ManifestError::BadChunk(format!(
                "{ctx}: NO_INDEX is not a valid string index"
            )));
        }
        if (idx as usize) >= self.strings.len() {
            return Err(ManifestError::BadChunk(format!(
                "{ctx}: string index {idx} out of range (pool has {})",
                self.strings.len()
            )));
        }
        Ok(())
    }

    fn process_element_open(
        &mut self,
        name: &str,
        attrs: &[(String, Option<String>)],
    ) -> Result<Frame, ManifestError> {
        let parent = self
            .stack
            .last()
            .map(|f| (f.name.as_str(), f.component, f.filter_slot));
        let mut component: Option<(ComponentKind, usize)> = None;
        let mut filter_slot: Option<usize> = None;
        match parent {
            None => self.process_root_element(name, attrs)?,
            Some(("manifest", _, _)) => self.process_manifest_child(name, attrs)?,
            Some(("application", _, _)) => {
                component = self.process_application_child(name, attrs)?;
            }
            Some((parent_name, Some((kind, comp_idx)), _))
                if matches!(
                    (kind, parent_name),
                    (ComponentKind::Activity, "activity")
                        | (ComponentKind::Service, "service")
                        | (ComponentKind::Receiver, "receiver")
                ) =>
            {
                if name == "intent-filter" {
                    let slot = match kind {
                        ComponentKind::Activity => {
                            let comp = &mut self.info.activities[comp_idx];
                            comp.intent_filters.push(IntentFilter::default());
                            comp.intent_filters.len() - 1
                        }
                        ComponentKind::Service => {
                            let comp = &mut self.info.services[comp_idx];
                            comp.intent_filters.push(IntentFilter::default());
                            comp.intent_filters.len() - 1
                        }
                        ComponentKind::Receiver => {
                            let comp = &mut self.info.receivers[comp_idx];
                            comp.intent_filters.push(IntentFilter::default());
                            comp.intent_filters.len() - 1
                        }
                    };
                    filter_slot = Some(slot);
                    // Inherit the parent component so nested <action> /
                    // <category> events can route into the right slot.
                    component = Some((kind, comp_idx));
                }
            }
            Some(("intent-filter", Some((kind, comp_idx)), Some(filter_idx))) => {
                let name_attr = attr(attrs, "name");
                match name {
                    "action" => {
                        if let Some(n) = name_attr {
                            push_filter_action(
                                self.info_for_kind_mut(kind),
                                comp_idx,
                                filter_idx,
                                n,
                            );
                        }
                    }
                    "category" => {
                        if let Some(n) = name_attr {
                            push_filter_category(
                                self.info_for_kind_mut(kind),
                                comp_idx,
                                filter_idx,
                                n,
                            );
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }

        Ok(Frame {
            name: name.to_string(),
            component,
            filter_slot,
        })
    }

    /// Process a top-level element (no parent on the stack).
    fn process_root_element(
        &mut self,
        name: &str,
        attrs: &[(String, Option<String>)],
    ) -> Result<(), ManifestError> {
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
            }
            "uses-sdk" => {
                if let Some(v) = int_attr(attrs, "minSdkVersion") {
                    self.info.min_sdk = Some(v);
                }
                if let Some(v) = int_attr(attrs, "targetSdkVersion") {
                    self.info.target_sdk = Some(v);
                }
            }
            "uses-permission" => {
                if let Some(p) = attr(attrs, "name") {
                    self.info.permissions.push(PermissionEntry {
                        name: p.to_string(),
                        protection_level: None,
                        label: None,
                    });
                }
            }
            "permission" => {
                if let Some(p) = attr(attrs, "name") {
                    self.info.permissions.push(PermissionEntry {
                        name: p.to_string(),
                        protection_level: attr(attrs, "protectionLevel").map(str::to_string),
                        label: attr(attrs, "label").map(str::to_string),
                    });
                }
            }
            "application" => {
                if let Some(v) = attr(attrs, "label") {
                    self.info.application_label = Some(v.to_string());
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Process a child of `<application>`. Returns the new component
    /// Process a child of `<manifest>`. Returns nothing — these elements
    /// contribute fields directly to `self.info` and don't push a frame.
    fn process_manifest_child(
        &mut self,
        name: &str,
        attrs: &[(String, Option<String>)],
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
            "uses-permission" => {
                if let Some(p) = attr(attrs, "name") {
                    self.info.permissions.push(PermissionEntry {
                        name: p.to_string(),
                        protection_level: None,
                        label: None,
                    });
                }
            }
            "permission" => {
                if let Some(p) = attr(attrs, "name") {
                    self.info.permissions.push(PermissionEntry {
                        name: p.to_string(),
                        protection_level: attr(attrs, "protectionLevel").map(str::to_string),
                        label: attr(attrs, "label").map(str::to_string),
                    });
                }
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
        attrs: &[(String, Option<String>)],
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
            "provider" => {
                if let Some(p) = attr(attrs, "name") {
                    self.info.providers.push(ProviderEntry {
                        name: p.to_string(),
                        authorities: attr(attrs, "authorities").map(str::to_string),
                        exported: bool_attr(attrs, "exported"),
                        permission: attr(attrs, "permission").map(str::to_string),
                        grant_uri_permissions: bool_attr(attrs, "grantUriPermissions"),
                        label: attr(attrs, "label").map(str::to_string),
                    });
                }
                None
            }
            _ => None,
        };
        Ok(ctx)
    }

    fn info_for_kind_mut(&mut self, kind: ComponentKind) -> &mut Vec<ComponentEntry> {
        match kind {
            ComponentKind::Activity => &mut self.info.activities,
            ComponentKind::Service => &mut self.info.services,
            ComponentKind::Receiver => &mut self.info.receivers,
        }
    }
}

fn push_filter_action(vec: &mut [ComponentEntry], comp_idx: usize, filter_idx: usize, name: &str) {
    if let Some(comp) = vec.get_mut(comp_idx)
        && let Some(f) = comp.intent_filters.get_mut(filter_idx)
    {
        f.actions.push(name.to_string());
    }
}

fn push_filter_category(
    vec: &mut [ComponentEntry],
    comp_idx: usize,
    filter_idx: usize,
    name: &str,
) {
    if let Some(comp) = vec.get_mut(comp_idx)
        && let Some(f) = comp.intent_filters.get_mut(filter_idx)
    {
        f.categories.push(name.to_string());
    }
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn attr<'a>(attrs: &'a [(String, Option<String>)], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(n, _)| n == name)
        .and_then(|(_, v)| v.as_deref())
}

fn int_attr(attrs: &[(String, Option<String>)], name: &str) -> Option<u32> {
    attr(attrs, name).and_then(|v| v.parse().ok())
}

fn bool_attr(attrs: &[(String, Option<String>)], name: &str) -> bool {
    matches!(attr(attrs, name), Some("true"))
}

fn component_from_attrs(name: &str, attrs: &[(String, Option<String>)]) -> ComponentEntry {
    ComponentEntry {
        name: name.to_string(),
        exported: bool_attr(attrs, "exported"),
        permission: attr(attrs, "permission").map(str::to_string),
        label: attr(attrs, "label").map(str::to_string),
        intent_filters: Vec::new(),
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

/// AOSP's `decodeLength` for UTF-8 string-pool prefixes:
/// one byte if the high bit is clear; otherwise two bytes with the high
/// bit stripped (so the value fits in 15 bits).
fn decode_uleb128(bytes: &[u8], pos: &mut usize) -> Result<u32, ManifestError> {
    let b0 = bytes
        .get(*pos)
        .copied()
        .ok_or_else(|| ManifestError::Truncated(format!("uleb128 read at {pos} past EOF")))?;
    *pos += 1;
    if b0 & 0x80 == 0 {
        Ok(b0 as u32)
    } else {
        let b1 = bytes
            .get(*pos)
            .copied()
            .ok_or_else(|| ManifestError::Truncated(format!("uleb128 read at {pos} past EOF")))?;
        *pos += 1;
        Ok((((b0 & 0x7F) as u32) << 8) | b1 as u32)
    }
}

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
