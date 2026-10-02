//! Generic binary-AXML tree decoder.
//!
//! [`crate::parse_manifest`] answers "what does the *manifest* say";
//! this module answers "what does *this* compiled XML file say" for any
//! entry — `res/xml/network_security_config.xml`, backup rules, widget
//! provider descriptions, etc. It keeps node order, attribute
//! namespaces (as URIs plus the document's prefix bindings), and the
//! raw `dataType` byte so unresolved resource references stay
//! traceable.

use serde::Serialize;

use crate::{
    ANDROID_NS, MAX_CHILDREN, MAX_CHUNK_BODY, MAX_STRING_BYTES, MAX_STRING_COUNT, ManifestError,
    NO_INDEX, RES_STRING_POOL_TYPE, RES_XML_END_ELEMENT_TYPE, RES_XML_RESOURCE_MAP_TYPE,
    RES_XML_START_ELEMENT_TYPE, RES_XML_START_NAMESPACE_TYPE, XML_TREE_BODY_OFF, read_u16,
    read_u32, render_typed_value_str, validate_string_index_str,
};

/// One attribute: namespace URI (if any), local name, the rendered
/// value string, and the raw `Res_value.dataType` byte.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AxmlAttr {
    pub ns: Option<String>,
    pub name: String,
    /// Rendered value (`@0x…` references stay unresolved on purpose).
    pub value: Option<String>,
    /// Raw `Res_value.dataType` (e.g. `0x01` reference, `0x03` string,
    /// `0x12` boolean).
    pub value_type: u8,
}

/// One element with its attributes and children in document order.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AxmlElement {
    pub ns: Option<String>,
    pub name: String,
    pub attrs: Vec<AxmlAttr>,
    pub children: Vec<AxmlElement>,
}

/// A decoded document: the namespace prefix bindings declared in the
/// prologue and the root element (when present).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AxmlDocument {
    /// `(prefix, uri)` pairs from the leading namespace events.
    pub namespaces: Vec<(String, String)>,
    pub root: Option<AxmlElement>,
}

impl AxmlDocument {
    /// Resolve a prefix for a URI (first binding wins), for display.
    pub fn prefix_for(&self, uri: &str) -> Option<&str> {
        self.namespaces
            .iter()
            .find(|(_, u)| u == uri)
            .map(|(p, _)| p.as_str())
    }
}

/// Parse a compiled binary XML file into a tree. Strict like the
/// manifest parser: every chunk is bounds-checked and malformed input
/// is an error, never a panic. CDATA chunks (`0x0104`) are skipped
/// (vanishingly rare in compiled resources).
pub fn parse_axml(bytes: &[u8]) -> Result<AxmlDocument, ManifestError> {
    if bytes.len() < 8 {
        return Err(ManifestError::NotAXml);
    }
    // Same root checks as the manifest parser (headerSize 8, size sane).
    if usize::from(read_u16(bytes, 2)?) != 8 {
        return Err(ManifestError::NotAXml);
    }
    let root_size = read_u32(bytes, 4)? as usize;
    if root_size < 8 || root_size > MAX_CHUNK_BODY as usize {
        return Err(ManifestError::BadChunk(format!(
            "root XML chunk size {root_size} invalid"
        )));
    }
    if root_size > bytes.len() {
        return Err(ManifestError::Truncated(format!(
            "root chunk size {root_size} overruns file length {}",
            bytes.len()
        )));
    }
    let root_end = root_size;

    // First inner chunk must be the string pool.
    let mut cursor = 8usize;
    if cursor + 8 > root_end {
        return Err(ManifestError::Truncated("missing string pool chunk".into()));
    }
    let chunk_type = read_u16(bytes, cursor)?;
    let chunk_size = read_u32(bytes, cursor + 4)? as usize;
    if chunk_type != RES_STRING_POOL_TYPE {
        return Err(ManifestError::BadChunk(
            "first inner chunk is not a string pool".into(),
        ));
    }
    let strings = asc_apk::string_pool::parse(
        bytes,
        cursor,
        cursor
            .checked_add(chunk_size)
            .filter(|end| *end <= root_end)
            .ok_or_else(|| ManifestError::Truncated("string pool overruns root".into()))?,
        asc_apk::string_pool::Limits {
            max_count: MAX_STRING_COUNT,
            max_bytes: MAX_STRING_BYTES,
        },
    )
    .map_err(|e| match e {
        asc_apk::string_pool::PoolError::Truncated(s) => ManifestError::Truncated(s),
        asc_apk::string_pool::PoolError::Bad(s) => ManifestError::BadChunk(s),
    })?
    .strings;
    cursor += chunk_size;

    let mut doc = AxmlDocument {
        namespaces: Vec::new(),
        root: None,
    };
    // Stack of open elements (most recent last).
    let mut stack: Vec<AxmlElement> = Vec::new();
    while cursor + 8 <= root_end {
        let chunk_type = read_u16(bytes, cursor)?;
        let header_size = read_u16(bytes, cursor + 2)?;
        let chunk_size = read_u32(bytes, cursor + 4)? as usize;
        if header_size < 8 || chunk_size < header_size as usize {
            return Err(ManifestError::BadChunk(format!(
                "chunk at {cursor} has inconsistent header"
            )));
        }
        let chunk_end = cursor
            .checked_add(chunk_size)
            .filter(|end| *end <= root_end)
            .ok_or_else(|| {
                ManifestError::Truncated(format!(
                    "chunk at {cursor} overruns root end ({chunk_size} bytes)"
                ))
            })?;
        match chunk_type {
            RES_XML_RESOURCE_MAP_TYPE => {}
            RES_XML_START_NAMESPACE_TYPE => {
                let body = cursor + XML_TREE_BODY_OFF;
                if body + 8 > chunk_end {
                    return Err(ManifestError::Truncated("start-namespace body".into()));
                }
                let prefix = read_u32(bytes, body)?;
                let uri = read_u32(bytes, body + 4)?;
                validate_string_index_str(&strings, prefix, "start-ns prefix", true)?;
                validate_string_index_str(&strings, uri, "start-ns uri", true)?;
                if prefix != NO_INDEX && uri != NO_INDEX {
                    doc.namespaces.push((
                        strings[prefix as usize].clone(),
                        strings[uri as usize].clone(),
                    ));
                }
            }
            crate::RES_XML_END_NAMESPACE_TYPE => {}
            RES_XML_START_ELEMENT_TYPE => {
                if stack.len() >= MAX_CHILDREN {
                    return Err(ManifestError::BadChunk(format!(
                        "element nesting exceeds cap {MAX_CHILDREN}"
                    )));
                }
                let element = parse_element(bytes, cursor, chunk_end, &strings)?;
                stack.push(element);
            }
            RES_XML_END_ELEMENT_TYPE => {
                // Validate the close tag matches the open element.
                let body = cursor + XML_TREE_BODY_OFF;
                if body + 8 > chunk_end {
                    return Err(ManifestError::Truncated("end-element body".into()));
                }
                let close_name = read_u32(bytes, body + 4)?;
                validate_string_index_str(&strings, close_name, "end-element name", false)?;
                let close_name = &strings[close_name as usize];
                match stack.last() {
                    Some(open) if open.name != *close_name => {
                        return Err(ManifestError::BadChunk(format!(
                            "end-element <{close_name}> does not match open <{}>",
                            open.name
                        )));
                    }
                    Some(_) => {}
                    None => {
                        return Err(ManifestError::BadChunk(
                            "end-element with empty stack".into(),
                        ));
                    }
                }
                let element = stack.pop().expect("checked non-empty above");
                match stack.last_mut() {
                    Some(parent) => parent.children.push(element),
                    None => {
                        if doc.root.replace(element).is_some() {
                            return Err(ManifestError::BadChunk("multiple root elements".into()));
                        }
                    }
                }
            }
            _ => {
                return Err(ManifestError::Unsupported(format!(
                    "chunk type 0x{chunk_type:04x} not handled"
                )));
            }
        }
        cursor = chunk_end;
    }
    if cursor != root_end {
        return Err(ManifestError::BadChunk(format!(
            "trailing {} bytes at end of root chunk",
            root_end.saturating_sub(cursor)
        )));
    }
    if !stack.is_empty() {
        return Err(ManifestError::BadChunk(format!(
            "unclosed elements at end of document: {}",
            stack.len()
        )));
    }
    Ok(doc)
}

fn parse_element(
    bytes: &[u8],
    chunk_start: usize,
    chunk_end: usize,
    strings: &[String],
) -> Result<AxmlElement, ManifestError> {
    let body_off = chunk_start + XML_TREE_BODY_OFF;
    if body_off + 20 > chunk_end {
        return Err(ManifestError::Truncated("start-element body".into()));
    }
    let ns_idx = read_u32(bytes, body_off)?;
    let name_idx = read_u32(bytes, body_off + 4)?;
    let attr_start = read_u16(bytes, body_off + 8)? as usize;
    let attr_size = read_u16(bytes, body_off + 10)? as usize;
    let attr_count = read_u16(bytes, body_off + 12)? as usize;
    const ATTRIBUTE_MIN_SIZE: usize = 20;
    if attr_size < ATTRIBUTE_MIN_SIZE {
        return Err(ManifestError::BadChunk(format!(
            "start-element attributeSize {attr_size} < {ATTRIBUTE_MIN_SIZE}"
        )));
    }
    validate_string_index_str(strings, name_idx, "start-element name", false)?;
    let ns = if ns_idx == NO_INDEX {
        None
    } else {
        validate_string_index_str(strings, ns_idx, "start-element ns", true)?;
        Some(strings[ns_idx as usize].clone())
    };
    let attr_table_off = body_off + attr_start;
    let attrs_needed = attr_count
        .checked_mul(attr_size)
        .ok_or_else(|| ManifestError::BadChunk("attribute table overflow".into()))?;
    if attr_table_off
        .checked_add(attrs_needed)
        .is_none_or(|end| end > chunk_end)
    {
        return Err(ManifestError::Truncated("attribute table".into()));
    }
    let mut attrs = Vec::with_capacity(attr_count);
    for i in 0..attr_count {
        let attr_off = attr_table_off + i * attr_size;
        let a_ns = read_u32(bytes, attr_off)?;
        let a_name = read_u32(bytes, attr_off + 4)?;
        let a_raw = read_u32(bytes, attr_off + 8)?;
        let tv_type = bytes[attr_off + 15];
        let tv_data = read_u32(bytes, attr_off + 16)?;
        validate_string_index_str(strings, a_name, "attribute name", false)?;
        let ns = if a_ns == NO_INDEX {
            None
        } else {
            validate_string_index_str(strings, a_ns, "attribute ns", false)?;
            Some(strings[a_ns as usize].clone())
        };
        attrs.push(AxmlAttr {
            ns,
            name: strings[a_name as usize].clone(),
            value: render_typed_value_str(strings, tv_type, tv_data, a_raw)?,
            value_type: tv_type,
        });
    }
    Ok(AxmlElement {
        ns,
        name: strings[name_idx as usize].clone(),
        attrs,
        children: Vec::new(),
    })
}

/// Render the tree as indented, XML-ish text. Namespaced attributes
/// print as `prefix:name` (Android prefix for
/// `http://schemas.android.com/apk/res/android`), unknown URIs as
/// `{uri}name`. Values are quoted.
pub fn format_axml_text(doc: &AxmlDocument) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    if let Some((prefix, uri)) = doc.namespaces.first() {
        let _ = writeln!(s, "# namespaces: {prefix} = {uri}");
    }
    if let Some(root) = &doc.root {
        render_element(&mut s, doc, root, 0);
    }
    s
}

fn render_element(out: &mut String, doc: &AxmlDocument, e: &AxmlElement, depth: usize) {
    use std::fmt::Write as _;
    let indent = "  ".repeat(depth);
    let name = qualify(doc, e.ns.as_deref(), &e.name);
    let _ = write!(out, "{indent}<{name}");
    for a in &e.attrs {
        let an = qualify(doc, a.ns.as_deref(), &a.name);
        match &a.value {
            Some(v) => {
                let _ = write!(out, " {an}=\"{}\"", v.replace('"', "&quot;"));
            }
            None => {
                let _ = write!(out, " {an}=(null)");
            }
        }
    }
    if e.children.is_empty() {
        let _ = writeln!(out, "/>");
        return;
    }
    let _ = writeln!(out, ">");
    for c in &e.children {
        render_element(out, doc, c, depth + 1);
    }
    let _ = writeln!(out, "{indent}</{name}>");
}

fn qualify(doc: &AxmlDocument, ns: Option<&str>, name: &str) -> String {
    match ns {
        None => name.to_string(),
        Some(ANDROID_NS) => format!("android:{name}"),
        Some(uri) => match doc.prefix_for(uri) {
            Some(p) => format!("{p}:{name}"),
            None => format!("{{{uri}}}{name}"),
        },
    }
}
