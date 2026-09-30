//! `map_list` / `map_item` accessors.

use crate::error::DexError;
use crate::view::DexView;

/// Map item type constants (subset commonly inspected).
pub const MAP_TYPE_HEADER_ITEM: u16 = 0x0000;
pub const MAP_TYPE_STRING_ID_ITEM: u16 = 0x0001;
pub const MAP_TYPE_TYPE_ID_ITEM: u16 = 0x0002;
pub const MAP_TYPE_PROTO_ID_ITEM: u16 = 0x0003;
pub const MAP_TYPE_FIELD_ID_ITEM: u16 = 0x0004;
pub const MAP_TYPE_METHOD_ID_ITEM: u16 = 0x0005;
pub const MAP_TYPE_CLASS_DEF_ITEM: u16 = 0x0006;
pub const MAP_TYPE_CALL_SITE_ID_ITEM: u16 = 0x0007;
pub const MAP_TYPE_METHOD_HANDLE_ITEM: u16 = 0x0008;
pub const MAP_TYPE_TYPE_LIST: u16 = 0x1001;
pub const MAP_TYPE_STRING_DATA: u16 = 0x2002;
pub const MAP_TYPE_CODE_ITEM: u16 = 0x2001;
pub const MAP_TYPE_ANNOTATIONS_DIRECTORY_ITEM: u16 = 0x2006;
pub const MAP_TYPE_ANNOTATION_SET: u16 = 0x1003;
pub const MAP_TYPE_CLASS_DATA_ITEM: u16 = 0x2000;
pub const MAP_TYPE_DEBUG_INFO_ITEM: u16 = 0x2003;
pub const MAP_TYPE_MAP_LIST: u16 = 0x1000;

/// A single map entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapItem {
    pub ty: u16,
    pub size: u32,
    pub offset: u32,
}

/// Iterator over a `map_list`.
pub struct MapIter<'a> {
    physical: &'a [u8],
    base: usize,
    pos: usize,
    count: usize,
}

impl<'a> Iterator for MapIter<'a> {
    type Item = Result<MapItem, DexError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.count {
            return None;
        }
        let off = self.base + self.pos * 12;
        if off + 12 > self.physical.len() {
            self.pos = self.count;
            return Some(Err(DexError::Truncated {
                needed: off + 12,
                actual: self.physical.len(),
            }));
        }
        let ty = match crate::read::read_u16(self.physical, off) {
            Ok(v) => v,
            Err(e) => {
                self.pos = self.count;
                return Some(Err(e));
            }
        };
        let _unused = match crate::read::read_u16(self.physical, off + 2) {
            Ok(v) => v,
            Err(e) => {
                self.pos = self.count;
                return Some(Err(e));
            }
        };
        let size = match crate::read::read_u32(self.physical, off + 4) {
            Ok(v) => v,
            Err(e) => {
                self.pos = self.count;
                return Some(Err(e));
            }
        };
        let offset = match crate::read::read_u32(self.physical, off + 8) {
            Ok(v) => v,
            Err(e) => {
                self.pos = self.count;
                return Some(Err(e));
            }
        };
        self.pos += 1;
        Some(Ok(MapItem { ty, size, offset }))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.count - self.pos;
        (rem, Some(rem))
    }
}

impl<'a> DexView<'a> {
    /// Returns the raw `map_off` from the header (0 if absent).
    #[inline]
    pub fn map_off(&self) -> u32 {
        self.header.map_off
    }

    /// Iterates `map_item` entries.
    pub fn map_list(&self) -> Result<MapIter<'a>, DexError> {
        let off = self.header.map_off;
        if off == 0 {
            return Ok(MapIter {
                physical: self.physical,
                base: 0,
                pos: 0,
                count: 0,
            });
        }
        let base = off as usize;
        if base + 4 > self.physical.len() {
            return Err(DexError::Truncated {
                needed: base + 4,
                actual: self.physical.len(),
            });
        }
        let count = crate::read::read_u32(self.physical, base)? as usize;
        let needed = count.checked_mul(12).ok_or(DexError::InvalidLength {
            off: base,
            message: "map_list count overflow",
        })?;
        if base + 4 + needed > self.physical.len() {
            return Err(DexError::Truncated {
                needed: base + 4 + needed,
                actual: self.physical.len(),
            });
        }
        Ok(MapIter {
            physical: self.physical,
            base: base + 4,
            pos: 0,
            count,
        })
    }

    /// Byte offset just past the last section the map (and link area)
    /// describes, i.e. where declared DEX content ends. Bytes beyond it are
    /// not covered by any section.
    ///
    /// Only extents that can be computed exactly are reported: the last
    /// map item (by offset) must be a fixed-size table, the map itself or
    /// `string_data`. Anything else, DEX-041 containers (shared sections),
    /// or an unreadable map yields [`DataEnd::Unknown`]; callers must not
    /// read that as "no trailing bytes".
    pub fn data_end(&self) -> DataEnd {
        if self.version().as_str() == "041" {
            return DataEnd::Unknown("DEX-041 container has shared sections");
        }
        let Ok(iter) = self.map_list() else {
            return DataEnd::Unknown("map_list unreadable");
        };
        let mut items = Vec::new();
        for it in iter {
            match it {
                Ok(i) => items.push(i),
                Err(_) => return DataEnd::Unknown("map_list truncated"),
            }
        }
        let Some(last) = items.iter().max_by_key(|i| i.offset) else {
            return DataEnd::Unknown("map_list empty");
        };
        let size = last.size as usize;
        let start = last.offset as usize;
        let fixed = |unit: usize| size.checked_mul(unit).and_then(|n| start.checked_add(n));
        let end = match last.ty {
            MAP_TYPE_HEADER_ITEM => Some(start + self.header.header_size as usize),
            MAP_TYPE_STRING_ID_ITEM | MAP_TYPE_TYPE_ID_ITEM | MAP_TYPE_CALL_SITE_ID_ITEM => {
                fixed(4)
            }
            MAP_TYPE_PROTO_ID_ITEM => fixed(12),
            MAP_TYPE_FIELD_ID_ITEM | MAP_TYPE_METHOD_ID_ITEM | MAP_TYPE_METHOD_HANDLE_ITEM => {
                fixed(8)
            }
            MAP_TYPE_CLASS_DEF_ITEM => fixed(32),
            // The map_list item's own `size` is 1; the real length is the
            // leading u32 count of the list.
            MAP_TYPE_MAP_LIST => crate::read::read_u32(self.physical, start)
                .ok()
                .and_then(|c| (c as usize).checked_mul(12))
                .and_then(|n| start.checked_add(4)?.checked_add(n)),
            MAP_TYPE_STRING_DATA => self.string_data_end(start, size),
            _ => return DataEnd::Unknown("last map item has a variable-size type"),
        };
        let Some(mut end) = end else {
            return DataEnd::Unknown("last map item extent overflows");
        };
        if self.header.link_size > 0 {
            end = end.max(self.header.link_off as usize + self.header.link_size as usize);
        }
        if end > self.physical.len() {
            return DataEnd::Unknown("declared extent exceeds file");
        }
        DataEnd::Known(end)
    }

    /// End of `count` consecutive `string_data_item`s starting at `start`
    /// (ULEB utf16 length, MUTF-8 bytes, NUL). `None` on any overrun.
    fn string_data_end(&self, start: usize, count: usize) -> Option<usize> {
        let buf = self.physical;
        let mut pos = start;
        for _ in 0..count {
            let (_, n) = crate::leb::uleb128(buf.get(pos..)?).ok()?;
            pos += n;
            pos += buf.get(pos..)?.iter().position(|&b| b == 0)? + 1;
        }
        Some(pos)
    }
}

/// Result of [`DexView::data_end`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataEnd {
    /// Declared content ends at this physical offset.
    Known(usize),
    /// Not computable; the reason is a short static description.
    Unknown(&'static str),
}
