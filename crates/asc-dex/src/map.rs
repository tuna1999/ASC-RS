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
pub const MAP_TYPE_TYPE_LIST: u16 = 0x1000;
pub const MAP_TYPE_STRING_DATA: u16 = 0x1002;
pub const MAP_TYPE_CODE_ITEM: u16 = 0x2001;
pub const MAP_TYPE_ANNOTATIONS_DIRECTORY_ITEM: u16 = 0x2006;
pub const MAP_TYPE_ANNOTATION_SET: u16 = 0x2003;
pub const MAP_TYPE_CLASS_DATA_ITEM: u16 = 0x2002;
pub const MAP_TYPE_DEBUG_INFO_ITEM: u16 = 0x2005;

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
}
