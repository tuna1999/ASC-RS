//! Typed pool accessors: strings, types, protos, fields, methods, call-sites
//! and method-handles.
//!
//! All accessors operate on the physical buffer the `DexView` was built from
//! and interpret every offset absolutely. They never allocate during a
//! pool-wide scan; per-item reads allocate only when the caller asks for a
//! lossy decode.

use crate::error::DexError;
use crate::header::DexHeader;
use crate::ids::{
    CallSiteIdx, FieldIdx, MethodHandleIdx, MethodIdx, NO_INDEX, ProtoIdx, StringIdx, TypeIdx,
};
use crate::mutf8;
use crate::view::DexView;

use std::borrow::Cow;

/// A borrowed DEX string record.
#[derive(Debug, Clone, Copy)]
pub struct DexStringRef<'a> {
    /// UTF-16 code-unit length as encoded at the start of the string record
    /// (ULEB128). Informational only — `decode_lossy` does not use it for
    /// validation, only as a sizing hint.
    pub utf16_len: u32,
    /// Raw MUTF-8 payload (not including the trailing NUL).
    pub mutf8: &'a [u8],
}

impl<'a> DexStringRef<'a> {
    /// Returns the raw MUTF-8 bytes (without the terminator).
    #[inline]
    pub fn raw_mutf8(&self) -> &'a [u8] {
        self.mutf8
    }

    /// Decodes the string lossily. Borrows the original slice when the
    /// payload is pure ASCII, otherwise allocates.
    pub fn decode_lossy(&self) -> Cow<'a, str> {
        mutf8::decode_lossy(self.mutf8, self.utf16_len)
    }
}

/// Zero-copy view of a `type_list` (proto parameter list or class interfaces).
#[derive(Debug, Clone, Copy)]
pub struct TypeList<'a> {
    pub(crate) bytes: &'a [u8],
}

impl<'a> TypeList<'a> {
    /// Returns the count of entries, or zero for an empty list.
    #[inline]
    pub fn len(&self) -> usize {
        if self.bytes.len() < 4 {
            0
        } else {
            crate::read::read_u32(self.bytes, 0).unwrap_or(0) as usize
        }
    }

    /// Returns `true` when the list has zero entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the `i`-th type index. `i` must be `< self.len()`.
    pub fn get(&self, i: usize) -> Option<TypeIdx> {
        let count = self.len();
        if i >= count {
            return None;
        }
        let off = 4 + i * 2;
        if off + 2 > self.bytes.len() {
            return None;
        }
        Some(TypeIdx(
            crate::read::read_u16(self.bytes, off).unwrap_or(0) as u32
        ))
    }

    /// Iterator over the `TypeIdx` entries.
    pub fn iter(&self) -> TypeListIter<'a> {
        TypeListIter {
            bytes: self.bytes,
            count: self.len(),
            pos: 0,
        }
    }
}

impl<'a> IntoIterator for TypeList<'a> {
    type Item = TypeIdx;
    type IntoIter = TypeListIter<'a>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator returned by `TypeList::iter`.
pub struct TypeListIter<'a> {
    bytes: &'a [u8],
    count: usize,
    pos: usize,
}

impl<'a> Iterator for TypeListIter<'a> {
    type Item = TypeIdx;
    fn next(&mut self) -> Option<TypeIdx> {
        if self.pos >= self.count {
            return None;
        }
        let off = 4 + self.pos * 2;
        if off + 2 > self.bytes.len() {
            return None;
        }
        let idx = TypeIdx(crate::read::read_u16(self.bytes, off).unwrap_or(0) as u32);
        self.pos += 1;
        Some(idx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.count - self.pos;
        (remaining, Some(remaining))
    }
}

/// A resolved `field_id` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldIdItem {
    pub class: TypeIdx,
    pub ty: TypeIdx,
    pub name: StringIdx,
}

/// A resolved `method_id` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodIdItem {
    pub class: TypeIdx,
    pub proto: ProtoIdx,
    pub name: StringIdx,
}

/// A resolved `proto_id` entry. `parameters_off == 0` ⇒ empty parameter list.
#[derive(Debug, Clone, Copy)]
pub struct ProtoIdItem<'a> {
    pub shorty: StringIdx,
    pub return_type: TypeIdx,
    pub parameters: TypeList<'a>,
}

/// Distinguishes the two kinds of method-handle target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldOrMethod {
    Field(FieldIdx),
    Method(MethodIdx),
}

/// A resolved `method_handle_item`. `handle_type` is the raw 0..=9 value.
#[derive(Debug, Clone, Copy)]
pub struct MethodHandleItem {
    pub handle_type: u16,
    pub target: FieldOrMethod,
}

// --------------------- pool extent validation ---------------------

/// Validates that a pool of `count` items, each of `stride` bytes, fits in
/// `bytes` starting at `off`. Returns `Ok(())` on success or a
/// [`DexError::PoolOutOfBounds`] describing the offending pool.
#[inline]
pub(crate) fn check_pool(
    pool: &'static str,
    off: u32,
    count: u32,
    stride: usize,
    file: usize,
) -> Result<(), DexError> {
    if count == 0 {
        return Ok(());
    }
    let off_us = off as usize;
    let needed = count
        .checked_mul(stride as u32)
        .ok_or(DexError::PoolOutOfBounds {
            pool,
            off: off_us,
            count,
            stride,
            file,
        })?;
    let end = off_us
        .checked_add(needed as usize)
        .ok_or(DexError::PoolOutOfBounds {
            pool,
            off: off_us,
            count,
            stride,
            file,
        })?;
    if end > file {
        return Err(DexError::PoolOutOfBounds {
            pool,
            off: off_us,
            count,
            stride,
            file,
        });
    }
    Ok(())
}

/// Validates every pool extent and returns `Ok(())` if all are in range.
/// Pool offsets are absolute offsets into the physical container and must
/// fit inside the logical DEX's extent `header_off..header_off + file_size`.
pub(crate) fn validate_all(
    header: &DexHeader,
    file_size: usize,
    header_off: usize,
) -> Result<(), DexError> {
    // Reuse the existing `check_pool` helper against the absolute end.
    let abs_end = header_off.saturating_add(file_size);
    check_pool(
        "string_ids",
        header.string_ids_off,
        header.string_ids_size,
        4,
        abs_end,
    )?;
    check_pool(
        "type_ids",
        header.type_ids_off,
        header.type_ids_size,
        4,
        abs_end,
    )?;
    check_pool(
        "proto_ids",
        header.proto_ids_off,
        header.proto_ids_size,
        12,
        abs_end,
    )?;
    check_pool(
        "field_ids",
        header.field_ids_off,
        header.field_ids_size,
        8,
        abs_end,
    )?;
    check_pool(
        "method_ids",
        header.method_ids_off,
        header.method_ids_size,
        8,
        abs_end,
    )?;
    check_pool(
        "class_defs",
        header.class_defs_off,
        header.class_defs_size,
        32,
        abs_end,
    )?;
    if header.map_off != 0
        && (header.map_off as usize) < abs_end
        && (header.map_off as usize) + 4 > abs_end
    {
        return Err(DexError::OffsetOutOfBounds {
            off: header.map_off as usize,
            file: abs_end,
        });
    }
    Ok(())
}

// --------------------- typed index accessors ---------------------

impl<'a> DexView<'a> {
    /// Returns the count of strings in the string pool.
    #[inline]
    pub fn string_count(&self) -> u32 {
        self.header.string_ids_size
    }

    /// Returns the count of types in the type pool.
    #[inline]
    pub fn type_count(&self) -> u32 {
        self.header.type_ids_size
    }

    /// Returns the count of protos.
    #[inline]
    pub fn proto_count(&self) -> u32 {
        self.header.proto_ids_size
    }

    /// Returns the count of fields.
    #[inline]
    pub fn field_count(&self) -> u32 {
        self.header.field_ids_size
    }

    /// Returns the count of methods.
    #[inline]
    pub fn method_count(&self) -> u32 {
        self.header.method_ids_size
    }

    /// Returns the count of class-defs.
    #[inline]
    pub fn class_def_count(&self) -> u32 {
        self.header.class_defs_size
    }

    /// Returns the string at the given index. The returned reference borrows
    /// the underlying `physical` buffer.
    pub fn string(&self, idx: StringIdx) -> Result<DexStringRef<'a>, DexError> {
        let count = self.header.string_ids_size;
        if idx.0 >= count {
            return Err(DexError::IndexOutOfBounds {
                pool: "string_ids",
                idx: idx.0,
                count,
            });
        }
        let pool_base = self.header.string_ids_off as usize;
        let entry_off = pool_base + (idx.0 as usize) * 4;
        if entry_off + 4 > self.physical.len() {
            return Err(DexError::OffsetOutOfBounds {
                off: entry_off,
                file: self.physical.len(),
            });
        }
        let data_off = crate::read::read_u32(self.physical, entry_off)? as usize;
        let (utf16_len, payload_start) = self.read_string_record(data_off)?;
        let payload_end = mutf8::find_terminator(self.physical, payload_start)?;
        Ok(DexStringRef {
            utf16_len,
            mutf8: &self.physical[payload_start..payload_end],
        })
    }

    /// Returns the type index's descriptor string index.
    pub fn type_(&self, idx: TypeIdx) -> Result<StringIdx, DexError> {
        let count = self.header.type_ids_size;
        if idx.0 >= count {
            return Err(DexError::IndexOutOfBounds {
                pool: "type_ids",
                idx: idx.0,
                count,
            });
        }
        let off = self.header.type_ids_off as usize + (idx.0 as usize) * 4;
        if off + 4 > self.physical.len() {
            return Err(DexError::OffsetOutOfBounds {
                off,
                file: self.physical.len(),
            });
        }
        let descriptor = crate::read::read_u32(self.physical, off)?;
        Ok(StringIdx(descriptor))
    }

    /// Returns the proto's shorty / return type and a zero-copy parameter list.
    pub fn proto(&self, idx: ProtoIdx) -> Result<ProtoIdItem<'a>, DexError> {
        let count = self.header.proto_ids_size;
        if idx.0 >= count {
            return Err(DexError::IndexOutOfBounds {
                pool: "proto_ids",
                idx: idx.0,
                count,
            });
        }
        let off = self.header.proto_ids_off as usize + (idx.0 as usize) * 12;
        if off + 12 > self.physical.len() {
            return Err(DexError::OffsetOutOfBounds {
                off,
                file: self.physical.len(),
            });
        }
        let shorty = crate::read::read_u32(self.physical, off)?;
        let return_type = crate::read::read_u32(self.physical, off + 4)?;
        let params_off = crate::read::read_u32(self.physical, off + 8)?;

        let parameters = if params_off == 0 {
            TypeList { bytes: &[] }
        } else {
            let p = params_off as usize;
            if p + 4 > self.physical.len() {
                return Err(DexError::OffsetOutOfBounds {
                    off: p,
                    file: self.physical.len(),
                });
            }
            let size = crate::read::read_u32(self.physical, p)? as usize;
            let needed = size.checked_mul(2).ok_or(DexError::InvalidLength {
                off: p,
                message: "type_list size overflow",
            })?;
            let total = 4 + needed;
            if p + total > self.physical.len() {
                return Err(DexError::InvalidLength {
                    off: p,
                    message: "type_list extends past EOF",
                });
            }
            TypeList {
                bytes: &self.physical[p..p + total],
            }
        };

        Ok(ProtoIdItem {
            shorty: StringIdx(shorty),
            return_type: TypeIdx(return_type),
            parameters,
        })
    }

    /// Returns the field's class / type / name.
    pub fn field(&self, idx: FieldIdx) -> Result<FieldIdItem, DexError> {
        let count = self.header.field_ids_size;
        if idx.0 >= count {
            return Err(DexError::IndexOutOfBounds {
                pool: "field_ids",
                idx: idx.0,
                count,
            });
        }
        let off = self.header.field_ids_off as usize + (idx.0 as usize) * 8;
        if off + 8 > self.physical.len() {
            return Err(DexError::OffsetOutOfBounds {
                off,
                file: self.physical.len(),
            });
        }
        let class = crate::read::read_u16(self.physical, off)?;
        let ty = crate::read::read_u16(self.physical, off + 2)?;
        let name = crate::read::read_u32(self.physical, off + 4)?;
        Ok(FieldIdItem {
            class: TypeIdx(class as u32),
            ty: TypeIdx(ty as u32),
            name: StringIdx(name),
        })
    }

    /// Returns the method's class / proto / name.
    pub fn method(&self, idx: MethodIdx) -> Result<MethodIdItem, DexError> {
        let count = self.header.method_ids_size;
        if idx.0 >= count {
            return Err(DexError::IndexOutOfBounds {
                pool: "method_ids",
                idx: idx.0,
                count,
            });
        }
        let off = self.header.method_ids_off as usize + (idx.0 as usize) * 8;
        if off + 8 > self.physical.len() {
            return Err(DexError::OffsetOutOfBounds {
                off,
                file: self.physical.len(),
            });
        }
        let class = crate::read::read_u16(self.physical, off)?;
        let proto = crate::read::read_u16(self.physical, off + 2)?;
        let name = crate::read::read_u32(self.physical, off + 4)?;
        Ok(MethodIdItem {
            class: TypeIdx(class as u32),
            proto: ProtoIdx(proto as u32),
            name: StringIdx(name),
        })
    }

    /// Number of entries in the `call_site_ids` pool (0 on pre-038 DEX).
    pub fn call_site_count(&self) -> u32 {
        self.call_site_pool().map(|(_, c)| c).unwrap_or(0)
    }

    /// Number of entries in the `method_handles` pool (0 on pre-038 DEX).
    pub fn method_handle_count(&self) -> u32 {
        self.method_handle_pool().map(|(_, c)| c).unwrap_or(0)
    }

    /// Returns the encoded-array offset for the given `call_site_id` (DEX 038+).
    pub fn call_site_off(&self, idx: CallSiteIdx) -> Result<u32, DexError> {
        let (off, count) = self.call_site_pool()?;
        if idx.0 >= count {
            return Err(DexError::IndexOutOfBounds {
                pool: "call_site_ids",
                idx: idx.0,
                count,
            });
        }
        let entry = off as usize + (idx.0 as usize) * 4;
        if entry + 4 > self.physical.len() {
            return Err(DexError::OffsetOutOfBounds {
                off: entry,
                file: self.physical.len(),
            });
        }
        crate::read::read_u32(self.physical, entry)
    }

    /// Returns the `method_handle` entry at the given index. DEX 038+ only.
    pub fn method_handle(&self, idx: MethodHandleIdx) -> Result<MethodHandleItem, DexError> {
        let (off, count) = self.method_handle_pool()?;
        if idx.0 >= count {
            return Err(DexError::IndexOutOfBounds {
                pool: "method_handles",
                idx: idx.0,
                count,
            });
        }
        let entry = off as usize + (idx.0 as usize) * 8;
        if entry + 8 > self.physical.len() {
            return Err(DexError::OffsetOutOfBounds {
                off: entry,
                file: self.physical.len(),
            });
        }
        let handle_type = crate::read::read_u16(self.physical, entry)?;
        let field_or_method_idx = crate::read::read_u16(self.physical, entry + 4)?;
        if handle_type <= 5 {
            Ok(MethodHandleItem {
                handle_type,
                target: FieldOrMethod::Field(FieldIdx(field_or_method_idx as u32)),
            })
        } else {
            Ok(MethodHandleItem {
                handle_type,
                target: FieldOrMethod::Method(MethodIdx(field_or_method_idx as u32)),
            })
        }
    }

    // ------------------- low-level helpers (crate-private) -------------------

    /// Reads a string record starting at `off`. Returns
    /// `(utf16_len, payload_start)` where `payload_start` is the byte offset
    /// of the first MUTF-8 byte after the ULEB length.
    pub(crate) fn read_string_record(&self, off: usize) -> Result<(u32, usize), DexError> {
        if off >= self.physical.len() {
            return Err(DexError::OffsetOutOfBounds {
                off,
                file: self.physical.len(),
            });
        }
        let slice = &self.physical[off..];
        let (len, n) = crate::leb::uleb128_to_u32(slice)?;
        Ok((len, off + n))
    }

    /// Returns `(off, count)` for the `call_site_ids` pool (DEX 038+).
    /// Older formats simply have no pool — count is reported as 0.
    fn call_site_pool(&self) -> Result<(u32, u32), DexError> {
        // call_site_ids_size @ 0x70..0x74
        // call_site_ids_off  @ 0x74..0x78
        let end = self
            .header_off
            .checked_add(0x78)
            .ok_or(DexError::InvalidHeader {
                off: self.header_off,
                message: "header_off overflow",
            })?;
        if end > self.physical.len() {
            return Ok((0, 0));
        }
        let base = self.header_off;
        let size = crate::read::read_u32(self.physical, base + 0x70)?;
        let off = crate::read::read_u32(self.physical, base + 0x74)?;
        Ok((off, size))
    }

    /// Returns `(off, count)` for the `method_handles` pool (DEX 038+).
    fn method_handle_pool(&self) -> Result<(u32, u32), DexError> {
        let end = self
            .header_off
            .checked_add(0x80)
            .ok_or(DexError::InvalidHeader {
                off: self.header_off,
                message: "header_off overflow",
            })?;
        if end > self.physical.len() {
            return Ok((0, 0));
        }
        let base = self.header_off;
        let size = crate::read::read_u32(self.physical, base + 0x78)?;
        let off = crate::read::read_u32(self.physical, base + 0x7C)?;
        Ok((off, size))
    }
}

// --------------------- sequential iterators ---------------------

impl<'a> DexView<'a> {
    /// Iterates `(StringIdx, DexStringRef)` over the entire string pool.
    pub fn strings(&self) -> StringIter<'a> {
        let count = self.header.string_ids_size;
        let base = self.header.string_ids_off as usize;
        StringIter {
            physical: self.physical,
            count,
            pool_base: base,
            pos: 0,
        }
    }

    /// Iterates `(TypeIdx, StringIdx)` over the type pool.
    pub fn types(&self) -> TypeIter<'a> {
        TypeIter {
            physical: self.physical,
            count: self.header.type_ids_size,
            base: self.header.type_ids_off as usize,
            pos: 0,
        }
    }

    /// Iterates `(ProtoIdx, ProtoIdItem)` over the proto pool.
    pub fn protos(&self) -> ProtoIter<'a> {
        ProtoIter {
            physical: self.physical,
            count: self.header.proto_ids_size,
            base: self.header.proto_ids_off as usize,
            pos: 0,
        }
    }

    /// Iterates `(FieldIdx, FieldIdItem)`.
    pub fn fields(&self) -> FieldIter<'a> {
        FieldIter {
            physical: self.physical,
            count: self.header.field_ids_size,
            base: self.header.field_ids_off as usize,
            pos: 0,
        }
    }

    /// Iterates `(MethodIdx, MethodIdItem)`.
    pub fn methods(&self) -> MethodIter<'a> {
        MethodIter {
            physical: self.physical,
            count: self.header.method_ids_size,
            base: self.header.method_ids_off as usize,
            pos: 0,
        }
    }
}

/// Iterator over `string_ids`.
pub struct StringIter<'a> {
    physical: &'a [u8],
    count: u32,
    pool_base: usize,
    pos: u32,
}

impl<'a> Iterator for StringIter<'a> {
    type Item = (StringIdx, DexStringRef<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.count {
            return None;
        }
        let idx = StringIdx(self.pos);
        let entry_off = self.pool_base + (self.pos as usize) * 4;
        if entry_off + 4 > self.physical.len() {
            self.pos = self.count;
            return None;
        }
        let data_off = crate::read::read_u32(self.physical, entry_off).unwrap_or(0) as usize;
        let (utf16_len, n) = match crate::leb::uleb128_to_u32(&self.physical[data_off..]) {
            Ok(v) => v,
            Err(_) => {
                self.pos += 1;
                return Some((
                    idx,
                    DexStringRef {
                        utf16_len: 0,
                        mutf8: &[],
                    },
                ));
            }
        };
        let payload_start = data_off + n;
        let payload_end = match crate::mutf8::find_terminator(self.physical, payload_start) {
            Ok(v) => v,
            Err(_) => {
                self.pos += 1;
                return Some((
                    idx,
                    DexStringRef {
                        utf16_len,
                        mutf8: &[],
                    },
                ));
            }
        };
        self.pos += 1;
        Some((
            idx,
            DexStringRef {
                utf16_len,
                mutf8: &self.physical[payload_start..payload_end],
            },
        ))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = (self.count - self.pos) as usize;
        (rem, Some(rem))
    }
}

/// Iterator over `type_ids`.
pub struct TypeIter<'a> {
    physical: &'a [u8],
    count: u32,
    base: usize,
    pos: u32,
}
impl<'a> Iterator for TypeIter<'a> {
    type Item = (TypeIdx, StringIdx);
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.count {
            return None;
        }
        let idx = TypeIdx(self.pos);
        let off = self.base + (self.pos as usize) * 4;
        if off + 4 > self.physical.len() {
            self.pos = self.count;
            return None;
        }
        let descriptor = crate::read::read_u32(self.physical, off).unwrap_or(0);
        self.pos += 1;
        Some((idx, StringIdx(descriptor)))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = (self.count - self.pos) as usize;
        (rem, Some(rem))
    }
}

/// Iterator over `proto_ids`.
pub struct ProtoIter<'a> {
    physical: &'a [u8],
    count: u32,
    base: usize,
    pos: u32,
}
impl<'a> Iterator for ProtoIter<'a> {
    type Item = (ProtoIdx, ProtoIdItem<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.count {
            return None;
        }
        let idx = ProtoIdx(self.pos);
        // Re-implement proto() inline to avoid recursive view borrow.
        let off = self.base + (self.pos as usize) * 12;
        if off + 12 > self.physical.len() {
            self.pos = self.count;
            return None;
        }
        let shorty = crate::read::read_u32(self.physical, off).unwrap_or(0);
        let return_type = crate::read::read_u32(self.physical, off + 4).unwrap_or(0);
        let params_off = crate::read::read_u32(self.physical, off + 8).unwrap_or(0);
        let parameters = if params_off == 0 {
            TypeList { bytes: &[] }
        } else {
            let p = params_off as usize;
            if p + 4 > self.physical.len() {
                self.pos = self.count;
                return None;
            }
            let size = crate::read::read_u32(self.physical, p).unwrap_or(0) as usize;
            let needed = size.saturating_mul(2);
            if needed == usize::MAX || p + 4 + needed > self.physical.len() {
                self.pos = self.count;
                return None;
            }
            TypeList {
                bytes: &self.physical[p..p + 4 + needed],
            }
        };
        self.pos += 1;
        Some((
            idx,
            ProtoIdItem {
                shorty: StringIdx(shorty),
                return_type: TypeIdx(return_type),
                parameters,
            },
        ))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = (self.count - self.pos) as usize;
        (rem, Some(rem))
    }
}

/// Iterator over `field_ids`.
pub struct FieldIter<'a> {
    physical: &'a [u8],
    count: u32,
    base: usize,
    pos: u32,
}
impl<'a> Iterator for FieldIter<'a> {
    type Item = (FieldIdx, FieldIdItem);
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.count {
            return None;
        }
        let idx = FieldIdx(self.pos);
        let off = self.base + (self.pos as usize) * 8;
        if off + 8 > self.physical.len() {
            self.pos = self.count;
            return None;
        }
        let class = crate::read::read_u16(self.physical, off).unwrap_or(0);
        let ty = crate::read::read_u16(self.physical, off + 2).unwrap_or(0);
        let name = crate::read::read_u32(self.physical, off + 4).unwrap_or(0);
        self.pos += 1;
        Some((
            idx,
            FieldIdItem {
                class: TypeIdx(class as u32),
                ty: TypeIdx(ty as u32),
                name: StringIdx(name),
            },
        ))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = (self.count - self.pos) as usize;
        (rem, Some(rem))
    }
}

/// Iterator over `method_ids`.
pub struct MethodIter<'a> {
    physical: &'a [u8],
    count: u32,
    base: usize,
    pos: u32,
}
impl<'a> Iterator for MethodIter<'a> {
    type Item = (MethodIdx, MethodIdItem);
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.count {
            return None;
        }
        let idx = MethodIdx(self.pos);
        let off = self.base + (self.pos as usize) * 8;
        if off + 8 > self.physical.len() {
            self.pos = self.count;
            return None;
        }
        let class = crate::read::read_u16(self.physical, off).unwrap_or(0);
        let proto = crate::read::read_u16(self.physical, off + 2).unwrap_or(0);
        let name = crate::read::read_u32(self.physical, off + 4).unwrap_or(0);
        self.pos += 1;
        Some((
            idx,
            MethodIdItem {
                class: TypeIdx(class as u32),
                proto: ProtoIdx(proto as u32),
                name: StringIdx(name),
            },
        ))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = (self.count - self.pos) as usize;
        (rem, Some(rem))
    }
}

/// Returns `true` when an index means "absent" per the DEX spec.
#[inline]
pub fn is_no_index(idx: u32) -> bool {
    idx == NO_INDEX
}
