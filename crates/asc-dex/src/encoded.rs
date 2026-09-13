//! `encoded_value` / `encoded_array` / `encoded_annotation` parsers and the
//! annotations-directory / annotations-set items.

use crate::error::DexError;
use crate::ids::{FieldIdx, MethodIdx, StringIdx, TypeIdx};
use crate::view::DexView;

/// The type tag of a single encoded value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ValueType {
    Byte = 0x00,
    Short = 0x02,
    Char = 0x03,
    Int = 0x04,
    Long = 0x06,
    Float = 0x10,
    Double = 0x11,
    MethodType = 0x15,
    MethodHandle = 0x16,
    String = 0x17,
    Type = 0x18,
    Field = 0x19,
    Method = 0x1A,
    Enum = 0x1B,
    Array = 0x1C,
    Annotation = 0x1D,
    Null = 0x1E,
    Boolean = 0x1F,
}

impl ValueType {
    pub fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            0x00 => ValueType::Byte,
            0x02 => ValueType::Short,
            0x03 => ValueType::Char,
            0x04 => ValueType::Int,
            0x06 => ValueType::Long,
            0x10 => ValueType::Float,
            0x11 => ValueType::Double,
            0x15 => ValueType::MethodType,
            0x16 => ValueType::MethodHandle,
            0x17 => ValueType::String,
            0x18 => ValueType::Type,
            0x19 => ValueType::Field,
            0x1A => ValueType::Method,
            0x1B => ValueType::Enum,
            0x1C => ValueType::Array,
            0x1D => ValueType::Annotation,
            0x1E => ValueType::Null,
            0x1F => ValueType::Boolean,
            _ => return None,
        })
    }
}

/// A single encoded value with its typed payload. Stored as owned data so
/// the original borrow is decoupled from the parser's stack.
#[derive(Debug, Clone, PartialEq)]
pub enum EncodedValue {
    Byte(i8),
    Short(i16),
    Char(u16),
    Int(i32),
    Long(i64),
    Float(u32),
    Double(u64),
    MethodType(u32),
    MethodHandle(u32),
    String(StringIdx),
    Type(TypeIdx),
    Field(FieldIdx),
    Method(MethodIdx),
    Enum(FieldIdx),
    Array(Vec<EncodedValue>),
    Annotation(EncodedAnnotation),
    Null,
    Boolean(bool),
}

/// A parsed `encoded_annotation`.
#[derive(Debug, Clone, PartialEq)]
pub struct EncodedAnnotation {
    pub type_idx: TypeIdx,
    pub elements: Vec<(StringIdx, EncodedValue)>,
}

/// Maximum allowed recursion depth when parsing arrays/annotations.
pub const MAX_DEPTH: u8 = 64;

impl<'a> DexView<'a> {
    /// Parses an `encoded_value` at `off`, returning the value and the byte
    /// count consumed.
    pub fn encoded_value(
        &self,
        bytes: &'a [u8],
        off: usize,
    ) -> Result<(EncodedValue, usize), DexError> {
        self.encoded_value_depth(bytes, off, 0)
    }

    fn encoded_value_depth(
        &self,
        bytes: &'a [u8],
        off: usize,
        depth: u8,
    ) -> Result<(EncodedValue, usize), DexError> {
        if depth >= MAX_DEPTH {
            return Err(DexError::EncodedValueDepthExceeded { max: MAX_DEPTH });
        }
        if off >= bytes.len() {
            return Err(DexError::Truncated {
                needed: off + 1,
                actual: bytes.len(),
            });
        }
        let header = bytes[off];
        let value_type = header & 0x1F;
        let value_arg = header >> 5;
        let mut p = off + 1;
        let ty = ValueType::from_tag(value_type)
            .ok_or(DexError::Malformed("unknown encoded_value type tag"))?;
        match ty {
            ValueType::Byte => {
                // BYTE is always exactly one payload byte (arg must be 0).
                need(p, 1, bytes.len())?;
                let v = bytes[p] as i8;
                Ok((EncodedValue::Byte(v), p + 1 - off))
            }
            ValueType::Short | ValueType::Int | ValueType::Long => {
                // Signed scalars: (arg+1) payload bytes, sign-extended.
                let width = (value_arg as usize) + 1;
                need(p, width, bytes.len())?;
                let v = sign_extended(bytes, p, width);
                let r = match ty {
                    ValueType::Short => EncodedValue::Short(v as i16),
                    ValueType::Int => EncodedValue::Int(v as i32),
                    _ => EncodedValue::Long(v),
                };
                Ok((r, p + width - off))
            }
            ValueType::Char | ValueType::Float | ValueType::Double => {
                // Zero-extended scalars: (arg+1) payload bytes.
                let width = (value_arg as usize) + 1;
                need(p, width, bytes.len())?;
                let mut v: u64 = 0;
                for i in 0..width {
                    v |= (bytes[p + i] as u64) << (i * 8);
                }
                let r = match ty {
                    ValueType::Char => EncodedValue::Char(v as u16),
                    ValueType::Float => EncodedValue::Float(v as u32),
                    _ => EncodedValue::Double(v),
                };
                Ok((r, p + width - off))
            }
            ValueType::MethodType | ValueType::MethodHandle => {
                let (idx, n) = read_arg_index(bytes, p, value_arg)?;
                let r = if matches!(ty, ValueType::MethodType) {
                    EncodedValue::MethodType(idx)
                } else {
                    EncodedValue::MethodHandle(idx)
                };
                Ok((r, p + n - off))
            }
            ValueType::String => {
                let (idx, n) = read_arg_index(bytes, p, value_arg)?;
                Ok((EncodedValue::String(StringIdx(idx)), p + n - off))
            }
            ValueType::Type => {
                let (idx, n) = read_arg_index(bytes, p, value_arg)?;
                Ok((EncodedValue::Type(TypeIdx(idx)), p + n - off))
            }
            ValueType::Field => {
                let (idx, n) = read_arg_index(bytes, p, value_arg)?;
                Ok((EncodedValue::Field(FieldIdx(idx)), p + n - off))
            }
            ValueType::Method => {
                let (idx, n) = read_arg_index(bytes, p, value_arg)?;
                Ok((EncodedValue::Method(MethodIdx(idx)), p + n - off))
            }
            ValueType::Enum => {
                let (idx, n) = read_arg_index(bytes, p, value_arg)?;
                Ok((EncodedValue::Enum(FieldIdx(idx)), p + n - off))
            }
            ValueType::Array => {
                let (count, n) = crate::leb::uleb128(&bytes[p..])?;
                p += n;
                let mut out = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    let (v, k) = self.encoded_value_depth(bytes, p, depth + 1)?;
                    p += k;
                    out.push(v);
                }
                Ok((EncodedValue::Array(out), p - off))
            }
            ValueType::Annotation => {
                let (type_idx, n) = crate::leb::uleb128(&bytes[p..])?;
                p += n;
                let (count, n) = crate::leb::uleb128(&bytes[p..])?;
                p += n;
                let mut elements = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    let (name_idx, n) = crate::leb::uleb128(&bytes[p..])?;
                    p += n;
                    let (v, k) = self.encoded_value_depth(bytes, p, depth + 1)?;
                    p += k;
                    elements.push((StringIdx(name_idx as u32), v));
                }
                Ok((
                    EncodedValue::Annotation(EncodedAnnotation {
                        type_idx: TypeIdx(type_idx as u32),
                        elements,
                    }),
                    p - off,
                ))
            }
            ValueType::Null => Ok((EncodedValue::Null, 1)),
            ValueType::Boolean => Ok((EncodedValue::Boolean(value_arg != 0), 1)),
        }
    }

    /// Parses an `encoded_array` (used by `class_def.static_values_off`).
    pub fn encoded_array(
        &self,
        bytes: &'a [u8],
        off: usize,
    ) -> Result<(Vec<EncodedValue>, usize), DexError> {
        let (count, n) = crate::leb::uleb128(&bytes[off..])?;
        let mut p = off + n;
        let mut out = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (v, k) = self.encoded_value(bytes, p)?;
            p += k;
            out.push(v);
        }
        Ok((out, p - off))
    }

    /// Parses a `static_values` payload at `off`. Returns `Ok(None)` for `off == 0`.
    pub fn static_values(&self, off: u32) -> Result<Option<Vec<EncodedValue>>, DexError> {
        if off == 0 {
            return Ok(None);
        }
        let p = off as usize;
        let (vals, _) = self.encoded_array(self.physical, p)?;
        Ok(Some(vals))
    }

    /// Parses an `annotation_item` (visibility byte + encoded_annotation)
    /// at `off`. Returns `Ok(None)` for `off == 0`.
    pub fn annotation_item(&self, off: u32) -> Result<Option<AnnotationItem>, DexError> {
        if off == 0 {
            return Ok(None);
        }
        let p = off as usize;
        if p + 1 > self.physical.len() {
            return Err(DexError::OffsetOutOfBounds {
                off: p,
                file: self.physical.len(),
            });
        }
        let visibility = self.physical[p];
        let (ann, _n) = self.encoded_annotation(self.physical, p + 1)?;
        Ok(Some(AnnotationItem {
            visibility,
            annotation: ann,
        }))
    }

    /// Parses an `encoded_annotation` (used by annotation_set / annotation_item).
    pub fn encoded_annotation(
        &self,
        bytes: &'a [u8],
        off: usize,
    ) -> Result<(EncodedAnnotation, usize), DexError> {
        let (type_idx, n) = crate::leb::uleb128(&bytes[off..])?;
        let mut p = off + n;
        let (count, n) = crate::leb::uleb128(&bytes[p..])?;
        p += n;
        let mut elements = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (name_idx, n) = crate::leb::uleb128(&bytes[p..])?;
            p += n;
            let (v, k) = self.encoded_value(bytes, p)?;
            p += k;
            elements.push((StringIdx(name_idx as u32), v));
        }
        Ok((
            EncodedAnnotation {
                type_idx: TypeIdx(type_idx as u32),
                elements,
            },
            p - off,
        ))
    }

    /// Parses an `annotation_set_item` (a `u32` count followed by that many
    /// `u32` annotation_item offsets).
    pub fn annotation_set(&self, off: u32) -> Result<AnnotationSet, DexError> {
        let p = off as usize;
        if p + 4 > self.physical.len() {
            return Err(DexError::OffsetOutOfBounds {
                off: p,
                file: self.physical.len(),
            });
        }
        let size = crate::read::read_u32(self.physical, p)? as usize;
        let needed = size.checked_mul(4).ok_or(DexError::InvalidLength {
            off: p,
            message: "annotation_set size overflow",
        })?;
        if p + 4 + needed > self.physical.len() {
            return Err(DexError::Truncated {
                needed: p + 4 + needed,
                actual: self.physical.len(),
            });
        }
        let mut ann_offs = Vec::with_capacity(size);
        for i in 0..size {
            let q = p + 4 + i * 4;
            let v = crate::read::read_u32(self.physical, q)?;
            ann_offs.push(v);
        }
        Ok(AnnotationSet {
            annotation_offs: ann_offs,
        })
    }

    /// Parses an `annotation_set_ref_list` (a `u32` count followed by that
    /// many `u32` annotation_set_item offsets).
    pub fn annotation_set_ref_list(&self, off: u32) -> Result<AnnotationSetRefList, DexError> {
        let p = off as usize;
        if p + 4 > self.physical.len() {
            return Err(DexError::OffsetOutOfBounds {
                off: p,
                file: self.physical.len(),
            });
        }
        let size = crate::read::read_u32(self.physical, p)? as usize;
        let needed = size.checked_mul(4).ok_or(DexError::InvalidLength {
            off: p,
            message: "annotation_set_ref_list size overflow",
        })?;
        if p + 4 + needed > self.physical.len() {
            return Err(DexError::Truncated {
                needed: p + 4 + needed,
                actual: self.physical.len(),
            });
        }
        let mut set_offs = Vec::with_capacity(size);
        for i in 0..size {
            let q = p + 4 + i * 4;
            let v = crate::read::read_u32(self.physical, q)?;
            set_offs.push(v);
        }
        Ok(AnnotationSetRefList {
            annotation_set_offs: set_offs,
        })
    }

    /// Parses an `annotations_directory_item` at `off`. Returns `Ok(None)`
    /// for `off == 0`.
    pub fn annotations_directory(
        &self,
        off: u32,
    ) -> Result<Option<AnnotationsDirectory>, DexError> {
        if off == 0 {
            return Ok(None);
        }
        let p = off as usize;
        if p + 16 > self.physical.len() {
            return Err(DexError::OffsetOutOfBounds {
                off: p,
                file: self.physical.len(),
            });
        }
        let class_anno_off = crate::read::read_u32(self.physical, p)?;
        let fields_size = crate::read::read_u32(self.physical, p + 4)?;
        let methods_size = crate::read::read_u32(self.physical, p + 8)?;
        let params_size = crate::read::read_u32(self.physical, p + 12)?;

        let mut q = p + 16;
        let mut fields = Vec::with_capacity(fields_size as usize);
        for _ in 0..fields_size {
            if q + 8 > self.physical.len() {
                return Err(DexError::Truncated {
                    needed: q + 8,
                    actual: self.physical.len(),
                });
            }
            let field_idx = crate::read::read_u32(self.physical, q)?;
            let anno_off = crate::read::read_u32(self.physical, q + 4)?;
            fields.push(FieldAnnotation {
                field_idx: crate::ids::FieldIdx(field_idx),
                annotations_off: anno_off,
            });
            q += 8;
        }

        let mut methods = Vec::with_capacity(methods_size as usize);
        for _ in 0..methods_size {
            if q + 8 > self.physical.len() {
                return Err(DexError::Truncated {
                    needed: q + 8,
                    actual: self.physical.len(),
                });
            }
            let method_idx = crate::read::read_u32(self.physical, q)?;
            let anno_off = crate::read::read_u32(self.physical, q + 4)?;
            methods.push(MethodAnnotation {
                method_idx: crate::ids::MethodIdx(method_idx),
                annotations_off: anno_off,
            });
            q += 8;
        }

        let mut params = Vec::with_capacity(params_size as usize);
        for _ in 0..params_size {
            if q + 8 > self.physical.len() {
                return Err(DexError::Truncated {
                    needed: q + 8,
                    actual: self.physical.len(),
                });
            }
            let method_idx = crate::read::read_u32(self.physical, q)?;
            let anno_off = crate::read::read_u32(self.physical, q + 4)?;
            params.push(ParameterAnnotation {
                method_idx: crate::ids::MethodIdx(method_idx),
                annotations_off: anno_off,
            });
            q += 8;
        }

        Ok(Some(AnnotationsDirectory {
            class_annotations_off: class_anno_off,
            fields,
            methods,
            parameters: params,
        }))
    }
}

#[inline]
fn need(p: usize, n: usize, len: usize) -> Result<(), DexError> {
    if p.checked_add(n).map(|e| e > len).unwrap_or(true) {
        return Err(DexError::Truncated {
            needed: p + n,
            actual: len,
        });
    }
    Ok(())
}

/// Reads an arg-extended little-endian index used by `encoded_value` for
/// pool references (string / type / field / method / enum / method-type /
/// method-handle). `arg` is the high 3 bits of the value header and selects
/// the byte width (`arg+1` bytes).
fn read_arg_index(bytes: &[u8], off: usize, arg: u8) -> Result<(u32, usize), DexError> {
    let width = (arg as usize) + 1;
    need(off, width, bytes.len())?;
    let mut idx: u32 = 0;
    for i in 0..width {
        idx |= (bytes[off + i] as u32) << (i * 8);
    }
    Ok((idx, width))
}

/// Parsed `annotation_item`.
#[derive(Debug, Clone, PartialEq)]
pub struct AnnotationItem {
    pub visibility: u8,
    pub annotation: EncodedAnnotation,
}

/// Reads `width` little-endian bytes at `off` and sign-extends the
/// result to `i64` (for the arg-sized signed scalars in
/// `encoded_value`).
fn sign_extended(bytes: &[u8], off: usize, width: usize) -> i64 {
    let mut v: u64 = 0;
    for i in 0..width {
        v |= (bytes[off + i] as u64) << (i * 8);
    }
    let shift = 64 - width * 8;
    ((v << shift) as i64) >> shift
}

/// Parsed `annotation_set_item`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnotationSet {
    pub annotation_offs: Vec<u32>,
}

/// Parsed `annotation_set_ref_list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnotationSetRefList {
    pub annotation_set_offs: Vec<u32>,
}

/// One entry of `annotations_directory.fields`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldAnnotation {
    pub field_idx: crate::ids::FieldIdx,
    pub annotations_off: u32,
}

/// One entry of `annotations_directory.methods`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodAnnotation {
    pub method_idx: crate::ids::MethodIdx,
    pub annotations_off: u32,
}

/// One entry of `annotations_directory.parameters`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParameterAnnotation {
    pub method_idx: crate::ids::MethodIdx,
    pub annotations_off: u32,
}

/// Parsed `annotations_directory_item`.
#[derive(Debug, Clone)]
pub struct AnnotationsDirectory {
    pub class_annotations_off: u32,
    pub fields: Vec<FieldAnnotation>,
    pub methods: Vec<MethodAnnotation>,
    pub parameters: Vec<ParameterAnnotation>,
}
