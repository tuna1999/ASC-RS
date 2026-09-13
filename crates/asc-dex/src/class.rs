//! `class_def_item` and `class_data_item` accessors.
//!
//! Class definitions carry fixed-size pointers to interface lists,
//! annotations, class-data, and static values. `class_data` is parsed
//! lazily on demand and yields uleb-encoded field/method lists with
//! cumulative index decoding.

use crate::error::DexError;
use crate::ids::{FieldIdx, MethodIdx, NO_INDEX, StringIdx, TypeIdx};
use crate::pools::TypeList;
use crate::view::DexView;

/// A `class_def_item` row, copied out of the physical buffer.
#[derive(Debug, Clone, Copy)]
pub struct ClassDef {
    pub class: TypeIdx,
    pub access_flags: u32,
    pub superclass: Option<TypeIdx>,
    pub interfaces_off: u32,
    pub source_file: Option<StringIdx>,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

impl<'a> DexView<'a> {
    /// Returns the `i`-th class-def.
    pub fn class_def(&self, i: u32) -> Result<ClassDef, DexError> {
        let count = self.header.class_defs_size;
        if i >= count {
            return Err(DexError::IndexOutOfBounds {
                pool: "class_defs",
                idx: i,
                count,
            });
        }
        let off = self.header.class_defs_off as usize + (i as usize) * 32;
        if off + 32 > self.physical.len() {
            return Err(DexError::OffsetOutOfBounds {
                off,
                file: self.physical.len(),
            });
        }
        let class_idx = crate::read::read_u32(self.physical, off)?;
        let access = crate::read::read_u32(self.physical, off + 4)?;
        let super_idx = crate::read::read_u32(self.physical, off + 8)?;
        let ifs_off = crate::read::read_u32(self.physical, off + 12)?;
        let src_idx = crate::read::read_u32(self.physical, off + 16)?;
        let anno_off = crate::read::read_u32(self.physical, off + 20)?;
        let data_off = crate::read::read_u32(self.physical, off + 24)?;
        let static_off = crate::read::read_u32(self.physical, off + 28)?;

        Ok(ClassDef {
            class: TypeIdx(class_idx),
            access_flags: access,
            superclass: (super_idx != NO_INDEX).then_some(TypeIdx(super_idx)),
            interfaces_off: ifs_off,
            source_file: (src_idx != NO_INDEX).then_some(StringIdx(src_idx)),
            annotations_off: anno_off,
            class_data_off: data_off,
            static_values_off: static_off,
        })
    }

    /// Returns the `type_list` view for `class_def.interfaces_off`. Returns
    /// `Ok(None)` when the offset is zero.
    pub fn class_interfaces(
        &self,
        def: &ClassDef,
    ) -> Result<Option<TypeList<'a>>, DexError> {
        if def.interfaces_off == 0 {
            return Ok(None);
        }
        let p = def.interfaces_off as usize;
        if p + 4 > self.physical.len() {
            return Err(DexError::OffsetOutOfBounds {
                off: p,
                file: self.physical.len(),
            });
        }
        let size = crate::read::read_u32(self.physical, p)? as usize;
        let needed = size.checked_mul(2).ok_or(DexError::InvalidLength {
            off: p,
            message: "interfaces size overflow",
        })?;
        let total = 4 + needed;
        if p + total > self.physical.len() {
            return Err(DexError::InvalidLength {
                off: p,
                message: "interfaces extends past EOF",
            });
        }
        Ok(Some(TypeList {
            bytes: crate::read::slice(self.physical, p, total)?,
        }))
    }

    /// Parses `class_data_item` at `off`. Returns `Ok(None)` for `off == 0`.
    /// On error, returns the `DexError` produced during scanning.
    pub fn class_data(&self, off: u32) -> Result<Option<ClassData>, DexError> {
        if off == 0 {
            return Ok(None);
        }
        let p = off as usize;
        if p >= self.physical.len() {
            return Err(DexError::OffsetOutOfBounds {
                off: p,
                file: self.physical.len(),
            });
        }
        let mut slice = &self.physical[p..];

        let (static_fields_size, n) = crate::leb::uleb128_to_u32(slice)?;
        slice = &slice[n..];
        let (instance_fields_size, n) = crate::leb::uleb128_to_u32(slice)?;
        slice = &slice[n..];
        let (direct_methods_size, n) = crate::leb::uleb128_to_u32(slice)?;
        slice = &slice[n..];
        let (virtual_methods_size, n) = crate::leb::uleb128_to_u32(slice)?;
        slice = &slice[n..];

        const MAX_LIST: u32 = 1 << 20;
        if static_fields_size > MAX_LIST
            || instance_fields_size > MAX_LIST
            || direct_methods_size > MAX_LIST
            || virtual_methods_size > MAX_LIST
        {
            return Err(DexError::InvalidLength {
                off: p,
                message: "class_data list size exceeds cap",
            });
        }

        let total = (static_fields_size
            + instance_fields_size
            + direct_methods_size
            + virtual_methods_size) as usize;

        // 3 ulebs per field, 4 ulebs per method (idx, access, code_off).
        let estimated = total.saturating_mul(8);
        if estimated > slice.len() {
            return Err(DexError::Truncated {
                needed: estimated,
                actual: slice.len(),
            });
        }

        let mut static_fields = Vec::with_capacity(static_fields_size as usize);
        let mut last_idx: u32 = 0;
        for i in 0..static_fields_size {
            let (delta, n) = crate::leb::uleb128_to_u32(slice)?;
            slice = &slice[n..];
            last_idx = last_idx.checked_add(delta).ok_or(
                DexError::ClassDataDeltaOverflow { off: p },
            )?;
            let (access, n) = crate::leb::uleb128_to_u32(slice)?;
            slice = &slice[n..];
            static_fields.push(EncodedField {
                field_idx: FieldIdx(last_idx),
                access_flags: access,
                ordinal: i,
            });
        }

        let mut instance_fields = Vec::with_capacity(instance_fields_size as usize);
        last_idx = 0;
        for i in 0..instance_fields_size {
            let (delta, n) = crate::leb::uleb128_to_u32(slice)?;
            slice = &slice[n..];
            last_idx = last_idx.checked_add(delta).ok_or(
                DexError::ClassDataDeltaOverflow { off: p },
            )?;
            let (access, n) = crate::leb::uleb128_to_u32(slice)?;
            slice = &slice[n..];
            instance_fields.push(EncodedField {
                field_idx: FieldIdx(last_idx),
                access_flags: access,
                ordinal: i,
            });
        }

        let mut direct_methods = Vec::with_capacity(direct_methods_size as usize);
        last_idx = 0;
        for i in 0..direct_methods_size {
            let (delta, n) = crate::leb::uleb128_to_u32(slice)?;
            slice = &slice[n..];
            last_idx = last_idx.checked_add(delta).ok_or(
                DexError::ClassDataDeltaOverflow { off: p },
            )?;
            let (access, n) = crate::leb::uleb128_to_u32(slice)?;
            slice = &slice[n..];
            let (code_off, n) = crate::leb::uleb128_to_u32(slice)?;
            slice = &slice[n..];
            direct_methods.push(EncodedMethod {
                method_idx: MethodIdx(last_idx),
                access_flags: access,
                code_off,
                ordinal: i,
            });
        }

        let mut virtual_methods = Vec::with_capacity(virtual_methods_size as usize);
        last_idx = 0;
        for i in 0..virtual_methods_size {
            let (delta, n) = crate::leb::uleb128_to_u32(slice)?;
            slice = &slice[n..];
            last_idx = last_idx.checked_add(delta).ok_or(
                DexError::ClassDataDeltaOverflow { off: p },
            )?;
            let (access, n) = crate::leb::uleb128_to_u32(slice)?;
            slice = &slice[n..];
            let (code_off, n) = crate::leb::uleb128_to_u32(slice)?;
            slice = &slice[n..];
            virtual_methods.push(EncodedMethod {
                method_idx: MethodIdx(last_idx),
                access_flags: access,
                code_off,
                ordinal: i,
            });
        }

        Ok(Some(ClassData {
            static_fields,
            instance_fields,
            direct_methods,
            virtual_methods,
        }))
    }
}

/// An encoded field entry inside `class_data_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedField {
    pub field_idx: FieldIdx,
    pub access_flags: u32,
    /// Zero-based ordinal within its list.
    pub ordinal: u32,
}

/// An encoded method entry inside `class_data_item`. `code_off == 0`
/// indicates an abstract or native method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedMethod {
    pub method_idx: MethodIdx,
    pub access_flags: u32,
    pub code_off: u32,
    pub ordinal: u32,
}

/// Parsed `class_data_item`.
#[derive(Debug, Clone)]
pub struct ClassData {
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}