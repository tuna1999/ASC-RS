//! Pool item records behind the `DexView` accessors.
//!
//! The records borrow the physical buffer the `DexView` was built from and
//! interpret every offset absolutely. Nothing here allocates during a
//! pool-wide scan; a per-item read allocates only when the caller asks for a
//! lossy decode.

use crate::error::DexError;
use crate::ids::{FieldIdx, MethodIdx, ProtoIdx, StringIdx, TypeIdx};
use crate::mutf8;

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
