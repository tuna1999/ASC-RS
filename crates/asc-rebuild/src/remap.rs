//! Old-to-new index maps for the rebuilt DEX pools.
//!
//! Strategy:
//!
//! 1. For each pool, the closure collected a sorted `BTreeSet<u32>` of
//!    selected old indices.
//! 2. We walk the set in ascending order and assign new indices
//!    `0..count`. New index = rank in the source order (NOT encounter
//!    order), which keeps the rebuilt DEX stable and matches the
//!    reference oracle's behavior.
//! 3. The map stores `Vec<Option<u32>>` of length `old_count`; `None`
//!    means the index was dropped, `Some(new_idx)` means it's mapped.

use crate::error::RebuildError;
use std::marker::PhantomData;

/// Old-to-new lookup table for a single pool.
///
/// `inner.len() == source_pool_size`. `inner[i] == None` ⇒ index `i` was
/// not selected; `Some(new_idx)` ⇒ the new index assigned in the rebuilt
/// DEX (where `new_idx` is the rank of `i` among the selected indices).
pub(crate) struct IndexMap<I> {
    pub(crate) inner: Vec<Option<u32>>,
    count: u32,
    _kind: PhantomData<I>,
}

impl<I> IndexMap<I> {
    /// Builds an `IndexMap` from a `BTreeSet<u32>` of selected old
    /// indices. The map's backing `Vec` is sized to `old_count`.
    pub(crate) fn build(selected: &std::collections::BTreeSet<u32>, old_count: u32) -> Self {
        let mut inner: Vec<Option<u32>> = vec![None; old_count as usize];
        for (rank, &old) in selected.iter().enumerate() {
            inner[old as usize] = Some(rank as u32);
        }
        Self {
            inner,
            count: selected.len() as u32,
            _kind: PhantomData,
        }
    }

    /// Builds a map from an explicit output order: entry `rank` is
    /// `Some(old)` for a source index, `None` for a slot with no source
    /// counterpart (a string synthesized by a patch).
    pub(crate) fn from_order(order: impl Iterator<Item = Option<u32>>, old_count: u32) -> Self {
        let mut inner: Vec<Option<u32>> = vec![None; old_count as usize];
        let mut count = 0;
        for (rank, old) in order.enumerate() {
            if let Some(old) = old {
                inner[old as usize] = Some(rank as u32);
            }
            count += 1;
        }
        Self {
            inner,
            count,
            _kind: PhantomData,
        }
    }

    #[inline]
    pub(crate) fn len(&self) -> u32 {
        self.count
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub(crate) fn lookup(&self, old: u32) -> Result<u32, RebuildError> {
        match self.inner.get(old as usize) {
            Some(Some(n)) => Ok(*n),
            Some(None) => Err(RebuildError::Internal(
                "referenced index was not selected (pool lookup miss)",
            )),
            None => Err(RebuildError::Internal(
                "index out of bounds (pool lookup overflow)",
            )),
        }
    }

    /// Like `lookup` but tolerant: returns 0 on miss.
    #[allow(dead_code)]
    #[inline]
    pub(crate) fn lookup_or_zero(&self, old: u32) -> u32 {
        self.inner.get(old as usize).and_then(|x| *x).unwrap_or(0)
    }

    /// Returns the old-index value at a given new-index rank.
    /// Used by the layout pass to iterate pool entries in rank order.
    pub(crate) fn old_for_rank(&self, rank: u32) -> Option<u32> {
        self.inner
            .iter()
            .position(|opt| matches!(opt, Some(n) if *n == rank))
            .map(|p| p as u32)
    }
}

/// All seven pool maps for one rebuild.
pub(crate) struct PoolMaps {
    pub strings: IndexMap<asc_dex::StringIdx>,
    pub types: IndexMap<asc_dex::TypeIdx>,
    pub protos: IndexMap<asc_dex::ProtoIdx>,
    pub fields: IndexMap<asc_dex::FieldIdx>,
    pub methods: IndexMap<asc_dex::MethodIdx>,
    pub call_sites: IndexMap<asc_dex::CallSiteIdx>,
    pub method_handles: IndexMap<asc_dex::MethodHandleIdx>,
}

impl PoolMaps {
    pub(crate) fn build(closure: &crate::closure::Closure, view: &asc_dex::DexView<'_>) -> Self {
        Self {
            strings: IndexMap::build(&closure.strings, view.string_count()),
            types: IndexMap::build(&closure.types, view.type_count()),
            protos: IndexMap::build(&closure.protos, view.proto_count()),
            fields: IndexMap::build(&closure.fields, view.field_count()),
            methods: IndexMap::build(&closure.methods, view.method_count()),
            call_sites: IndexMap::build(&closure.call_sites, view.call_site_count()),
            method_handles: IndexMap::build(&closure.method_handles, view.method_handle_count()),
        }
    }
}
