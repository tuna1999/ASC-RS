//! Typed DEX pool indexes — shared contract across ASC-RS crates.
//!
//! Subsystems pass these instead of raw `u32` across API boundaries.
//! The inner `u32` is deliberately public (no getter ceremony); all types are
//! `#[repr(transparent)]`, so the ABI is identical to `u32`.
//!
//! This file is a frozen contract seeded by the Lead agent: crates may
//! consume it, but must not rename or remove existing items.

/// Sentinel used by the DEX format for "absent index" (e.g. no superclass).
pub const NO_INDEX: u32 = 0xFFFF_FFFF;

/// Index into `string_ids`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct StringIdx(pub u32);

/// Index into `type_ids`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct TypeIdx(pub u32);

/// Index into `proto_ids`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct ProtoIdx(pub u32);

/// Index into `field_ids`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct FieldIdx(pub u32);

/// Index into `method_ids`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct MethodIdx(pub u32);

/// Index into `call_site_ids` (DEX 038+).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct CallSiteIdx(pub u32);

/// Index into `method_handles` (DEX 038+).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct MethodHandleIdx(pub u32);
