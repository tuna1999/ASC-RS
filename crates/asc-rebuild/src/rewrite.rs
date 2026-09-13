//! In-place rewriting of pool-reference slots in payload bytes.
//!
//! Two families of payloads need rewriting:
//!
//! 1. **Bytecode** (`code_item.insns`): every reference slot is fixed at
//!    a known code-unit offset inside the instruction; we patch the
//!    16-bit or 32-bit little-endian index in place using the slot
//!    metadata from `asc_bytecode::opcode_info`.
//!
//! 2. **ULEB-encoded payloads** (catch handlers, debug_info, encoded
//!    values, annotation element names): each pool-ref uleb is re-encoded
//!    at its existing position so surrounding ulebs keep their alignment.
//!    When the encoded width changes the whole sub-record's bytes shift;
//!    we therefore re-emit the full sub-record, not patch in place.
//!
//! For code items we patch the insns buffer in place and only re-emit
//! the catch-handler-list when its width changed.

use crate::closure::Closure;
use crate::error::RebuildError;
use crate::remap::PoolMaps;
use crate::util::{ULEB_MAX_BYTES, write_sleb128_to, write_uleb128_to};

use asc_bytecode::{DexRef, RefWalker};
use asc_dex::{CatchHandler, DexView, EncodedValue, ValueType};

/// Rewrites every reference slot inside the `insns` buffer in place.
///
/// The closure records `insns_units` so we re-construct the `RefWalker`
/// (which validates `insns.len() == insns_units * 2`) and patch each
/// reported `RefInstruction` at `(instr.offset + slot.unit_off) * 2`.
///
/// This function does NOT touch opcode widths, payload pseudo-instructions,
/// or register slots — only the pool-reference operands.
pub(crate) fn rewrite_bytecode(
    insns: &mut [u8],
    insns_units: u32,
    maps: &PoolMaps,
) -> Result<(), RebuildError> {
    let walker = RefWalker::new(insns, insns_units).map_err(|e| RebuildError::BytecodeRef {
        off: 0,
        message: format!("RefWalker::new: {e:?}"),
    })?;
    // Collect the hits first (the walker borrows insns).
    let mut hits = Vec::new();
    for hit in walker {
        let hit = hit.map_err(|e| RebuildError::BytecodeRef {
            off: 0,
            message: format!("walk: {e:?}"),
        })?;
        hits.push(hit);
    }
    for hit in hits {
        if let Some(r) = hit.primary {
            patch_ref(insns, hit.offset, &r, true, maps)?;
        }
        if let Some(r) = hit.secondary {
            patch_ref(insns, hit.offset, &r, false, maps)?;
        }
    }
    Ok(())
}

/// Patches a single 16-bit or 32-bit slot. `is_primary` selects which
/// slot of the instruction (primary vs secondary) the ref belongs to.
fn patch_ref(
    insns: &mut [u8],
    instr_off_units: u32,
    r: &DexRef,
    is_primary: bool,
    maps: &PoolMaps,
) -> Result<(), RebuildError> {
    use asc_bytecode::{RefKind, opcode_info};
    let opcode = insns[(instr_off_units as usize) * 2];
    let info = opcode_info(opcode);
    let slot = if is_primary {
        info.primary.map(|(s, _)| s)
    } else {
        info.secondary.map(|(s, _)| s)
    };
    let Some(slot) = slot else {
        return Err(RebuildError::Internal(
            "ref kind doesn't match the chosen slot",
        ));
    };
    let want = match r {
        DexRef::String(_) => RefKind::String,
        DexRef::Type(_) => RefKind::Type,
        DexRef::Field(_) => RefKind::Field,
        DexRef::Method(_) => RefKind::Method,
        DexRef::Proto(_) => RefKind::Proto,
        DexRef::CallSite(_) => RefKind::CallSite,
        DexRef::MethodHandle(_) => RefKind::MethodHandle,
    };
    let slot_kind = if is_primary {
        info.primary.map(|(_, k)| k)
    } else {
        info.secondary.map(|(_, k)| k)
    };
    if slot_kind != Some(want) {
        return Err(RebuildError::Internal("ref kind doesn't match slot kind"));
    }
    let byte_off = ((instr_off_units + slot.unit_off as u32) as usize) * 2;
    let new_idx = match r {
        DexRef::String(s) => maps.strings.lookup(s.0)?,
        DexRef::Type(t) => maps.types.lookup(t.0)?,
        DexRef::Field(f) => maps.fields.lookup(f.0)?,
        DexRef::Method(m) => maps.methods.lookup(m.0)?,
        DexRef::Proto(p) => maps.protos.lookup(p.0)?,
        DexRef::CallSite(c) => maps.call_sites.lookup(c.0)?,
        DexRef::MethodHandle(mh) => maps.method_handles.lookup(mh.0)?,
    };
    if slot.bits == 16 {
        let bytes = (new_idx as u16).to_le_bytes();
        insns[byte_off] = bytes[0];
        insns[byte_off + 1] = bytes[1];
    } else {
        // 32-bit jumbo slot (const-string/jumbo only).
        let bytes = new_idx.to_le_bytes();
        insns[byte_off] = bytes[0];
        insns[byte_off + 1] = bytes[1];
        insns[byte_off + 2] = bytes[2];
        insns[byte_off + 3] = bytes[3];
    }
    Ok(())
}

/// Re-encoded `encoded_catch_handler_list`.
pub(crate) struct ReencodedCatchList {
    pub raw: Vec<u8>,
    /// `(orig_byte_off, new_byte_off)` per handler entry. `orig_byte_off`
    /// matches `try_item.handler_off` values in the SOURCE code item;
    /// `new_byte_off` is the handler's offset inside `raw`.
    pub offset_map: Vec<(u32, u32)>,
}

pub(crate) fn rewrite_catch_handler_list(
    view: &DexView<'_>,
    code: &asc_dex::CodeItem<'_>,
    maps: &PoolMaps,
) -> Result<ReencodedCatchList, RebuildError> {
    let Some(list) = view.catch_handler_list(code)? else {
        return Ok(ReencodedCatchList {
            raw: Vec::new(),
            offset_map: Vec::new(),
        });
    };
    let handlers: Vec<CatchHandler> = list.iter_all()?;
    let orig_offsets = list.handler_offsets()?;
    let mut out: Vec<u8> = Vec::new();
    // uleb128 entry count — the count is known before any entry bytes.
    write_uleb128_to(&mut out, handlers.len() as u64, ULEB_MAX_BYTES)?;
    let mut new_offsets = Vec::with_capacity(handlers.len());
    for h in &handlers {
        new_offsets.push(out.len() as u32);
        let size_signed: i64 = if h.catch_all_addr.is_some() {
            -(h.pairs.len() as i64)
        } else {
            h.pairs.len() as i64
        };
        write_sleb128_to(&mut out, size_signed);
        for (t, a) in &h.pairs {
            let new_t = maps.types.lookup(*t)?;
            write_uleb128_to(&mut out, new_t as u64, ULEB_MAX_BYTES)?;
            write_uleb128_to(&mut out, *a as u64, ULEB_MAX_BYTES)?;
        }
        if let Some(a) = h.catch_all_addr {
            write_uleb128_to(&mut out, a as u64, ULEB_MAX_BYTES)?;
        }
    }
    let offset_map = orig_offsets
        .into_iter()
        .zip(new_offsets)
        .collect::<Vec<_>>();
    Ok(ReencodedCatchList {
        raw: out,
        offset_map,
    })
}

/// Re-encodes a `debug_info_item` payload using the new string / type
/// indices.
pub(crate) fn rewrite_debug_info(raw: &[u8], maps: &PoolMaps) -> Result<Vec<u8>, RebuildError> {
    let mut p = 0usize;
    let (line_start, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
    p += n;
    let (params_size, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
    p += n;
    let mut param_names: Vec<Option<u32>> = Vec::with_capacity(params_size as usize);
    for _ in 0..params_size {
        let (v, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
        p += n;
        if v == 0 {
            param_names.push(None);
        } else {
            param_names.push(Some(v));
        }
    }
    let mut out: Vec<u8> = Vec::with_capacity(raw.len());
    write_uleb128_to(&mut out, line_start as u64, crate::util::ULEB_GENERIC_MAX)?;
    write_uleb128_to(&mut out, params_size as u64, crate::util::ULEB_GENERIC_MAX)?;
    for opt in &param_names {
        // Parameter names are uleb128p1: 0 = absent, v>0 references
        // string index (v - 1). The closure collects the DECODED index
        // (via asc-dex's typed view), so look up v-1 and re-emit new+1.
        match opt {
            None => out.push(0),
            Some(old) => {
                let new = maps.strings.lookup(old - 1)?;
                write_uleb128_to(&mut out, (new as u64) + 1, crate::util::ULEB_GENERIC_MAX)?;
            }
        }
    }

    while p < raw.len() {
        let op = raw[p];
        p += 1;
        match op {
            asc_dex::DBG_END_SEQUENCE => {
                out.push(op);
                break;
            }
            asc_dex::DBG_ADVANCE_PC => {
                let (v, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
                p += n;
                out.push(op);
                write_uleb128_to(&mut out, v as u64, crate::util::ULEB_GENERIC_MAX)?;
            }
            asc_dex::DBG_ADVANCE_LINE => {
                let (v, n) = asc_dex::leb::sleb128_to_i32(&raw[p..])?;
                p += n;
                out.push(op);
                let mut buf = [0u8; 5];
                let m = write_sleb128_to_bytes(v, &mut buf);
                out.extend_from_slice(&buf[..m]);
            }
            asc_dex::DBG_START_LOCAL => {
                let (reg, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
                p += n;
                let (name, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
                p += n;
                let (ty, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
                p += n;
                out.push(op);
                write_uleb128_to(&mut out, reg as u64, crate::util::ULEB_GENERIC_MAX)?;
                write_p1_string(&mut out, name, maps)?;
                write_p1_type(&mut out, ty, maps)?;
            }
            asc_dex::DBG_START_LOCAL_EXTENDED => {
                let (reg, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
                p += n;
                let (name, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
                p += n;
                let (ty, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
                p += n;
                let (sig, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
                p += n;
                out.push(op);
                write_uleb128_to(&mut out, reg as u64, crate::util::ULEB_GENERIC_MAX)?;
                write_p1_string(&mut out, name, maps)?;
                write_p1_type(&mut out, ty, maps)?;
                write_p1_string(&mut out, sig, maps)?;
            }
            asc_dex::DBG_END_LOCAL | asc_dex::DBG_RESTART_LOCAL => {
                let (v, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
                p += n;
                out.push(op);
                write_uleb128_to(&mut out, v as u64, crate::util::ULEB_GENERIC_MAX)?;
            }
            asc_dex::DBG_SET_PROLOGUE_END | asc_dex::DBG_SET_EPILOGUE_BEGIN => {
                out.push(op);
            }
            asc_dex::DBG_SET_FILE => {
                let (v, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
                p += n;
                out.push(op);
                write_p1_string(&mut out, v, maps)?;
            }
            op if op >= 0x0a => {
                out.push(op);
            }
            _ => {
                return Err(RebuildError::Internal(
                    "unknown debug opcode during rewrite",
                ));
            }
        }
    }
    Ok(out)
}

/// Writes `value` (SLEB128) into `buf`, returning the byte count used.
fn write_sleb128_to_bytes(value: i32, buf: &mut [u8; 5]) -> usize {
    let mut v: i64 = value as i64;
    let mut more = true;
    let mut i = 0usize;
    while more {
        let byte = (v as u8) & 0x7F;
        v >>= 7;
        if (v == 0 && (byte & 0x40) == 0) || (v == -1 && (byte & 0x40) != 0) {
            buf[i] = byte;
            more = false;
        } else {
            buf[i] = byte | 0x80;
        }
        i += 1;
    }
    i
}

fn write_p1_string(out: &mut Vec<u8>, v: u32, maps: &PoolMaps) -> Result<(), RebuildError> {
    if v == 0 {
        out.push(0);
    } else {
        let new = maps.strings.lookup(v - 1)?;
        write_uleb128_to(out, (new as u64) + 1, crate::util::ULEB_GENERIC_MAX)?;
    }
    Ok(())
}

fn write_p1_type(out: &mut Vec<u8>, v: u32, maps: &PoolMaps) -> Result<(), RebuildError> {
    if v == 0 {
        out.push(0);
    } else {
        let new = maps.types.lookup(v - 1)?;
        write_uleb128_to(out, (new as u64) + 1, crate::util::ULEB_GENERIC_MAX)?;
    }
    Ok(())
}

/// Re-encodes an `encoded_value` payload, rewriting every pool-ref slot.
pub(crate) fn rewrite_encoded_value(
    v: &EncodedValue,
    out: &mut Vec<u8>,
    maps: &PoolMaps,
    depth: u8,
) -> Result<(), RebuildError> {
    if depth >= asc_dex::ENCODED_VALUE_MAX_DEPTH {
        return Err(RebuildError::EncodedValueDepth {
            off: 0,
            max: asc_dex::ENCODED_VALUE_MAX_DEPTH,
        });
    }
    let (tag_byte, arg): (u8, u8) = match v {
        EncodedValue::Byte(_) => (ValueType::Byte as u8, 0u8),
        EncodedValue::Short(_) => (ValueType::Short as u8, 0u8),
        EncodedValue::Char(_) => (ValueType::Char as u8, 0u8),
        EncodedValue::Int(_) => (ValueType::Int as u8, 0u8),
        EncodedValue::Long(_) => (ValueType::Long as u8, 0u8),
        EncodedValue::Float(_) => (ValueType::Float as u8, 0u8),
        EncodedValue::Double(_) => (ValueType::Double as u8, 0u8),
        EncodedValue::MethodType(_) => (ValueType::MethodType as u8, 0u8),
        EncodedValue::MethodHandle(_) => (ValueType::MethodHandle as u8, 0u8),
        EncodedValue::String(_) => (ValueType::String as u8, 0u8),
        EncodedValue::Type(_) => (ValueType::Type as u8, 0u8),
        EncodedValue::Field(_) => (ValueType::Field as u8, 0u8),
        EncodedValue::Method(_) => (ValueType::Method as u8, 0u8),
        EncodedValue::Enum(_) => (ValueType::Enum as u8, 0u8),
        EncodedValue::Array(_) => (ValueType::Array as u8, 0u8),
        EncodedValue::Annotation(_) => (ValueType::Annotation as u8, 0u8),
        EncodedValue::Null => (ValueType::Null as u8, 0u8),
        EncodedValue::Boolean(b) => (ValueType::Boolean as u8, u8::from(*b)),
    };
    out.push(tag_byte | (arg << 5));
    match v {
        EncodedValue::Byte(x) => out.push(*x as u8),
        EncodedValue::Short(x) => out.extend_from_slice(&x.to_le_bytes()),
        EncodedValue::Char(x) => out.extend_from_slice(&x.to_le_bytes()),
        EncodedValue::Int(x) => out.extend_from_slice(&x.to_le_bytes()),
        EncodedValue::Long(x) => out.extend_from_slice(&x.to_le_bytes()),
        EncodedValue::Float(x) => out.extend_from_slice(&x.to_le_bytes()),
        EncodedValue::Double(x) => out.extend_from_slice(&x.to_le_bytes()),
        EncodedValue::MethodType(_) | EncodedValue::MethodHandle(_) => {
            // MethodType → proto, MethodHandle → method_handles.
            let idx = match v {
                EncodedValue::MethodType(idx) => {
                    if *idx == u32::MAX {
                        0
                    } else {
                        maps.protos.lookup(*idx)?
                    }
                }
                EncodedValue::MethodHandle(idx) => {
                    if *idx == u32::MAX {
                        0
                    } else {
                        maps.method_handles.lookup(*idx)?
                    }
                }
                _ => {
                    return Err(RebuildError::Internal(
                        "encoded value arm mismatch (method type/handle)",
                    ));
                }
            };
            let new_arg = arg_for_index(idx);
            let last = out.len() - 1;
            out[last] = tag_byte | (new_arg << 5);
            write_index(out, idx, new_arg)?;
        }
        EncodedValue::String(s) => {
            let new = maps.strings.lookup(s.0)?;
            let new_arg = arg_for_index(new);
            let last = out.len() - 1;
            out[last] = tag_byte | (new_arg << 5);
            write_index(out, new, new_arg)?;
        }
        EncodedValue::Type(t) => {
            let new = maps.types.lookup(t.0)?;
            let new_arg = arg_for_index(new);
            let last = out.len() - 1;
            out[last] = tag_byte | (new_arg << 5);
            write_index(out, new, new_arg)?;
        }
        EncodedValue::Field(f) => {
            let new = maps.fields.lookup(f.0)?;
            let new_arg = arg_for_index(new);
            let last = out.len() - 1;
            out[last] = tag_byte | (new_arg << 5);
            write_index(out, new, new_arg)?;
        }
        EncodedValue::Method(m) => {
            let new = maps.methods.lookup(m.0)?;
            let new_arg = arg_for_index(new);
            let last = out.len() - 1;
            out[last] = tag_byte | (new_arg << 5);
            write_index(out, new, new_arg)?;
        }
        EncodedValue::Enum(f) => {
            let new = maps.fields.lookup(f.0)?;
            let new_arg = arg_for_index(new);
            let last = out.len() - 1;
            out[last] = tag_byte | (new_arg << 5);
            write_index(out, new, new_arg)?;
        }
        EncodedValue::Array(items) => {
            write_uleb128_to(out, items.len() as u64, crate::util::ULEB_GENERIC_MAX)?;
            for item in items {
                rewrite_encoded_value(item, out, maps, depth + 1)?;
            }
        }
        EncodedValue::Annotation(ann) => {
            let new_ty = maps.types.lookup(ann.type_idx.0)?;
            write_uleb128_to(out, new_ty as u64, crate::util::ULEB_GENERIC_MAX)?;
            write_uleb128_to(
                out,
                ann.elements.len() as u64,
                crate::util::ULEB_GENERIC_MAX,
            )?;
            for (name, v) in &ann.elements {
                let new_name = maps.strings.lookup(name.0)?;
                write_uleb128_to(out, new_name as u64, crate::util::ULEB_GENERIC_MAX)?;
                rewrite_encoded_value(v, out, maps, depth + 1)?;
            }
        }
        EncodedValue::Null | EncodedValue::Boolean(_) => {}
    }
    Ok(())
}

/// Returns the smallest `arg` (0..=3) whose byte width covers `idx`.
fn arg_for_index(idx: u32) -> u8 {
    if idx <= 0xFF {
        0
    } else if idx <= 0xFFFF {
        1
    } else if idx <= 0xFFFFFF {
        2
    } else {
        3
    }
}

/// Writes a pool-index using the arg-selected byte width (1..=4 bytes,
/// little-endian, no continuation bit — exactly what `encoded_value`
/// uses; not a uleb128).
fn write_index(out: &mut Vec<u8>, idx: u32, arg: u8) -> Result<(), RebuildError> {
    let bytes = match arg {
        0 => 1usize,
        1 => 2,
        2 => 3,
        3 => 4,
        _ => return Err(RebuildError::Internal("encoded_value arg > 3")),
    };
    let bytes_arr = idx.to_le_bytes();
    out.extend_from_slice(&bytes_arr[..bytes]);
    Ok(())
}

/// Re-encodes a `class_data_item` body. `code_offs` is a per-method list
/// (direct + virtual) carrying the NEW code-item offsets (or 0 for
/// abstract/native methods). The caller computes them after laying out
/// the rest of the DEX.
pub(crate) fn rewrite_class_data(
    raw: &[u8],
    closure: &Closure,
    maps: &PoolMaps,
    code_offs: &[u32],
) -> Result<Vec<u8>, RebuildError> {
    let mut p = 0usize;
    let (static_n, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
    p += n;
    let (instance_n, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
    p += n;
    let (direct_n, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
    p += n;
    let (virtual_n, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
    p += n;

    let mut new_raw: Vec<u8> = Vec::with_capacity(raw.len());
    write_uleb128_to(&mut new_raw, static_n as u64, crate::util::ULEB_GENERIC_MAX)?;
    write_uleb128_to(
        &mut new_raw,
        instance_n as u64,
        crate::util::ULEB_GENERIC_MAX,
    )?;
    write_uleb128_to(&mut new_raw, direct_n as u64, crate::util::ULEB_GENERIC_MAX)?;
    write_uleb128_to(
        &mut new_raw,
        virtual_n as u64,
        crate::util::ULEB_GENERIC_MAX,
    )?;

    // Static fields. Deltas in the source are against ORIGINAL indices;
    // the rebuilt class_data re-derives deltas against NEW indices of
    // the (order-preserved) selected entries. Keep the two accumulators
    // separate.
    static EMPTY_FIELDS: &[asc_dex::FieldIdx] = &[];
    let selected_static: &[asc_dex::FieldIdx] = closure
        .class_def_record
        .as_ref()
        .map(|r| r.selected_static_fields.as_slice())
        .unwrap_or(EMPTY_FIELDS);
    let mut sel_iter = selected_static.iter();
    let mut prev_new: Option<u32> = None;
    for _ in 0..static_n {
        let (_delta, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
        p += n;
        let (access, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
        p += n;
        let sel = sel_iter
            .next()
            .ok_or(RebuildError::Internal("selected static fields short"))?;
        let new_idx = maps.fields.lookup(sel.0)?;
        let base = prev_new.replace(new_idx).unwrap_or(0);
        let new_delta = new_idx
            .checked_sub(base)
            .ok_or(RebuildError::Internal("class_data new delta underflow"))?;
        write_uleb128_to(
            &mut new_raw,
            new_delta as u64,
            crate::util::ULEB_GENERIC_MAX,
        )?;
        write_uleb128_to(&mut new_raw, access as u64, crate::util::ULEB_GENERIC_MAX)?;
    }
    // Instance fields
    static EMPTY_FIELDS2: &[asc_dex::FieldIdx] = &[];
    let selected_instance: &[asc_dex::FieldIdx] = closure
        .class_def_record
        .as_ref()
        .map(|r| r.selected_instance_fields.as_slice())
        .unwrap_or(EMPTY_FIELDS2);
    let mut sel_iter = selected_instance.iter();
    let mut prev_new: Option<u32> = None;
    for _ in 0..instance_n {
        let (_delta, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
        p += n;
        let (access, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
        p += n;
        let sel = sel_iter
            .next()
            .ok_or(RebuildError::Internal("selected instance fields short"))?;
        let new_idx = maps.fields.lookup(sel.0)?;
        let base = prev_new.replace(new_idx).unwrap_or(0);
        let new_delta = new_idx
            .checked_sub(base)
            .ok_or(RebuildError::Internal("class_data new delta underflow"))?;
        write_uleb128_to(
            &mut new_raw,
            new_delta as u64,
            crate::util::ULEB_GENERIC_MAX,
        )?;
        write_uleb128_to(&mut new_raw, access as u64, crate::util::ULEB_GENERIC_MAX)?;
    }
    // Direct methods
    static EMPTY_METHODS: &[asc_dex::MethodIdx] = &[];
    let selected_direct: &[asc_dex::MethodIdx] = closure
        .class_def_record
        .as_ref()
        .map(|r| r.selected_direct_methods.as_slice())
        .unwrap_or(EMPTY_METHODS);
    let mut sel_iter = selected_direct.iter();
    let mut prev_new: Option<u32> = None;
    for i in 0..direct_n {
        let (_delta, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
        p += n;
        let (access, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
        p += n;
        let (_code_off, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
        p += n;
        let sel = sel_iter
            .next()
            .ok_or(RebuildError::Internal("selected direct methods short"))?;
        let new_idx = maps.methods.lookup(sel.0)?;
        let base = prev_new.replace(new_idx).unwrap_or(0);
        let new_delta = new_idx
            .checked_sub(base)
            .ok_or(RebuildError::Internal("class_data new delta underflow"))?;
        write_uleb128_to(
            &mut new_raw,
            new_delta as u64,
            crate::util::ULEB_GENERIC_MAX,
        )?;
        write_uleb128_to(&mut new_raw, access as u64, crate::util::ULEB_GENERIC_MAX)?;
        let code_off_new = code_offs.get(i as usize).copied().unwrap_or(0);
        write_uleb128_to(
            &mut new_raw,
            code_off_new as u64,
            crate::util::ULEB_GENERIC_MAX,
        )?;
    }
    // Virtual methods
    static EMPTY_METHODS2: &[asc_dex::MethodIdx] = &[];
    let selected_virtual: &[asc_dex::MethodIdx] = closure
        .class_def_record
        .as_ref()
        .map(|r| r.selected_virtual_methods.as_slice())
        .unwrap_or(EMPTY_METHODS2);
    let mut sel_iter = selected_virtual.iter();
    let mut prev_new: Option<u32> = None;
    for i in 0..virtual_n {
        let (_delta, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
        p += n;
        let (access, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
        p += n;
        let (_code_off, n) = asc_dex::leb::uleb128_to_u32(&raw[p..])?;
        p += n;
        let sel = sel_iter
            .next()
            .ok_or(RebuildError::Internal("selected virtual methods short"))?;
        let new_idx = maps.methods.lookup(sel.0)?;
        let base = prev_new.replace(new_idx).unwrap_or(0);
        let new_delta = new_idx
            .checked_sub(base)
            .ok_or(RebuildError::Internal("class_data new delta underflow"))?;
        write_uleb128_to(
            &mut new_raw,
            new_delta as u64,
            crate::util::ULEB_GENERIC_MAX,
        )?;
        write_uleb128_to(&mut new_raw, access as u64, crate::util::ULEB_GENERIC_MAX)?;
        let code_off_new = code_offs
            .get(direct_n as usize + i as usize)
            .copied()
            .unwrap_or(0);
        write_uleb128_to(
            &mut new_raw,
            code_off_new as u64,
            crate::util::ULEB_GENERIC_MAX,
        )?;
    }
    Ok(new_raw)
}

/// Re-encodes an `annotation_item` (visibility byte + encoded_annotation).
pub(crate) fn rewrite_annotation_item(
    visibility: u8,
    ann: &asc_dex::EncodedAnnotation,
    out: &mut Vec<u8>,
    maps: &PoolMaps,
) -> Result<(), RebuildError> {
    out.push(visibility);
    let new_ty = maps.types.lookup(ann.type_idx.0)?;
    write_uleb128_to(out, new_ty as u64, crate::util::ULEB_GENERIC_MAX)?;
    write_uleb128_to(
        out,
        ann.elements.len() as u64,
        crate::util::ULEB_GENERIC_MAX,
    )?;
    for (name, v) in &ann.elements {
        let new_name = maps.strings.lookup(name.0)?;
        write_uleb128_to(out, new_name as u64, crate::util::ULEB_GENERIC_MAX)?;
        rewrite_encoded_value(v, out, maps, 0)?;
    }
    Ok(())
}

/// Re-encodes an `annotation_set_item` (count + offsets).
pub(crate) fn rewrite_annotation_set(
    new_offsets: &[u32],
    out: &mut Vec<u8>,
) -> Result<(), RebuildError> {
    write_uleb128_to(out, new_offsets.len() as u64, crate::util::ULEB_GENERIC_MAX)?;
    for &off in new_offsets {
        out.extend_from_slice(&off.to_le_bytes());
    }
    Ok(())
}

/// Re-encodes an `annotation_set_ref_list` (count + set offsets).
pub(crate) fn rewrite_annotation_set_ref_list(
    new_offsets: &[u32],
    out: &mut Vec<u8>,
) -> Result<(), RebuildError> {
    write_uleb128_to(out, new_offsets.len() as u64, crate::util::ULEB_GENERIC_MAX)?;
    for &off in new_offsets {
        out.extend_from_slice(&off.to_le_bytes());
    }
    Ok(())
}

/// Re-encodes an `annotations_directory_item`.
pub(crate) fn rewrite_annotations_directory(
    class_ann_off: u32,
    field_annotations: &[(u32, u32)],
    method_annotations: &[(u32, u32)],
    parameter_annotations: &[(u32, u32)],
    out: &mut Vec<u8>,
) -> Result<(), RebuildError> {
    out.extend_from_slice(&class_ann_off.to_le_bytes());
    out.extend_from_slice(&(field_annotations.len() as u32).to_le_bytes());
    out.extend_from_slice(&(method_annotations.len() as u32).to_le_bytes());
    out.extend_from_slice(&(parameter_annotations.len() as u32).to_le_bytes());
    for (f, s) in field_annotations {
        out.extend_from_slice(&f.to_le_bytes());
        out.extend_from_slice(&s.to_le_bytes());
    }
    for (m, s) in method_annotations {
        out.extend_from_slice(&m.to_le_bytes());
        out.extend_from_slice(&s.to_le_bytes());
    }
    for (m, s) in parameter_annotations {
        out.extend_from_slice(&m.to_le_bytes());
        out.extend_from_slice(&s.to_le_bytes());
    }
    Ok(())
}

/// Re-encodes a `static_values` payload (an `encoded_array`).
pub(crate) fn rewrite_static_values(
    items: &[EncodedValue],
    maps: &PoolMaps,
) -> Result<Vec<u8>, RebuildError> {
    let mut out = Vec::new();
    write_uleb128_to(&mut out, items.len() as u64, crate::util::ULEB_GENERIC_MAX)?;
    for v in items {
        rewrite_encoded_value(v, &mut out, maps, 0)?;
    }
    Ok(out)
}
