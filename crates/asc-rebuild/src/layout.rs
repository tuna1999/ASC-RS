//! Canonical section order + final emit for the rebuilt DEX.
//!
//! We emit sections in the following order:
//!
//! 1. String-data records (4-aligned region; each record is ULEB-len +
//!    mutf8 payload + NUL).
//! 2. Type-list payloads (interfaces type_list + each proto's parameter
//!    type_list). 4-aligned.
//! 3. Static-values encoded arrays (4-aligned).
//! 4. Debug-info items (unaligned).
//! 5. Annotation items, sets, set-ref lists, directory (4-aligned).
//! 6. Code items (4-aligned; each item has its own insns, tries, and
//!    catch handler list).
//! 7. Class-data item (4-aligned).
//! 8. Call-site encoded-array payloads + method-handle rows (only when
//!    needed for 038+).
//! 9. Pool blocks — string_ids, type_ids, proto_ids, field_ids,
//!    method_ids, call_site_ids, method_handles, class_defs — written
//!    AFTER the data section so we already know every cross-reference
//!    offset.
//! 10. Map list (last; 4-aligned).
//! 11. Header (rewritten last, knowing every other offset).
//!
//! Final pass: SHA-1 signature + Adler-32 checksum.

use crate::closure::{Closure, MethodIter};
use crate::error::RebuildError;
use crate::remap::PoolMaps;
use crate::rewrite::{
    rewrite_annotation_item, rewrite_annotation_set, rewrite_annotation_set_ref_list,
    rewrite_annotations_directory, rewrite_bytecode, rewrite_catch_handler_list,
    rewrite_class_data, rewrite_debug_info, rewrite_static_values,
};
use crate::util::{align_to_4, push_raw_string_data, raw_string_data_len};

use asc_dex::{ClassDef, DexHeader, DexView, StringIdx, TypeIdx};

/// Bookkeeping for every absolute offset / size the rebuilt file
/// needs. Populated top-to-bottom during emit; referenced when the
/// header / map_list are written.
#[derive(Debug)]
pub(crate) struct LayoutOut {
    pub out: Vec<u8>,
    pub version: asc_dex::DexVersion,

    pub string_data_off: u32,
    pub string_data_size: u32,
    pub interfaces_off: u32,
    pub interfaces_size: u32,
    pub proto_type_lists_off: u32,
    pub proto_type_lists_size: u32,
    pub static_values_off: u32,
    pub static_values_size: u32,
    pub debug_info_off: u32,
    pub debug_info_size: u32,
    pub ann_items_off: u32,
    pub ann_items_size: u32,
    pub ann_sets_off: u32,
    pub ann_sets_size: u32,
    pub ann_set_ref_lists_off: u32,
    pub ann_set_ref_lists_size: u32,
    pub ann_dir_off: u32,
    pub ann_dir_size: u32,
    pub code_items_off: u32,
    pub code_items_size: u32,
    pub class_data_off: u32,
    pub class_data_size: u32,
    pub call_site_arrays_off: u32,
    pub call_site_arrays_size: u32,

    // Item counts for the map_list (map entries carry ITEM counts,
    // never byte sizes — ART/d8 consumers iterate them; see
    // `emit_map_list`).
    pub string_data_count: u32,
    pub interfaces_count: u32,
    pub proto_type_list_count: u32,
    pub static_values_count: u32,
    pub debug_info_count: u32,
    pub ann_item_count: u32,
    pub ann_set_count: u32,
    pub ann_ref_list_count: u32,
    pub code_item_count: u32,
    pub call_site_array_count: u32,

    pub string_ids_off: u32,
    pub type_ids_off: u32,
    pub proto_ids_off: u32,
    pub field_ids_off: u32,
    pub method_ids_off: u32,
    pub call_site_ids_off: u32,
    pub method_handles_off: u32,
    pub class_defs_off: u32,

    pub map_off: u32,

    pub target_new_type_idx: u32,

    pub kept_string_count: u32,
    pub kept_type_count: u32,
    pub kept_proto_count: u32,
    pub kept_field_count: u32,
    pub kept_method_count: u32,
    pub kept_call_site_count: u32,
    pub kept_method_handle_count: u32,

    pub source_string_count: u32,
    pub source_type_count: u32,
    pub source_proto_count: u32,
    pub source_field_count: u32,
    pub source_method_count: u32,
    pub source_class_count: u32,
}
impl Default for LayoutOut {
    fn default() -> Self {
        Self {
            out: Vec::new(),
            version: asc_dex::DexVersion::V040,
            string_data_off: 0,
            string_data_size: 0,
            interfaces_off: 0,
            interfaces_size: 0,
            proto_type_lists_off: 0,
            proto_type_lists_size: 0,
            static_values_off: 0,
            static_values_size: 0,
            debug_info_off: 0,
            debug_info_size: 0,
            ann_items_off: 0,
            ann_items_size: 0,
            ann_sets_off: 0,
            ann_sets_size: 0,
            ann_set_ref_lists_off: 0,
            ann_set_ref_lists_size: 0,
            ann_dir_off: 0,
            ann_dir_size: 0,
            code_items_off: 0,
            code_items_size: 0,
            class_data_off: 0,
            class_data_size: 0,
            call_site_arrays_off: 0,
            call_site_arrays_size: 0,
            string_ids_off: 0,
            type_ids_off: 0,
            proto_ids_off: 0,
            field_ids_off: 0,
            method_ids_off: 0,
            call_site_ids_off: 0,
            method_handles_off: 0,
            class_defs_off: 0,
            map_off: 0,
            string_data_count: 0,
            interfaces_count: 0,
            proto_type_list_count: 0,
            static_values_count: 0,
            debug_info_count: 0,
            ann_item_count: 0,
            ann_set_count: 0,
            ann_ref_list_count: 0,
            code_item_count: 0,
            call_site_array_count: 0,
            target_new_type_idx: 0,
            kept_string_count: 0,
            kept_type_count: 0,
            kept_proto_count: 0,
            kept_field_count: 0,
            kept_method_count: 0,
            kept_call_site_count: 0,
            kept_method_handle_count: 0,
            source_string_count: 0,
            source_type_count: 0,
            source_proto_count: 0,
            source_field_count: 0,
            source_method_count: 0,
            source_class_count: 0,
        }
    }
}

const HEADER_SIZE: usize = DexHeader::SIZE;

/// Top-level entry point. Emits the rebuilt DEX into a fresh `Vec<u8>`.
pub(crate) fn emit(
    view: &DexView<'_>,
    closure: &Closure,
    maps: &PoolMaps,
) -> Result<LayoutOut, RebuildError> {
    let mut lo = LayoutOut::default();
    let mut out = Vec::with_capacity(1024 * 1024);
    out.resize(HEADER_SIZE, 0u8);

    lo.source_string_count = view.string_count();
    lo.source_type_count = view.type_count();
    lo.source_proto_count = view.proto_count();
    lo.source_field_count = view.field_count();
    lo.source_method_count = view.method_count();
    lo.source_class_count = view.class_def_count();
    lo.kept_string_count = maps.strings.len();
    lo.kept_type_count = maps.types.len();
    lo.kept_proto_count = maps.protos.len();
    lo.kept_field_count = maps.fields.len();
    lo.kept_method_count = maps.methods.len();
    lo.kept_call_site_count = maps.call_sites.len();
    lo.kept_method_handle_count = maps.method_handles.len();
    lo.version = view.version();

    // ---------- string_data region ----------
    align_to_4(&mut out);
    lo.string_data_off = out.len() as u32;
    for &old_idx in &closure.strings {
        let sref = view.string(StringIdx(old_idx))?;
        push_raw_string_data(&mut out, &sref);
    }
    lo.string_data_size = (out.len() as u32) - lo.string_data_off;
    lo.string_data_count = closure.strings.len() as u32;

    // ---------- type_list (interfaces) ----------
    let mut proto_params_off: Vec<u32> = vec![0; maps.protos.len() as usize];
    if let Some(cd_rec) = &closure.class_def_record
        && cd_rec.interfaces_off != 0
    {
        align_to_4(&mut out);
        lo.interfaces_off = out.len() as u32;
        let cd = ClassDef {
            class: cd_rec.class_type_idx,
            access_flags: cd_rec.access_flags,
            superclass: cd_rec.superclass,
            interfaces_off: cd_rec.interfaces_off,
            source_file: cd_rec.source_file,
            annotations_off: cd_rec.annotations_off,
            class_data_off: cd_rec.class_data_off,
            static_values_off: cd_rec.static_values_off,
        };
        let original = view
            .class_interfaces(&cd)?
            .ok_or(asc_dex::DexError::InvalidLength {
                off: cd_rec.interfaces_off as usize,
                message: "interfaces_off == 0 after validation",
            })?;
        let mut types = Vec::with_capacity(original.len());
        for entry in original.iter() {
            types.push(entry);
        }
        out.extend_from_slice(&(types.len() as u32).to_le_bytes());
        for t in types {
            let new_idx = maps.types.lookup(t.0)?;
            out.extend_from_slice(&new_idx.to_le_bytes());
        }
        lo.interfaces_size = (out.len() as u32) - lo.interfaces_off;
        lo.interfaces_count = 1;
    }

    // ---------- proto parameter type_lists ----------
    align_to_4(&mut out);
    lo.proto_type_lists_off = out.len() as u32;
    for new_idx in 0..maps.protos.len() {
        let proto_old = maps
            .protos
            .old_for_rank(new_idx)
            .ok_or(RebuildError::Internal("proto rank → old missing"))?;
        let rec = closure
            .proto_records
            .iter()
            .find(|(p, _, _, _)| p.0 == proto_old)
            .ok_or(RebuildError::Internal("proto record not found"))?;
        if rec.3.is_empty() {
            continue;
        }
        align_to_4(&mut out);
        let tl_off = out.len() as u32;
        out.extend_from_slice(&(rec.3.len() as u32).to_le_bytes());
        for t in &rec.3 {
            let new_t = maps.types.lookup(t.0)?;
            out.extend_from_slice(&new_t.to_le_bytes());
        }
        proto_params_off[new_idx as usize] = tl_off;
        lo.proto_type_list_count += 1;
    }
    lo.proto_type_lists_size = if lo.proto_type_lists_off == out.len() as u32 {
        0
    } else {
        (out.len() as u32) - lo.proto_type_lists_off
    };

    // ---------- static_values ----------
    if let Some(cd_rec) = &closure.class_def_record
        && cd_rec.static_values_off != 0
    {
        align_to_4(&mut out);
        lo.static_values_off = out.len() as u32;
        let arr = view.encoded_array(view.physical(), cd_rec.static_values_off as usize)?;
        let rewritten = rewrite_static_values(&arr.0, maps)?;
        out.extend_from_slice(&rewritten);
        lo.static_values_size = (out.len() as u32) - lo.static_values_off;
        lo.static_values_count = 1;
    }

    // ---------- annotations region ----------
    let mut new_item_off_map: std::collections::HashMap<u32, u32> =
        std::collections::HashMap::new();
    let mut new_set_off_map: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    let mut new_ref_off_map: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    let class_ann_off: u32;
    let mut field_pairs: Vec<(u32, u32)> = Vec::new();
    let mut method_pairs: Vec<(u32, u32)> = Vec::new();
    let mut param_pairs: Vec<(u32, u32)> = Vec::new();
    if let Some(cd_rec) = &closure.class_def_record
        && cd_rec.annotations_off != 0
    {
        let dir = view.annotations_directory(cd_rec.annotations_off)?.ok_or(
            asc_dex::DexError::InvalidLength {
                off: cd_rec.annotations_off as usize,
                message: "annotations_off == 0 after validation",
            },
        )?;

        let mut item_offs: Vec<u32> = Vec::new();
        if dir.class_annotations_off != 0 {
            let set = view.annotation_set(dir.class_annotations_off)?;
            item_offs.extend(set.annotation_offs.iter().copied());
        }
        for fa in &dir.fields {
            if closure.fields.contains(&fa.field_idx.0) && fa.annotations_off != 0 {
                let set = view.annotation_set(fa.annotations_off)?;
                item_offs.extend(set.annotation_offs.iter().copied());
            }
        }
        for ma in &dir.methods {
            if closure.methods.contains(&ma.method_idx.0) && ma.annotations_off != 0 {
                let set = view.annotation_set(ma.annotations_off)?;
                item_offs.extend(set.annotation_offs.iter().copied());
            }
        }
        for pa in &dir.parameters {
            if closure.methods.contains(&pa.method_idx.0) && pa.annotations_off != 0 {
                let refs = view.annotation_set_ref_list(pa.annotations_off)?;
                for &set_off in &refs.annotation_set_offs {
                    if set_off != 0 {
                        let set = view.annotation_set(set_off)?;
                        item_offs.extend(set.annotation_offs.iter().copied());
                    }
                }
            }
        }
        item_offs.sort_unstable();
        item_offs.dedup();
        align_to_4(&mut out);
        lo.ann_items_off = out.len() as u32;
        for old_item_off in item_offs {
            if old_item_off == 0 {
                continue;
            }
            let Some(item) = view.annotation_item(old_item_off)? else {
                continue;
            };
            let start = out.len() as u32;
            rewrite_annotation_item(item.visibility, &item.annotation, &mut out, maps)?;
            new_item_off_map.insert(old_item_off, start);
        }
        lo.ann_items_size = (out.len() as u32) - lo.ann_items_off;
        lo.ann_item_count = new_item_off_map.len() as u32;

        let mut set_offs: Vec<u32> = Vec::new();
        if dir.class_annotations_off != 0 {
            set_offs.push(dir.class_annotations_off);
        }
        for fa in &dir.fields {
            if closure.fields.contains(&fa.field_idx.0) && fa.annotations_off != 0 {
                set_offs.push(fa.annotations_off);
            }
        }
        for ma in &dir.methods {
            if closure.methods.contains(&ma.method_idx.0) && ma.annotations_off != 0 {
                set_offs.push(ma.annotations_off);
            }
        }
        set_offs.sort_unstable();
        set_offs.dedup();
        align_to_4(&mut out);
        lo.ann_sets_off = out.len() as u32;
        for old_set_off in set_offs {
            let set = view.annotation_set(old_set_off)?;
            let start = out.len() as u32;
            let mut new_offs: Vec<u32> = Vec::new();
            for &old_item in &set.annotation_offs {
                if let Some(&new_o) = new_item_off_map.get(&old_item) {
                    new_offs.push(new_o);
                }
            }
            rewrite_annotation_set(&new_offs, &mut out)?;
            new_set_off_map.insert(old_set_off, start);
        }
        lo.ann_sets_size = (out.len() as u32) - lo.ann_sets_off;
        lo.ann_set_count = new_set_off_map.len() as u32;

        let mut param_ref_offs: Vec<u32> = Vec::new();
        for pa in &dir.parameters {
            if closure.methods.contains(&pa.method_idx.0) && pa.annotations_off != 0 {
                param_ref_offs.push(pa.annotations_off);
            }
        }
        param_ref_offs.sort_unstable();
        param_ref_offs.dedup();
        align_to_4(&mut out);
        lo.ann_set_ref_lists_off = out.len() as u32;
        for old_ref in param_ref_offs {
            let refs = view.annotation_set_ref_list(old_ref)?;
            let start = out.len() as u32;
            let mut new_offs: Vec<u32> = Vec::new();
            for &set_off in &refs.annotation_set_offs {
                if let Some(&new_o) = new_set_off_map.get(&set_off) {
                    new_offs.push(new_o);
                }
            }
            rewrite_annotation_set_ref_list(&new_offs, &mut out)?;
            new_ref_off_map.insert(old_ref, start);
        }
        lo.ann_set_ref_lists_size = (out.len() as u32) - lo.ann_set_ref_lists_off;
        lo.ann_ref_list_count = new_ref_off_map.len() as u32;

        align_to_4(&mut out);
        lo.ann_dir_off = out.len() as u32;
        class_ann_off = if dir.class_annotations_off != 0 {
            new_set_off_map
                .get(&dir.class_annotations_off)
                .copied()
                .unwrap_or(0)
        } else {
            0
        };
        for fa in &dir.fields {
            if !closure.fields.contains(&fa.field_idx.0) {
                continue;
            }
            let new_field = maps.fields.lookup(fa.field_idx.0)?;
            let new_set = new_set_off_map
                .get(&fa.annotations_off)
                .copied()
                .unwrap_or(0);
            field_pairs.push((new_field, new_set));
        }
        field_pairs.sort_by_key(|(f, _)| *f);
        for ma in &dir.methods {
            if !closure.methods.contains(&ma.method_idx.0) {
                continue;
            }
            let new_method = maps.methods.lookup(ma.method_idx.0)?;
            let new_set = new_set_off_map
                .get(&ma.annotations_off)
                .copied()
                .unwrap_or(0);
            method_pairs.push((new_method, new_set));
        }
        method_pairs.sort_by_key(|(m, _)| *m);
        for pa in &dir.parameters {
            if !closure.methods.contains(&pa.method_idx.0) {
                continue;
            }
            let new_method = maps.methods.lookup(pa.method_idx.0)?;
            let new_ref = new_ref_off_map
                .get(&pa.annotations_off)
                .copied()
                .unwrap_or(0);
            param_pairs.push((new_method, new_ref));
        }
        param_pairs.sort_by_key(|(m, _)| *m);
        rewrite_annotations_directory(
            class_ann_off,
            &field_pairs,
            &method_pairs,
            &param_pairs,
            &mut out,
        )?;
        lo.ann_dir_size = (out.len() as u32) - lo.ann_dir_off;
    }

    // ---------- debug_info region ----------
    let mut dbg_off_per_method: Vec<u32> = vec![0; maps.methods.len() as usize];
    if let Some(cd_rec) = &closure.class_def_record {
        let cd_has_dbg = cd_rec.debug_info_raw.iter().any(|b| !b.is_empty());
        if cd_has_dbg {
            align_to_4(&mut out);
            lo.debug_info_off = out.len() as u32;
            let mut iter = MethodIter::new(cd_rec);
            while let Some((old_method, _has_code, raw_idx)) = iter.next() {
                let raw_dbg = &cd_rec.debug_info_raw[raw_idx];
                if raw_dbg.is_empty() {
                    continue;
                }
                let off = out.len() as u32;
                let rewritten = rewrite_debug_info(raw_dbg, maps)?;
                out.extend_from_slice(&rewritten);
                let new_method_idx = maps.methods.lookup(old_method.0)?;
                dbg_off_per_method[new_method_idx as usize] = off;
                lo.debug_info_count += 1;
            }
            lo.debug_info_size = (out.len() as u32) - lo.debug_info_off;
        }
    }

    // ---------- code_items region ----------
    let mut new_code_off_per_method: Vec<u32> = vec![0; maps.methods.len() as usize];
    if let Some(cd_rec) = &closure.class_def_record {
        let any_code = cd_rec.method_has_code.iter().any(|&b| b);
        if any_code {
            align_to_4(&mut out);
            lo.code_items_off = out.len() as u32;
            let total =
                cd_rec.selected_direct_methods.len() + cd_rec.selected_virtual_methods.len();
            for raw_idx in 0..total {
                if !cd_rec.method_has_code[raw_idx] {
                    continue;
                }
                let old_method = if raw_idx < cd_rec.selected_direct_methods.len() {
                    cd_rec.selected_direct_methods[raw_idx]
                } else {
                    cd_rec.selected_virtual_methods[raw_idx - cd_rec.selected_direct_methods.len()]
                };
                let new_method_idx = maps.methods.lookup(old_method.0)? as usize;
                let src_code_off = cd_rec.source_code_off(old_method);
                let src_ci = view
                    .code_item(src_code_off)?
                    .ok_or(RebuildError::Internal("source code_item missing"))?;
                let mut code_bytes = cd_rec.code_item_raw[raw_idx].clone();
                let insns_size = u32::from_le_bytes([
                    code_bytes[12],
                    code_bytes[13],
                    code_bytes[14],
                    code_bytes[15],
                ]);
                let tries_size = u16::from_le_bytes([code_bytes[6], code_bytes[7]]);

                let insns_byte_len = insns_size as usize * 2;
                {
                    let insns = &mut code_bytes[16..16 + insns_byte_len];
                    rewrite_bytecode(insns, insns_size, maps)?;
                }

                let new_dbg_off = dbg_off_per_method.get(new_method_idx).copied().unwrap_or(0);
                code_bytes[8..12].copy_from_slice(&new_dbg_off.to_le_bytes());

                let tries_bytes = tries_size as usize * 8;
                let mut cursor = 16 + insns_byte_len;
                if tries_size > 0 && (insns_size & 1) == 1 {
                    cursor += 2;
                }
                let tries_end = cursor + tries_bytes;
                code_bytes.truncate(tries_end);

                let reencoded = rewrite_catch_handler_list(view, &src_ci, maps)?;

                let src_tries: Vec<_> = view.tries_iter(&src_ci)?.collect();
                let tries_pos_in_code = 16
                    + insns_byte_len
                    + (if tries_size > 0 && (insns_size & 1) == 1 {
                        2
                    } else {
                        0
                    });
                for (i, ti_res) in src_tries.iter().enumerate() {
                    let ti = *ti_res;
                    // handler_off in the SOURCE is a byte offset into the
                    // original handler list; map it to the re-encoded
                    // handler's byte offset.
                    let new_off = reencoded
                        .offset_map
                        .iter()
                        .find(|(orig, _)| *orig == ti.handler_off as u32)
                        .map(|(_, new)| *new)
                        .ok_or(RebuildError::Internal("catch handler offset out of range"))?;
                    let pos = tries_pos_in_code + i * 8 + 6;
                    if pos + 2 > code_bytes.len() {
                        return Err(RebuildError::Internal("try_item out of range"));
                    }
                    code_bytes[pos..pos + 2].copy_from_slice(&(new_off as u16).to_le_bytes());
                }

                while code_bytes.len() & 3 != 0 {
                    code_bytes.push(0);
                }
                code_bytes.extend_from_slice(&reencoded.raw);

                align_to_4(&mut out);
                new_code_off_per_method[new_method_idx] = out.len() as u32;
                out.extend_from_slice(&code_bytes);
                lo.code_item_count += 1;
            }
            lo.code_items_size = (out.len() as u32) - lo.code_items_off;
        }
    }

    // ---------- class_data item ----------
    if let Some(cd_rec) = &closure.class_def_record
        && cd_rec.class_data_off != 0
    {
        align_to_4(&mut out);
        lo.class_data_off = out.len() as u32;
        let new_raw = rewrite_class_data(
            &cd_rec.class_data_raw,
            closure,
            maps,
            &new_code_off_per_method,
        )?;
        out.extend_from_slice(&new_raw);
        lo.class_data_size = (out.len() as u32) - lo.class_data_off;
    }

    // ---------- call_site arrays + method_handles rows ----------
    let mut call_site_data_offs: Vec<u32> = vec![0; maps.call_sites.len() as usize];
    if !maps.call_sites.is_empty() {
        align_to_4(&mut out);
        lo.call_site_arrays_off = out.len() as u32;
        for (rank, &old_cs) in closure.call_sites.iter().enumerate() {
            let rec = closure
                .call_site_records
                .iter()
                .find(|(c, _, _)| c.0 == old_cs)
                .ok_or(RebuildError::Internal("call_site record not found"))?;
            let arr_off = out.len() as u32;
            let mut payload = Vec::new();
            crate::rewrite::rewrite_encoded_value(&rec.2, &mut payload, maps, 0)?;
            out.extend_from_slice(&payload);
            call_site_data_offs[rank] = arr_off;
        }
        lo.call_site_arrays_size = (out.len() as u32) - lo.call_site_arrays_off;
        lo.call_site_array_count = closure.call_sites.len() as u32;
    }

    // ---------- pool regions ----------
    // string_ids (each entry = offset of the corresponding string_data record).
    align_to_4(&mut out);
    lo.string_ids_off = out.len() as u32;
    let mut cur_off = lo.string_data_off;
    let mut per_string_off: Vec<u32> = Vec::with_capacity(maps.strings.len() as usize);
    for &old_idx in &closure.strings {
        per_string_off.push(cur_off);
        let sref = view.string(StringIdx(old_idx))?;
        cur_off += raw_string_data_len(&sref) as u32;
    }
    for &off in &per_string_off {
        out.extend_from_slice(&off.to_le_bytes());
    }

    // type_ids
    align_to_4(&mut out);
    lo.type_ids_off = out.len() as u32;
    for new_idx in 0..maps.types.len() {
        let old_idx = maps
            .types
            .old_for_rank(new_idx)
            .ok_or(RebuildError::Internal("type rank → old missing"))?;
        let desc_str_idx = closure
            .type_descriptor
            .iter()
            .find(|(t, _)| t.0 == old_idx)
            .map(|(_, d)| *d)
            .ok_or(RebuildError::Internal(
                "missing descriptor for new type idx",
            ))?;
        let new_desc = maps.strings.lookup(desc_str_idx.0)?;
        out.extend_from_slice(&new_desc.to_le_bytes());
    }

    // proto_ids
    align_to_4(&mut out);
    lo.proto_ids_off = out.len() as u32;
    for new_idx in 0..maps.protos.len() {
        let proto_old = maps
            .protos
            .old_for_rank(new_idx)
            .ok_or(RebuildError::Internal("proto rank → old missing"))?;
        let rec = closure
            .proto_records
            .iter()
            .find(|(p, _, _, _)| p.0 == proto_old)
            .ok_or(RebuildError::Internal("proto record not found"))?;
        let new_shorty = maps.strings.lookup(rec.1.0)?;
        let new_return = maps.types.lookup(rec.2.0)?;
        let params_off = proto_params_off[new_idx as usize];
        out.extend_from_slice(&new_shorty.to_le_bytes());
        out.extend_from_slice(&new_return.to_le_bytes());
        out.extend_from_slice(&params_off.to_le_bytes());
    }

    // field_ids
    align_to_4(&mut out);
    lo.field_ids_off = out.len() as u32;
    for new_idx in 0..maps.fields.len() {
        let old_idx = maps
            .fields
            .old_for_rank(new_idx)
            .ok_or(RebuildError::Internal("field rank → old missing"))?;
        let rec = closure
            .field_records
            .iter()
            .find(|(f, _, _, _)| f.0 == old_idx)
            .ok_or(RebuildError::Internal("field record not found"))?;
        let new_cls = maps.types.lookup(rec.1.0)? as u16;
        let new_ty = maps.types.lookup(rec.2.0)? as u16;
        let new_name = maps.strings.lookup(rec.3.0)?;
        out.extend_from_slice(&new_cls.to_le_bytes());
        out.extend_from_slice(&new_ty.to_le_bytes());
        out.extend_from_slice(&new_name.to_le_bytes());
    }

    // method_ids
    align_to_4(&mut out);
    lo.method_ids_off = out.len() as u32;
    for new_idx in 0..maps.methods.len() {
        let old_idx = maps
            .methods
            .old_for_rank(new_idx)
            .ok_or(RebuildError::Internal("method rank → old missing"))?;
        let rec = closure
            .method_records
            .iter()
            .find(|(m, _, _, _)| m.0 == old_idx)
            .ok_or(RebuildError::Internal("method record not found"))?;
        let new_cls = maps.types.lookup(rec.1.0)? as u16;
        let new_proto = maps.protos.lookup(rec.2.0)? as u16;
        let new_name = maps.strings.lookup(rec.3.0)?;
        out.extend_from_slice(&new_cls.to_le_bytes());
        out.extend_from_slice(&new_proto.to_le_bytes());
        out.extend_from_slice(&new_name.to_le_bytes());
    }

    // call_site_ids
    if !maps.call_sites.is_empty() {
        align_to_4(&mut out);
        lo.call_site_ids_off = out.len() as u32;
        for &off in &call_site_data_offs {
            out.extend_from_slice(&off.to_le_bytes());
        }
    }

    // method_handles
    if !maps.method_handles.is_empty() {
        align_to_4(&mut out);
        lo.method_handles_off = out.len() as u32;
        for &old_idx in &closure.method_handles {
            let rec = closure
                .method_handle_records
                .iter()
                .find(|(m, _, _)| m.0 == old_idx)
                .ok_or(RebuildError::Internal("method_handle record not found"))?;
            let target_new = match rec.1 {
                0..=5 => maps.fields.lookup_or_zero(rec.2 as u32) as u16,
                _ => maps.methods.lookup_or_zero(rec.2 as u32) as u16,
            };
            out.extend_from_slice(&rec.1.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&target_new.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
        }
    }

    // class_defs (single row).
    align_to_4(&mut out);
    lo.class_defs_off = out.len() as u32;
    let cd_rec = closure
        .class_def_record
        .as_ref()
        .ok_or(RebuildError::Internal("closure missing class_def_record"))?;
    let new_class = maps.types.lookup(cd_rec.class_type_idx.0)?;
    let new_super = match cd_rec.superclass {
        Some(s) => maps.types.lookup(s.0)?,
        None => u32::MAX,
    };
    let new_src = match cd_rec.source_file {
        Some(s) => maps.strings.lookup(s.0)?,
        None => u32::MAX,
    };
    out.extend_from_slice(&new_class.to_le_bytes());
    out.extend_from_slice(&cd_rec.access_flags.to_le_bytes());
    out.extend_from_slice(&new_super.to_le_bytes());
    out.extend_from_slice(&lo.interfaces_off.to_le_bytes());
    out.extend_from_slice(&new_src.to_le_bytes());
    out.extend_from_slice(&lo.ann_dir_off.to_le_bytes());
    out.extend_from_slice(&lo.class_data_off.to_le_bytes());
    out.extend_from_slice(&lo.static_values_off.to_le_bytes());
    lo.target_new_type_idx = new_class;

    // ---------- map_list ----------
    align_to_4(&mut out);
    lo.map_off = out.len() as u32;
    emit_map_list(&mut out, &lo)?;

    // ---------- header ----------
    let final_size = out.len();
    write_header(&mut out, view, closure, &lo, final_size)?;

    // ---------- SHA-1 signature + Adler-32 checksum ----------
    seal(&mut out);

    lo.out = out;
    Ok(lo)
}

fn emit_map_list(out: &mut Vec<u8>, lo: &LayoutOut) -> Result<(), RebuildError> {
    // Item type codes as emitted by ART/d8, verified against the
    // map_list of every corpus DEX (workload/aurora/fdroid):
    //   0x0000 header, 0x0001..0x0008 id tables / class_def,
    //   0x1000 map_list, 0x1001 type_list, 0x1002 annotation_set_ref_list,
    //   0x1003 annotation_set_item, 0x2000 class_data_item,
    //   0x2001 code_item, 0x2002 string_data_item, 0x2003 debug_info_item,
    //   0x2004 annotation_item, 0x2005 encoded_array_item,
    //   0x2006 annotations_directory_item.
    // Counts are ITEM counts (never byte sizes) and entries are sorted
    // by ascending offset, both per spec; a wrong count/type made the
    // droidsaw decompiler spin forever on our rebuilt DEX.
    let mut entries: Vec<(u16, u32, u32)> = Vec::new();
    entries.push((0x0000, 1, 0));
    if lo.kept_string_count > 0 {
        entries.push((0x0001, lo.kept_string_count, lo.string_ids_off));
    }
    if lo.kept_type_count > 0 {
        entries.push((0x0002, lo.kept_type_count, lo.type_ids_off));
    }
    if lo.kept_proto_count > 0 {
        entries.push((0x0003, lo.kept_proto_count, lo.proto_ids_off));
    }
    if lo.kept_field_count > 0 {
        entries.push((0x0004, lo.kept_field_count, lo.field_ids_off));
    }
    if lo.kept_method_count > 0 {
        entries.push((0x0005, lo.kept_method_count, lo.method_ids_off));
    }
    entries.push((0x0006, 1, lo.class_defs_off));
    if lo.kept_call_site_count > 0 {
        entries.push((0x0007, lo.kept_call_site_count, lo.call_site_ids_off));
    }
    if lo.kept_method_handle_count > 0 {
        entries.push((0x0008, lo.kept_method_handle_count, lo.method_handles_off));
    }
    // type_lists: interfaces list + per-proto parameter lists, emitted
    // as two runs; one map entry at the first run's offset.
    let type_list_count = lo.interfaces_count + lo.proto_type_list_count;
    if type_list_count > 0 {
        let first = if lo.interfaces_off != 0 {
            lo.interfaces_off
        } else {
            lo.proto_type_lists_off
        };
        entries.push((0x1001, type_list_count, first));
    }
    if lo.ann_ref_list_count > 0 {
        entries.push((0x1002, lo.ann_ref_list_count, lo.ann_set_ref_lists_off));
    }
    if lo.ann_set_count > 0 {
        entries.push((0x1003, lo.ann_set_count, lo.ann_sets_off));
    }
    if lo.class_data_size > 0 {
        entries.push((0x2000, 1, lo.class_data_off));
    }
    if lo.code_item_count > 0 {
        entries.push((0x2001, lo.code_item_count, lo.code_items_off));
    }
    if lo.string_data_count > 0 {
        entries.push((0x2002, lo.string_data_count, lo.string_data_off));
    }
    if lo.debug_info_count > 0 {
        entries.push((0x2003, lo.debug_info_count, lo.debug_info_off));
    }
    if lo.ann_item_count > 0 {
        entries.push((0x2004, lo.ann_item_count, lo.ann_items_off));
    }
    // encoded_arrays: static_values run + call-site payload arrays.
    let encoded_array_count = lo.static_values_count + lo.call_site_array_count;
    if encoded_array_count > 0 {
        let first = if lo.static_values_off != 0 {
            lo.static_values_off
        } else {
            lo.call_site_arrays_off
        };
        entries.push((0x2005, encoded_array_count, first));
    }
    if lo.ann_dir_size > 0 {
        entries.push((0x2006, 1, lo.ann_dir_off));
    }
    entries.push((0x1000, 1, lo.map_off));
    // Spec: map items appear in ascending offset order.
    entries.sort_by_key(|&(_ty, _size, off)| off);
    let total = entries.len() as u32;
    out.extend_from_slice(&total.to_le_bytes());
    for (ty, size, off) in &entries {
        out.extend_from_slice(&ty.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&off.to_le_bytes());
    }
    Ok(())
}

fn write_header(
    out: &mut [u8],
    view: &DexView<'_>,
    closure: &Closure,
    lo: &LayoutOut,
    file_size: usize,
) -> Result<(), RebuildError> {
    let version = if closure.needs_038() {
        match view.version() {
            asc_dex::DexVersion::V035 | asc_dex::DexVersion::V037 => asc_dex::DexVersion::V038,
            other => other,
        }
    } else {
        view.version()
    };
    let magic = magic_bytes(version);
    out[0..8].copy_from_slice(&magic);
    out[0x20..0x24].copy_from_slice(&(file_size as u32).to_le_bytes());
    out[0x24..0x28].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
    out[0x28..0x2C].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    out[0x2C..0x30].copy_from_slice(&0u32.to_le_bytes());
    out[0x30..0x34].copy_from_slice(&0u32.to_le_bytes());
    out[0x34..0x38].copy_from_slice(&lo.map_off.to_le_bytes());
    out[0x38..0x3C].copy_from_slice(&lo.kept_string_count.to_le_bytes());
    out[0x3C..0x40].copy_from_slice(&lo.string_ids_off.to_le_bytes());
    out[0x40..0x44].copy_from_slice(&lo.kept_type_count.to_le_bytes());
    out[0x44..0x48].copy_from_slice(&lo.type_ids_off.to_le_bytes());
    out[0x48..0x4C].copy_from_slice(&lo.kept_proto_count.to_le_bytes());
    out[0x4C..0x50].copy_from_slice(&lo.proto_ids_off.to_le_bytes());
    out[0x50..0x54].copy_from_slice(&lo.kept_field_count.to_le_bytes());
    out[0x54..0x58].copy_from_slice(&lo.field_ids_off.to_le_bytes());
    out[0x58..0x5C].copy_from_slice(&lo.kept_method_count.to_le_bytes());
    out[0x5C..0x60].copy_from_slice(&lo.method_ids_off.to_le_bytes());
    out[0x60..0x64].copy_from_slice(&1u32.to_le_bytes());
    out[0x64..0x68].copy_from_slice(&lo.class_defs_off.to_le_bytes());
    out[0x68..0x6C].copy_from_slice(&((file_size - HEADER_SIZE) as u32).to_le_bytes());
    out[0x6C..0x70].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
    // NOTE: DEX 038+ call_site_ids / method_handles are DATA sections
    // tracked exclusively through map_list — the header is 0x70 bytes in
    // EVERY version and has no fields for them. (This block used to
    // "extend" the header to 0x84, zeroing the first 20 bytes of the
    // string-data region.)
    let _ = version;
    let _ = TypeIdx(0);
    Ok(())
}

fn seal(out: &mut [u8]) {
    use adler2::adler32;
    use sha1::{Digest, Sha1};
    let file_size = out.len();
    let mut hasher = Sha1::new();
    hasher.update(&out[32..file_size]);
    let sig = hasher.finalize();
    out[0x0C..0x20].copy_from_slice(&sig);
    let sum = adler32(&out[0x0C..file_size]).unwrap_or(0);
    out[0x08..0x0C].copy_from_slice(&sum.to_le_bytes());
}
/// Builds the 8-byte DEX magic for `version`.
fn magic_bytes(version: asc_dex::DexVersion) -> [u8; 8] {
    let mut m = [0u8; 8];
    m[..4].copy_from_slice(b"dex\n");
    let s = version.as_str();
    m[4..7].copy_from_slice(s.as_bytes());
    m[7] = 0;
    m
}
