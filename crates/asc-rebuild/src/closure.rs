//! Dependency-closure computation from a target `ClassDef`.

use crate::error::RebuildError;

use asc_bytecode::{DexRef, RefWalker, walk_verify};
use asc_dex::{
    CallSiteIdx, ClassData, DexView, EncodedValue, FieldIdx, MethodHandleIdx, MethodIdx, ProtoIdx,
    StringIdx, TypeIdx, ValueType,
};
use std::collections::BTreeSet;

/// Upper bound on selected pool sizes.
const POOL_CAP: u32 = 1 << 20;

#[derive(Debug, Default)]
pub(crate) struct Closure {
    pub strings: BTreeSet<u32>,
    pub types: BTreeSet<u32>,
    pub protos: BTreeSet<u32>,
    pub fields: BTreeSet<u32>,
    pub methods: BTreeSet<u32>,
    pub class_defs: BTreeSet<u32>,
    pub call_sites: BTreeSet<u32>,
    /// Set of method indices whose `code_item` we have already walked.
    pub methods_with_walked_code: std::collections::BTreeSet<u32>,
    pub method_handles: BTreeSet<u32>,
    pub type_descriptor: Vec<(TypeIdx, StringIdx)>,
    pub proto_records: Vec<(ProtoIdx, StringIdx, TypeIdx, Vec<TypeIdx>)>,
    pub field_records: Vec<(FieldIdx, TypeIdx, TypeIdx, StringIdx)>,
    pub method_records: Vec<(MethodIdx, TypeIdx, ProtoIdx, StringIdx)>,
    pub call_site_records: Vec<(CallSiteIdx, u32, EncodedValue)>,
    pub method_handle_records: Vec<(MethodHandleIdx, u16, u16)>,
    pub class_def_record: Option<ClassDefRecord>,
}

#[derive(Debug, Clone)]
pub(crate) struct ClassDefRecord {
    #[allow(dead_code)] // kept for debugging parity with the python oracle
    pub old_idx: u32,
    pub class_type_idx: TypeIdx,
    pub access_flags: u32,
    pub superclass: Option<TypeIdx>,
    pub interfaces_off: u32,
    pub source_file: Option<StringIdx>,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
    pub class_data: Option<ClassData>,
    pub class_data_raw: Vec<u8>,
    pub selected_static_fields: Vec<FieldIdx>,
    pub selected_instance_fields: Vec<FieldIdx>,
    pub selected_direct_methods: Vec<MethodIdx>,
    pub selected_virtual_methods: Vec<MethodIdx>,
    pub code_item_raw: Vec<Vec<u8>>,
    pub debug_info_raw: Vec<Vec<u8>>,
    pub method_has_code: Vec<bool>,
    /// Per-method NEW code_off, populated by the layout pass.
    #[allow(dead_code)] // reserved for the wave-3 CLI verbose output
    pub new_code_offs: Vec<u32>,
}

impl Closure {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn add_string(&mut self, idx: u32) -> Result<bool, RebuildError> {
        if self.strings.len() as u32 >= POOL_CAP {
            return Err(RebuildError::PoolCap {
                pool: "string_ids",
                count: self.strings.len() as u32,
                cap: POOL_CAP,
            });
        }
        Ok(self.strings.insert(idx))
    }

    fn add_type(&mut self, idx: u32) -> Result<bool, RebuildError> {
        if self.types.len() as u32 >= POOL_CAP {
            return Err(RebuildError::PoolCap {
                pool: "type_ids",
                count: self.types.len() as u32,
                cap: POOL_CAP,
            });
        }
        Ok(self.types.insert(idx))
    }

    fn add_proto(&mut self, idx: u32) -> Result<bool, RebuildError> {
        if self.protos.len() as u32 >= POOL_CAP {
            return Err(RebuildError::PoolCap {
                pool: "proto_ids",
                count: self.protos.len() as u32,
                cap: POOL_CAP,
            });
        }
        Ok(self.protos.insert(idx))
    }

    fn add_field(&mut self, idx: u32) -> Result<bool, RebuildError> {
        if self.fields.len() as u32 >= POOL_CAP {
            return Err(RebuildError::PoolCap {
                pool: "field_ids",
                count: self.fields.len() as u32,
                cap: POOL_CAP,
            });
        }
        Ok(self.fields.insert(idx))
    }

    fn add_method(&mut self, idx: u32) -> Result<bool, RebuildError> {
        if self.methods.len() as u32 >= POOL_CAP {
            return Err(RebuildError::PoolCap {
                pool: "method_ids",
                count: self.methods.len() as u32,
                cap: POOL_CAP,
            });
        }
        Ok(self.methods.insert(idx))
    }

    /// Walks the dependency closure starting from `class_def_idx`.
    pub(crate) fn compute(
        view: &DexView<'_>,
        target_descriptor: &str,
    ) -> Result<Self, RebuildError> {
        validate_descriptor(target_descriptor)?;
        let mut state = Self::new();
        let class_def_idx = state.find_target_class_def(view, target_descriptor)?;
        state.walk_class_def(view, class_def_idx)?;
        state.augment_pass(view)?;
        Ok(state)
    }

    /// Augmentation pass: walk every selected method's source-side
    /// `code_item` that we haven't already walked. This catches the
    /// case where the target class's bytecode invokes a method M, and
    /// M's own bytecode references pool entries (string/field/method)
    /// that we haven't yet recorded — without this pass the rewrite
    /// path fails on a "pool lookup miss" for those entries.
    fn augment_pass(&mut self, view: &DexView<'_>) -> Result<(), RebuildError> {
        let to_walk: Vec<u32> = self
            .methods
            .iter()
            .copied()
            .filter(|m| !self.methods_with_walked_code.contains(m))
            .collect();
        for m in to_walk {
            let Some(src_code_off) = self.find_source_code_off(view, m) else {
                continue;
            };
            if src_code_off == 0 {
                continue;
            }
            self.methods_with_walked_code.insert(m);
            self.walk_code_item(view, src_code_off)?;
        }
        Ok(())
    }

    /// Scans every class_def's class_data to find the source `code_off`
    /// for `method_idx`. Returns `None` when the method is not declared
    /// on any source-side class_def.
    fn find_source_code_off(&self, view: &DexView<'_>, method_idx: u32) -> Option<u32> {
        let n = view.class_def_count();
        for ci in 0..n {
            let cd = view.class_def(ci).ok()?;
            let cdata = view.class_data(cd.class_data_off).ok().flatten();
            let Some(cdata) = cdata else { continue };
            for em in cdata
                .direct_methods
                .iter()
                .chain(cdata.virtual_methods.iter())
            {
                if em.method_idx.0 == method_idx {
                    return Some(em.code_off);
                }
            }
        }
        None
    }

    fn find_target_class_def(
        &mut self,
        view: &DexView<'_>,
        descriptor: &str,
    ) -> Result<u32, RebuildError> {
        let target = descriptor.as_bytes();
        let type_count = view.type_count();
        let mut found_type: Option<TypeIdx> = None;
        for ti in 0..type_count {
            let t = TypeIdx(ti);
            let sidx = view.type_(t)?;
            let sref = view.string(sidx)?;
            if sref.mutf8 == target {
                found_type = Some(t);
                break;
            }
        }
        let Some(target_type) = found_type else {
            return Err(RebuildError::ClassNotFound(descriptor.to_string()));
        };

        let class_count = view.class_def_count();
        for ci in 0..class_count {
            let cd = view.class_def(ci)?;
            if cd.class == target_type {
                return Ok(ci);
            }
        }
        Err(RebuildError::ClassNotFound(descriptor.to_string()))
    }

    fn walk_class_def(
        &mut self,
        view: &DexView<'_>,
        class_def_idx: u32,
    ) -> Result<(), RebuildError> {
        self.class_defs.insert(class_def_idx);
        let cd = view.class_def(class_def_idx)?;

        self.add_type(cd.class.0)?;
        let desc_str_idx = view.type_(cd.class)?;
        self.add_string(desc_str_idx.0)?;
        self.record_type(view, cd.class, desc_str_idx)?;

        if let Some(sc) = cd.superclass {
            self.add_type(sc.0)?;
            let sidx = view.type_(sc)?;
            self.add_string(sidx.0)?;
            self.record_type(view, sc, sidx)?;
        }

        if let Some(sf) = cd.source_file {
            self.add_string(sf.0)?;
        }

        if cd.interfaces_off != 0 {
            let ifs = view
                .class_interfaces(&cd)?
                .ok_or(asc_dex::DexError::InvalidLength {
                    off: cd.interfaces_off as usize,
                    message: "interfaces_off == 0 after validation",
                })?;
            for entry in ifs.iter() {
                let t = entry;
                self.add_type(t.0)?;
                let sidx = view.type_(t)?;
                self.add_string(sidx.0)?;
                self.record_type(view, t, sidx)?;
            }
        }

        if cd.annotations_off != 0 {
            self.walk_annotations_directory(view, cd.annotations_off)?;
        }

        let (class_data, class_data_raw) = if cd.class_data_off != 0 {
            let off = cd.class_data_off as usize;
            let raw = view.physical()[off..].to_vec();
            let cd_data =
                view.class_data(cd.class_data_off)?
                    .ok_or(asc_dex::DexError::InvalidLength {
                        off,
                        message: "class_data returned None for nonzero off",
                    })?;
            (Some(cd_data), raw)
        } else {
            (None, Vec::new())
        };

        let mut class_data_record = ClassDefRecord {
            old_idx: class_def_idx,
            class_type_idx: cd.class,
            access_flags: cd.access_flags,
            superclass: cd.superclass,
            interfaces_off: cd.interfaces_off,
            source_file: cd.source_file,
            annotations_off: cd.annotations_off,
            class_data_off: cd.class_data_off,
            static_values_off: cd.static_values_off,
            class_data,
            class_data_raw,
            selected_static_fields: Vec::new(),
            selected_instance_fields: Vec::new(),
            selected_direct_methods: Vec::new(),
            selected_virtual_methods: Vec::new(),
            code_item_raw: Vec::new(),
            debug_info_raw: Vec::new(),
            method_has_code: Vec::new(),
            new_code_offs: Vec::new(),
        };

        if let Some(cdata) = &class_data_record.class_data {
            for ef in &cdata.static_fields {
                self.walk_field(view, ef.field_idx)?;
                class_data_record.selected_static_fields.push(ef.field_idx);
            }
            for ef in &cdata.instance_fields {
                self.walk_field(view, ef.field_idx)?;
                class_data_record
                    .selected_instance_fields
                    .push(ef.field_idx);
            }
            for em in &cdata.direct_methods {
                self.walk_method(view, em.method_idx, em.code_off)?;
                class_data_record
                    .selected_direct_methods
                    .push(em.method_idx);
                class_data_record.method_has_code.push(em.code_off != 0);
                let (code_bytes, dbg_bytes) = self.copy_method(view, em.code_off)?;
                class_data_record.code_item_raw.push(code_bytes);
                class_data_record.debug_info_raw.push(dbg_bytes);
            }
            for em in &cdata.virtual_methods {
                self.walk_method(view, em.method_idx, em.code_off)?;
                class_data_record
                    .selected_virtual_methods
                    .push(em.method_idx);
                class_data_record.method_has_code.push(em.code_off != 0);
                let (code_bytes, dbg_bytes) = self.copy_method(view, em.code_off)?;
                class_data_record.code_item_raw.push(code_bytes);
                class_data_record.debug_info_raw.push(dbg_bytes);
            }
        }

        if cd.static_values_off != 0 {
            self.walk_encoded_array(view, cd.static_values_off, 0)?;
        }

        self.class_def_record = Some(class_data_record);
        Ok(())
    }

    fn copy_method(
        &self,
        view: &DexView<'_>,
        code_off: u32,
    ) -> Result<(Vec<u8>, Vec<u8>), RebuildError> {
        if code_off == 0 {
            return Ok((Vec::new(), Vec::new()));
        }
        let ci = view
            .code_item(code_off)?
            .ok_or(asc_dex::DexError::InvalidLength {
                off: code_off as usize,
                message: "code_off != 0 but code_item returned None",
            })?;
        let mut end = (code_off as usize) + 16 + ci.insns_size as usize * 2;
        if ci.tries_size > 0 && (ci.insns_size & 1) == 1 {
            end += 2;
        }
        if ci.tries_size > 0 {
            end += ci.tries_size as usize * 8;
            while end & 3 != 0 {
                end += 1;
            }
            if let Some(list) = view.catch_handler_list(&ci)? {
                end += list.byte_len();
            }
        }
        let code_bytes = view.physical()[(code_off as usize)..end].to_vec();
        let dbg_bytes = if ci.debug_info_off != 0 {
            self.copy_debug_info_raw(view, ci.debug_info_off)?
        } else {
            Vec::new()
        };
        Ok((code_bytes, dbg_bytes))
    }

    fn walk_field(&mut self, view: &DexView<'_>, field_idx: FieldIdx) -> Result<(), RebuildError> {
        if !self.add_field(field_idx.0)? {
            return Ok(());
        }
        let f = view.field(field_idx)?;
        self.add_type(f.class.0)?;
        let cs = view.type_(f.class)?;
        self.add_string(cs.0)?;
        self.record_type(view, f.class, cs)?;
        self.add_type(f.ty.0)?;
        let ts = view.type_(f.ty)?;
        self.add_string(ts.0)?;
        self.record_type(view, f.ty, ts)?;
        self.add_string(f.name.0)?;
        self.record_field(field_idx, f.class, f.ty, f.name)?;
        Ok(())
    }

    fn walk_method(
        &mut self,
        view: &DexView<'_>,
        method_idx: MethodIdx,
        code_off: u32,
    ) -> Result<(), RebuildError> {
        let first_seen = self.add_method(method_idx.0)?;
        let m = view.method(method_idx)?;
        self.add_type(m.class.0)?;
        let cs = view.type_(m.class)?;
        self.add_string(cs.0)?;
        self.record_type(view, m.class, cs)?;
        self.walk_proto(view, m.proto)?;
        self.add_string(m.name.0)?;
        self.record_method(method_idx, m.class, m.proto, m.name)?;
        // Walk the code_item if we have not yet walked this method's
        // bytecode. Annotations walk may pre-register a method (code_off=0)
        // and class_data walk may later supply the real code_off; we must
        // not skip the bytecode walk in that case.
        if code_off != 0 && !self.methods_with_walked_code.contains(&method_idx.0) {
            self.methods_with_walked_code.insert(method_idx.0);
            if first_seen {
                // First walk covers code_off != 0 already; fall through.
            }
            self.walk_code_item(view, code_off)?;
        }
        let _ = first_seen;
        Ok(())
    }

    fn walk_proto(&mut self, view: &DexView<'_>, proto_idx: ProtoIdx) -> Result<(), RebuildError> {
        if !self.add_proto(proto_idx.0)? {
            return Ok(());
        }
        let p = view.proto(proto_idx)?;
        self.add_string(p.shorty.0)?;
        self.add_type(p.return_type.0)?;
        let ret_sidx = view.type_(p.return_type)?;
        self.add_string(ret_sidx.0)?;
        self.record_type(view, p.return_type, ret_sidx)?;
        let mut params = Vec::with_capacity(p.parameters.len());
        for entry in p.parameters.iter() {
            let t = entry;
            self.add_type(t.0)?;
            let tsidx = view.type_(t)?;
            self.add_string(tsidx.0)?;
            self.record_type(view, t, tsidx)?;
            params.push(t);
        }
        self.proto_records
            .push((proto_idx, p.shorty, p.return_type, params));
        Ok(())
    }

    fn walk_code_item(&mut self, view: &DexView<'_>, code_off: u32) -> Result<(), RebuildError> {
        let Some(ci) = view.code_item(code_off)? else {
            return Err(asc_dex::DexError::InvalidLength {
                off: code_off as usize,
                message: "code_off != 0 but code_item returned None",
            }
            .into());
        };

        let walker = RefWalker::new(ci.insns_exact(), ci.insns_size).map_err(|e| {
            RebuildError::BytecodeRef {
                off: code_off,
                message: format!("RefWalker::new: {e:?}"),
            }
        })?;
        for hit in walker {
            let hit = hit.map_err(|e| RebuildError::BytecodeRef {
                off: code_off,
                message: format!("walk: {e:?}"),
            })?;
            self.walk_dex_ref(view, hit.primary)?;
            self.walk_dex_ref(view, hit.secondary)?;
        }

        if ci.tries_size > 0 {
            if let Some(list) = view.catch_handler_list(&ci)? {
                for entry in list.iter_all()? {
                    for (type_idx, _) in &entry.pairs {
                        self.add_type(*type_idx)?;
                        let sidx = view.type_(TypeIdx(*type_idx))?;
                        self.add_string(sidx.0)?;
                        self.record_type(view, TypeIdx(*type_idx), sidx)?;
                    }
                }
            }
        }

        if ci.debug_info_off != 0 {
            self.walk_debug_info(view, ci.debug_info_off)?;
        }
        Ok(())
    }

    fn walk_dex_ref(&mut self, view: &DexView<'_>, r: Option<DexRef>) -> Result<(), RebuildError> {
        let Some(r) = r else { return Ok(()) };
        match r {
            DexRef::String(s) => {
                self.add_string(s.0)?;
            }
            DexRef::Type(t) => {
                self.add_type(t.0)?;
                let sidx = view.type_(t)?;
                self.add_string(sidx.0)?;
                self.record_type(view, t, sidx)?;
            }
            DexRef::Field(f) => {
                self.walk_field(view, f)?;
            }
            DexRef::Method(m) => {
                self.walk_method(view, m, 0)?;
            }
            DexRef::Proto(p) => {
                self.walk_proto(view, p)?;
            }
            DexRef::CallSite(c) => {
                self.add_call_site(view, c)?;
            }
            DexRef::MethodHandle(mh) => {
                self.add_method_handle(view, mh)?;
            }
        }
        Ok(())
    }

    fn add_call_site(&mut self, view: &DexView<'_>, cs: CallSiteIdx) -> Result<(), RebuildError> {
        if !self.call_sites.insert(cs.0) {
            return Ok(());
        }
        let off = view.call_site_off(cs)?;
        let (vals, _) = view.encoded_array(view.physical(), off as usize)?;
        for v in &vals {
            self.walk_encoded_value(view, v, 0)?;
        }
        let arr = EncodedValue::Array(vals);
        self.call_site_records.push((cs, off, arr));
        Ok(())
    }

    fn add_method_handle(
        &mut self,
        view: &DexView<'_>,
        mh: MethodHandleIdx,
    ) -> Result<(), RebuildError> {
        if !self.method_handles.insert(mh.0) {
            return Ok(());
        }
        let item = view.method_handle(mh)?;
        let target: u16 = match item.target {
            asc_dex::FieldOrMethod::Field(f) => {
                self.walk_field(view, f)?;
                f.0 as u16
            }
            asc_dex::FieldOrMethod::Method(m) => {
                self.walk_method(view, m, 0)?;
                m.0 as u16
            }
        };
        self.method_handle_records
            .push((mh, item.handle_type, target));
        Ok(())
    }

    fn walk_debug_info(&mut self, view: &DexView<'_>, dbg_off: u32) -> Result<(), RebuildError> {
        let Some(header) = view.debug_info(dbg_off)? else {
            return Ok(());
        };
        for name in header.parameter_names.iter().flatten() {
            self.add_string(name.0)?;
        }
        for op in view.debug_ops(dbg_off)? {
            let op = op?;
            use asc_dex::DebugOp::*;
            match op {
                StartLocal { name, ty, .. } => {
                    if let Some(n) = name {
                        self.add_string(n.0)?;
                    }
                    if let Some(t) = ty {
                        self.add_type(t.0)?;
                        let sidx = view.type_(t)?;
                        self.add_string(sidx.0)?;
                        self.record_type(view, t, sidx)?;
                    }
                }
                StartLocalExtended { name, ty, sig, .. } => {
                    if let Some(n) = name {
                        self.add_string(n.0)?;
                    }
                    if let Some(t) = ty {
                        self.add_type(t.0)?;
                        let sidx = view.type_(t)?;
                        self.add_string(sidx.0)?;
                        self.record_type(view, t, sidx)?;
                    }
                    if let Some(s) = sig {
                        self.add_string(s.0)?;
                    }
                }
                SetFile { name: Some(n) } => {
                    self.add_string(n.0)?;
                }
                SetFile { name: None } => {}
                _ => {}
            }
        }
        Ok(())
    }

    fn walk_annotations_directory(
        &mut self,
        view: &DexView<'_>,
        dir_off: u32,
    ) -> Result<(), RebuildError> {
        let Some(dir) = view.annotations_directory(dir_off)? else {
            return Ok(());
        };
        if dir.class_annotations_off != 0 {
            self.walk_annotation_set(view, dir.class_annotations_off)?;
        }
        for fa in &dir.fields {
            self.walk_field(view, fa.field_idx)?;
            if fa.annotations_off != 0 {
                self.walk_annotation_set(view, fa.annotations_off)?;
            }
        }
        for ma in &dir.methods {
            self.walk_method(view, ma.method_idx, 0)?;
            if ma.annotations_off != 0 {
                self.walk_annotation_set(view, ma.annotations_off)?;
            }
        }
        for pa in &dir.parameters {
            self.walk_method(view, pa.method_idx, 0)?;
            if pa.annotations_off != 0 {
                self.walk_annotation_set_ref_list(view, pa.annotations_off)?;
            }
        }
        Ok(())
    }

    fn walk_annotation_set(
        &mut self,
        view: &DexView<'_>,
        set_off: u32,
    ) -> Result<(), RebuildError> {
        let set = view.annotation_set(set_off)?;
        for &item_off in &set.annotation_offs {
            if item_off == 0 {
                continue;
            }
            self.walk_annotation_item(view, item_off)?;
        }
        Ok(())
    }

    fn walk_annotation_set_ref_list(
        &mut self,
        view: &DexView<'_>,
        ref_off: u32,
    ) -> Result<(), RebuildError> {
        let refs = view.annotation_set_ref_list(ref_off)?;
        for &set_off in &refs.annotation_set_offs {
            if set_off == 0 {
                continue;
            }
            self.walk_annotation_set(view, set_off)?;
        }
        Ok(())
    }

    fn walk_annotation_item(
        &mut self,
        view: &DexView<'_>,
        item_off: u32,
    ) -> Result<(), RebuildError> {
        let Some(item) = view.annotation_item(item_off)? else {
            return Ok(());
        };
        self.walk_encoded_annotation(view, &item.annotation, 0)?;
        Ok(())
    }

    fn walk_encoded_annotation(
        &mut self,
        view: &DexView<'_>,
        ann: &asc_dex::EncodedAnnotation,
        depth: u8,
    ) -> Result<(), RebuildError> {
        if depth >= asc_dex::ENCODED_VALUE_MAX_DEPTH {
            return Err(RebuildError::EncodedValueDepth {
                off: 0,
                max: asc_dex::ENCODED_VALUE_MAX_DEPTH,
            });
        }
        self.add_type(ann.type_idx.0)?;
        let sidx = view.type_(ann.type_idx)?;
        self.add_string(sidx.0)?;
        self.record_type(view, ann.type_idx, sidx)?;
        for (name, v) in &ann.elements {
            self.add_string(name.0)?;
            self.walk_encoded_value(view, v, depth + 1)?;
        }
        Ok(())
    }

    fn walk_encoded_value(
        &mut self,
        view: &DexView<'_>,
        v: &EncodedValue,
        depth: u8,
    ) -> Result<(), RebuildError> {
        if depth >= asc_dex::ENCODED_VALUE_MAX_DEPTH {
            return Err(RebuildError::EncodedValueDepth {
                off: 0,
                max: asc_dex::ENCODED_VALUE_MAX_DEPTH,
            });
        }
        match v {
            EncodedValue::Byte(_)
            | EncodedValue::Short(_)
            | EncodedValue::Char(_)
            | EncodedValue::Int(_)
            | EncodedValue::Long(_)
            | EncodedValue::Float(_)
            | EncodedValue::Double(_)
            | EncodedValue::Null
            | EncodedValue::Boolean(_) => Ok(()),
            EncodedValue::MethodType(idx) => {
                if *idx != u32::MAX {
                    self.walk_proto(view, ProtoIdx(*idx))?;
                }
                Ok(())
            }
            EncodedValue::MethodHandle(idx) => {
                if *idx != u32::MAX {
                    self.add_method_handle(view, MethodHandleIdx(*idx))?;
                }
                Ok(())
            }
            EncodedValue::String(s) => {
                self.add_string(s.0)?;
                Ok(())
            }
            EncodedValue::Type(t) => {
                self.add_type(t.0)?;
                let sidx = view.type_(*t)?;
                self.add_string(sidx.0)?;
                self.record_type(view, *t, sidx)?;
                Ok(())
            }
            EncodedValue::Field(f) => {
                self.walk_field(view, *f)?;
                Ok(())
            }
            EncodedValue::Method(m) => {
                self.walk_method(view, *m, 0)?;
                Ok(())
            }
            EncodedValue::Enum(f) => {
                self.walk_field(view, *f)?;
                Ok(())
            }
            EncodedValue::Array(items) => {
                for item in items {
                    self.walk_encoded_value(view, item, depth + 1)?;
                }
                Ok(())
            }
            EncodedValue::Annotation(ann) => self.walk_encoded_annotation(view, ann, depth + 1),
        }
    }

    fn walk_encoded_array(
        &mut self,
        view: &DexView<'_>,
        off: u32,
        depth: u8,
    ) -> Result<(), RebuildError> {
        let (vals, _) = view.encoded_array(view.physical(), off as usize)?;
        for v in &vals {
            self.walk_encoded_value(view, v, depth)?;
        }
        Ok(())
    }

    fn record_type(
        &mut self,
        view: &DexView<'_>,
        type_idx: TypeIdx,
        descriptor: StringIdx,
    ) -> Result<(), RebuildError> {
        if let Some(existing) = self.type_descriptor.iter().find(|(t, _)| *t == type_idx) {
            if existing.1 != descriptor {
                return Err(RebuildError::Internal(
                    "type_idx maps to multiple descriptor strings",
                ));
            }
        } else {
            self.type_descriptor.push((type_idx, descriptor));
        }
        self.add_string(descriptor.0)?;
        let _ = view;
        Ok(())
    }

    fn record_field(
        &mut self,
        idx: FieldIdx,
        class: TypeIdx,
        ty: TypeIdx,
        name: StringIdx,
    ) -> Result<(), RebuildError> {
        if let Some(existing) = self.field_records.iter().find(|(i, _, _, _)| *i == idx) {
            if existing.1 != class || existing.2 != ty || existing.3 != name {
                return Err(RebuildError::Internal(
                    "field_idx maps to multiple (class,type,name) tuples",
                ));
            }
            return Ok(());
        }
        self.field_records.push((idx, class, ty, name));
        Ok(())
    }

    fn record_method(
        &mut self,
        idx: MethodIdx,
        class: TypeIdx,
        proto: ProtoIdx,
        name: StringIdx,
    ) -> Result<(), RebuildError> {
        if let Some(existing) = self.method_records.iter().find(|(i, _, _, _)| *i == idx) {
            if existing.1 != class || existing.2 != proto || existing.3 != name {
                return Err(RebuildError::Internal(
                    "method_idx maps to multiple (class,proto,name) tuples",
                ));
            }
            return Ok(());
        }
        self.method_records.push((idx, class, proto, name));
        Ok(())
    }

    fn copy_debug_info_raw(&self, view: &DexView<'_>, off: u32) -> Result<Vec<u8>, RebuildError> {
        let p = off as usize;
        let _ = view
            .debug_info(off)?
            .ok_or(asc_dex::DexError::InvalidLength {
                off: p,
                message: "debug_info_off != 0 but debug_info returned None",
            })?;
        let mut q = p;
        let (_line_start, n) = asc_dex::leb::uleb128_to_u32(&view.physical()[q..])?;
        q += n;
        let (params_size, n) = asc_dex::leb::uleb128_to_u32(&view.physical()[q..])?;
        q += n;
        for _ in 0..params_size {
            let (_v, n) = asc_dex::leb::uleb128_to_u32(&view.physical()[q..])?;
            q += n;
        }
        loop {
            if q >= view.physical().len() {
                return Err(asc_dex::DexError::Truncated {
                    needed: q + 1,
                    actual: view.physical().len(),
                }
                .into());
            }
            let op = view.physical()[q];
            q += 1;
            match op {
                asc_dex::DBG_END_SEQUENCE => break,
                asc_dex::DBG_ADVANCE_PC | asc_dex::DBG_SET_FILE => {
                    let (_v, n) = asc_dex::leb::uleb128_to_u32(&view.physical()[q..])?;
                    q += n;
                }
                asc_dex::DBG_ADVANCE_LINE => {
                    let (_v, n) = asc_dex::leb::sleb128_to_i32(&view.physical()[q..])?;
                    q += n;
                }
                asc_dex::DBG_START_LOCAL => {
                    for _ in 0..3 {
                        let (_t, n) = asc_dex::leb::uleb128_to_u32(&view.physical()[q..])?;
                        q += n;
                    }
                }
                asc_dex::DBG_START_LOCAL_EXTENDED => {
                    for _ in 0..4 {
                        let (_t, n) = asc_dex::leb::uleb128_to_u32(&view.physical()[q..])?;
                        q += n;
                    }
                }
                asc_dex::DBG_END_LOCAL | asc_dex::DBG_RESTART_LOCAL => {
                    let (_v, n) = asc_dex::leb::uleb128_to_u32(&view.physical()[q..])?;
                    q += n;
                }
                asc_dex::DBG_SET_PROLOGUE_END | asc_dex::DBG_SET_EPILOGUE_BEGIN => {}
                op if op >= 0x0a => {}
                _ => {
                    return Err(RebuildError::Internal(
                        "unknown debug opcode during raw copy",
                    ));
                }
            }
        }
        Ok(view.physical()[p..q].to_vec())
    }
}

impl Closure {
    #[allow(dead_code)]
    pub(crate) fn verify_code_item(
        &self,
        insns: &[u8],
        insns_units: u32,
    ) -> Result<(), RebuildError> {
        walk_verify(insns, insns_units).map_err(|e| RebuildError::BytecodeRef {
            off: 0,
            message: format!("walk_verify: {e:?}"),
        })
    }
}

fn validate_descriptor(s: &str) -> Result<(), RebuildError> {
    if s.is_empty() {
        return Err(RebuildError::BadDescriptor(s.to_string(), "empty"));
    }
    if !s.starts_with('L') && !s.starts_with('[') {
        return Err(RebuildError::BadDescriptor(
            s.to_string(),
            "must start with `L` or `[`",
        ));
    }
    if !s.ends_with(';') {
        return Err(RebuildError::BadDescriptor(
            s.to_string(),
            "must end with `;`",
        ));
    }
    if s.as_bytes().iter().any(|&b| b == b' ' || b == b',') {
        return Err(RebuildError::BadDescriptor(
            s.to_string(),
            "may not contain spaces or commas",
        ));
    }
    Ok(())
}

impl Closure {
    pub(crate) fn needs_038(&self) -> bool {
        !self.call_sites.is_empty() || !self.method_handles.is_empty()
    }

    #[allow(dead_code)]
    pub(crate) fn strings_sorted_for_layout(&self) -> Vec<u32> {
        self.strings.iter().copied().collect()
    }
}

#[allow(dead_code)]
const _VALUE_TYPE_PRIMITIVES: &[ValueType] = &[];

// ----- ClassDefRecord accessors -----
impl ClassDefRecord {
    pub(crate) fn find_method_position(&self, old: MethodIdx) -> Option<usize> {
        if let Some(i) = self.selected_direct_methods.iter().position(|m| *m == old) {
            return Some(i);
        }
        let n = self.selected_direct_methods.len();
        self.selected_virtual_methods
            .iter()
            .position(|m| *m == old)
            .map(|i| n + i)
    }
    pub(crate) fn source_code_off(&self, old: MethodIdx) -> u32 {
        let Some(p) = self.find_method_position(old) else {
            return 0;
        };
        if !self.method_has_code[p] {
            return 0;
        }
        let Some(cd) = &self.class_data else {
            return 0;
        };
        let n = self.selected_direct_methods.len();
        if p < n {
            cd.direct_methods.get(p).map(|m| m.code_off).unwrap_or(0)
        } else {
            cd.virtual_methods
                .get(p - n)
                .map(|m| m.code_off)
                .unwrap_or(0)
        }
    }
}

// ----- Iterator over a class-def record's methods (in class_data order) -----
pub(crate) struct MethodIter<'a> {
    rec: &'a ClassDefRecord,
    idx: usize,
}

impl<'a> MethodIter<'a> {
    pub(crate) fn new(rec: &'a ClassDefRecord) -> Self {
        Self { rec, idx: 0 }
    }
    pub(crate) fn next(&mut self) -> Option<(MethodIdx, bool, usize)> {
        let total = self.rec.method_has_code.len();
        if self.idx >= total {
            return None;
        }
        let i = self.idx;
        self.idx += 1;
        let (m, has_code) = if i < self.rec.selected_direct_methods.len() {
            (
                self.rec.selected_direct_methods[i],
                self.rec.method_has_code[i],
            )
        } else {
            let j = i - self.rec.selected_direct_methods.len();
            (
                self.rec.selected_virtual_methods[j],
                self.rec.method_has_code[i],
            )
        };
        Some((m, has_code, i))
    }
}
