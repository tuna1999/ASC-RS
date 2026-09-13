//! Integration tests that exercise the asc-dex reader against a hand-crafted
//! valid DEX blob.

mod common;

use asc_dex::*;
use common::{layout, tiny_dex};

#[test]
fn parses_header() {
    let buf = tiny_dex();
    let view = DexView::parse(&buf).expect("header valid");
    assert_eq!(view.version().as_str(), "035");
    assert_eq!(view.string_count(), 3);
    assert_eq!(view.type_count(), 2);
    assert_eq!(view.proto_count(), 1);
    assert_eq!(view.field_count(), 1);
    assert_eq!(view.method_count(), 2);
    assert_eq!(view.class_def_count(), 1);
}

#[test]
fn reads_strings() {
    let buf = tiny_dex();
    let view = DexView::parse(&buf).unwrap();
    let s0 = view.string(StringIdx(0)).unwrap();
    assert_eq!(s0.utf16_len, 7);
    assert_eq!(s0.decode_lossy().as_ref(), "LTest;");
    let s1 = view.string(StringIdx(1)).unwrap();
    assert_eq!(s1.decode_lossy().as_ref(), "main");
    let s2 = view.string(StringIdx(2)).unwrap();
    assert_eq!(s2.decode_lossy().as_ref(), "V");
}

#[test]
fn reads_type_descriptors() {
    let buf = tiny_dex();
    let view = DexView::parse(&buf).unwrap();
    let t0 = view.type_(TypeIdx(0)).unwrap();
    assert_eq!(t0, StringIdx(0));
    let t1 = view.type_(TypeIdx(1)).unwrap();
    assert_eq!(t1, StringIdx(2));
}

#[test]
fn reads_proto_with_params() {
    let buf = tiny_dex();
    let view = DexView::parse(&buf).unwrap();
    let p = view.proto(ProtoIdx(0)).unwrap();
    assert_eq!(p.shorty, StringIdx(1));
    assert_eq!(p.return_type, TypeIdx(1));
    assert_eq!(p.parameters.len(), 1);
    assert_eq!(p.parameters.get(0).unwrap(), TypeIdx(1));
}

#[test]
fn reads_field() {
    let buf = tiny_dex();
    let view = DexView::parse(&buf).unwrap();
    let f = view.field(FieldIdx(0)).unwrap();
    assert_eq!(f.class, TypeIdx(0));
    assert_eq!(f.ty, TypeIdx(1));
    assert_eq!(f.name, StringIdx(0));
}

#[test]
fn reads_methods() {
    let buf = tiny_dex();
    let view = DexView::parse(&buf).unwrap();
    let m = view.method(MethodIdx(0)).unwrap();
    assert_eq!(m.class, TypeIdx(0));
    assert_eq!(m.proto, ProtoIdx(0));
    assert_eq!(m.name, StringIdx(1));
}

#[test]
fn reads_class_def() {
    let buf = tiny_dex();
    let view = DexView::parse(&buf).unwrap();
    let cd = view.class_def(0).unwrap();
    assert_eq!(cd.class, TypeIdx(0));
    assert_eq!(cd.access_flags, 1);
    assert!(cd.superclass.is_none());
    assert!(cd.source_file.is_none());
    assert_eq!(cd.class_data_off, layout::CLASS_DATA_OFF);
}

#[test]
fn reads_class_data() {
    let buf = tiny_dex();
    let view = DexView::parse(&buf).unwrap();
    let data = view.class_data(layout::CLASS_DATA_OFF).unwrap().unwrap();
    assert_eq!(data.static_fields.len(), 0);
    assert_eq!(data.instance_fields.len(), 0);
    assert_eq!(data.direct_methods.len(), 1);
    assert_eq!(data.virtual_methods.len(), 0);
    let m = &data.direct_methods[0];
    assert_eq!(m.method_idx, MethodIdx(0));
    assert_eq!(m.access_flags, 1);
    assert_eq!(m.code_off, layout::CODE_OFF);
}

#[test]
fn reads_code_item() {
    let buf = tiny_dex();
    let view = DexView::parse(&buf).unwrap();
    let code = view.code_item(layout::CODE_OFF).unwrap().unwrap();
    assert_eq!(code.registers_size, 1);
    assert_eq!(code.ins_size, 1);
    assert_eq!(code.outs_size, 0);
    assert_eq!(code.tries_size, 1);
    assert_eq!(code.debug_info_off, layout::DEBUG_OFF);
    assert_eq!(code.insns_size, 3);
    // 3 units * 2 bytes + 2 bytes padding = 8 bytes total
    assert_eq!(code.insns.len(), 8);
}

#[test]
fn reads_tries() {
    let buf = tiny_dex();
    let view = DexView::parse(&buf).unwrap();
    let code = view.code_item(layout::CODE_OFF).unwrap().unwrap();
    let tries: Vec<_> = view.tries_iter(&code).unwrap().collect();
    assert_eq!(tries.len(), 1);
    assert_eq!(tries[0].start_addr, 0);
    assert_eq!(tries[0].insn_count, 3);
    assert_eq!(tries[0].handler_off, 0);
}

#[test]
fn reads_catch_handlers() {
    let buf = tiny_dex();
    let view = DexView::parse(&buf).unwrap();
    let code = view.code_item(layout::CODE_OFF).unwrap().unwrap();
    let list = view.catch_handler_list(&code).unwrap().unwrap();
    let tries: Vec<_> = view.tries_iter(&code).unwrap().collect();
    let handler = view.catch_handler(&list, &tries[0]).unwrap();
    assert_eq!(handler.pairs.len(), 1);
    assert_eq!(handler.pairs[0].0, 1);
    assert_eq!(handler.pairs[0].1, 0);
    assert_eq!(handler.catch_all_addr, None);
}

#[test]
fn reads_debug_info() {
    let buf = tiny_dex();
    let view = DexView::parse(&buf).unwrap();
    let hdr = view.debug_info(layout::DEBUG_OFF).unwrap().unwrap();
    assert_eq!(hdr.line_start, 1);
    assert_eq!(hdr.parameter_names.len(), 1);
    assert_eq!(hdr.parameter_names[0], Some(StringIdx(1)));
    let ops: Vec<_> = view
        .debug_ops(layout::DEBUG_OFF)
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert!(matches!(ops[0], DebugOp::EndSequence));
}

#[test]
fn reads_annotations_directory() {
    let buf = tiny_dex();
    let view = DexView::parse(&buf).unwrap();
    let dir = view
        .annotations_directory(layout::ANNOTATIONS_DIR_OFF)
        .unwrap()
        .unwrap();
    assert_eq!(dir.class_annotations_off, 0);
    assert!(dir.fields.is_empty());
    assert!(dir.methods.is_empty());
    assert!(dir.parameters.is_empty());
}

#[test]
fn reads_map_list() {
    let buf = tiny_dex();
    let view = DexView::parse(&buf).unwrap();
    let entries: Vec<_> = view.map_list().unwrap().map(|r| r.unwrap()).collect();
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0].ty, map::MAP_TYPE_HEADER_ITEM);
    assert_eq!(entries[1].ty, map::MAP_TYPE_CODE_ITEM);
    assert_eq!(entries[1].offset, layout::CODE_OFF);
}
