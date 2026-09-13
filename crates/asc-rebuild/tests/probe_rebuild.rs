//! TEMPORARY Lead probe — identify pool item 36715 in the workload dex
//! and check whether it is a proto shorty / debug name / etc.

use asc_dex::ids::StringIdx;

#[test]
fn probe_idx_36715() {
    let bytes = std::fs::read("../../corpus/dex/workload_classes.dex").expect("corpus dex present");
    let view = asc_dex::DexView::parse(&bytes).expect("parse");
    eprintln!(
        "counts: strings={} types={} protos={} fields={} methods={} classes={}",
        view.string_count(),
        view.type_count(),
        view.proto_count(),
        view.field_count(),
        view.method_count(),
        view.class_def_count()
    );
    let s = view.string(StringIdx(36715)).expect("string 36715");
    eprintln!("string[36715] = {:?}", s.decode_lossy());

    // Which protos use it as shorty?
    let mut hits = 0u32;
    for i in 0..view.proto_count() {
        let p = view.proto(asc_dex::ids::ProtoIdx(i)).expect("proto");
        if p.shorty.0 == 36715 {
            hits += 1;
            if hits <= 5 {
                eprintln!("proto[{i}] shorty = string[36715]");
            }
        }
    }
    eprintln!("protos using string[36715] as shorty: {hits}");
}
