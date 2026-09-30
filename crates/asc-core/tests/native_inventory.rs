//! `run_native` against the real Locket APK (skips when the fixture is
//! absent): the walk must cover BOTH class_data method lists.

#[test]
fn locket_counts_direct_and_virtual_natives() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/apk/com.locket.Locket.apk");
    if !p.exists() {
        eprintln!("skipping: Locket fixture not present");
        return;
    }
    let r = asc_core::run_native(&p).expect("run_native");
    // Byte-walk of the DEX (roadmap evidence): 447 direct + 174 virtual.
    assert_eq!((r.direct_count, r.virtual_count), (447, 174));
    assert!(r.complete, "{:?}", r.errors);
    assert!(r.libs.is_empty(), "base APK carries no lib/*.so");
    assert!(
        r.note.is_some(),
        "unbound natives must carry the dynamic-registration caveat"
    );
}
