//! Synthetic tables: the corpus only covers dense, package 0x7f layouts, so
//! every other variant is built by hand here.

use super::*;

fn w16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn w32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// UTF-16 string pool chunk. `long` encodes the first string with the
/// extended 32-bit length form.
fn pool(strings: &[&str], long_first: bool) -> Vec<u8> {
    let mut data = Vec::new();
    let mut offs = Vec::new();
    for (i, s) in strings.iter().enumerate() {
        offs.push(data.len() as u32);
        let u: Vec<u16> = s.encode_utf16().collect();
        if long_first && i == 0 {
            w16(&mut data, 0x8000 | (u.len() >> 16) as u16);
            w16(&mut data, u.len() as u16);
        } else {
            w16(&mut data, u.len() as u16);
        }
        for x in u {
            w16(&mut data, x);
        }
        w16(&mut data, 0);
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let start = 28 + 4 * strings.len() as u32;
    let mut v = Vec::new();
    w16(&mut v, 1);
    w16(&mut v, 28);
    w32(&mut v, start + data.len() as u32);
    w32(&mut v, strings.len() as u32);
    w32(&mut v, 0);
    w32(&mut v, 0);
    w32(&mut v, start);
    w32(&mut v, 0);
    for o in offs {
        w32(&mut v, o);
    }
    v.extend_from_slice(&data);
    v
}

fn full(key: u32, ty: u8, data: u32) -> Vec<u8> {
    let mut v = Vec::new();
    w16(&mut v, 8);
    w16(&mut v, 0);
    w32(&mut v, key);
    w16(&mut v, 8);
    v.push(0);
    v.push(ty);
    w32(&mut v, data);
    v
}

fn bag(key: u32, parent: u32, items: &[(u32, u8, u32)]) -> Vec<u8> {
    let mut v = Vec::new();
    w16(&mut v, 16);
    w16(&mut v, ENTRY_COMPLEX);
    w32(&mut v, key);
    w32(&mut v, parent);
    w32(&mut v, items.len() as u32);
    for &(n, t, d) in items {
        w32(&mut v, n);
        w16(&mut v, 8);
        v.push(0);
        v.push(t);
        w32(&mut v, d);
    }
    v
}

fn compact(key: u16, ty: u8, data: u32) -> Vec<u8> {
    let mut v = Vec::new();
    w16(&mut v, key);
    w16(&mut v, ENTRY_COMPACT | (ty as u16) << 8);
    w32(&mut v, data);
    v
}

/// Type chunk with a 28-byte config (not the usual 64) carrying `sdk`.
fn type_chunk(
    id: u8,
    flags: u8,
    sdk: u16,
    count: u32,
    offset_table: &[u8],
    entries: &[u8],
) -> Vec<u8> {
    let hs = 20 + 28;
    let mut v = Vec::new();
    w16(&mut v, RES_TYPE);
    w16(&mut v, hs as u16);
    w32(&mut v, (hs + offset_table.len() + entries.len()) as u32);
    v.push(id);
    v.push(flags);
    w16(&mut v, 0);
    w32(&mut v, count);
    w32(&mut v, (hs + offset_table.len()) as u32);
    let mut cfg = vec![0u8; 28];
    cfg[..4].copy_from_slice(&28u32.to_le_bytes());
    cfg[24..26].copy_from_slice(&sdk.to_le_bytes());
    v.extend_from_slice(&cfg);
    v.extend_from_slice(offset_table);
    v.extend_from_slice(entries);
    v
}

fn dense_offsets(offs: &[u32]) -> Vec<u8> {
    let mut v = Vec::new();
    for &o in offs {
        w32(&mut v, o);
    }
    v
}

fn package(
    id: u32,
    type_names: &[&str],
    key_names: &[&str],
    offset: u32,
    kids: &[Vec<u8>],
) -> Vec<u8> {
    let tp = pool(type_names, false);
    let kp = pool(key_names, false);
    let mut v = Vec::new();
    w16(&mut v, RES_PACKAGE);
    w16(&mut v, 288);
    let size_at = v.len();
    w32(&mut v, 0);
    w32(&mut v, id);
    let mut name = [0u8; 256];
    for (i, u) in "com.test".encode_utf16().enumerate() {
        name[2 * i..2 * i + 2].copy_from_slice(&u.to_le_bytes());
    }
    v.extend_from_slice(&name);
    w32(&mut v, 288);
    w32(&mut v, 0);
    w32(&mut v, 288 + tp.len() as u32);
    w32(&mut v, 0);
    w32(&mut v, offset);
    v.extend_from_slice(&tp);
    v.extend_from_slice(&kp);
    for k in kids {
        v.extend_from_slice(k);
    }
    let n = v.len() as u32;
    v[size_at..size_at + 4].copy_from_slice(&n.to_le_bytes());
    v
}

fn table(global: &[u8], pkgs: &[Vec<u8>]) -> Vec<u8> {
    let mut body = global.to_vec();
    for p in pkgs {
        body.extend_from_slice(p);
    }
    let mut v = Vec::new();
    w16(&mut v, RES_TABLE);
    w16(&mut v, 12);
    w32(&mut v, 12 + body.len() as u32);
    w32(&mut v, pkgs.len() as u32);
    v.extend_from_slice(&body);
    v
}

#[test]
fn id_uses_entry_index_not_key_index() {
    // Entry 0 of type 2 has key string index 42; the ID must be 0x7f020000.
    let keys: Vec<String> = (0..43).map(|i| format!("k{i}")).collect();
    let krefs: Vec<&str> = keys.iter().map(String::as_str).collect();
    let t = type_chunk(2, 0, 0, 1, &dense_offsets(&[0]), &full(42, 0x10, 7));
    let arsc = table(
        &pool(&["g"], false),
        &[package(0x7f, &["attr", "drawable"], &krefs, 0, &[t])],
    );
    let tb = parse(&arsc).unwrap();
    assert!(tb.complete, "{:?}", tb.diagnostics);
    let e = &tb.packages[0].entries[0];
    assert_eq!(e.id, 0x7f02_0000);
    assert_eq!(e.key_index, 42);
    assert_eq!(tb.packages[0].key_name(e), "k42");
    assert_eq!(tb.packages[0].type_name(2), "drawable");
    assert!(tb.by_id(0x7f02_002a).next().is_none());
    assert_eq!(
        tb.render(Res {
            data_type: 0x10,
            data: 7
        }),
        "7"
    );
}

#[test]
fn type_id_offset_shifts_the_id() {
    let t = type_chunk(1, 0, 0, 1, &dense_offsets(&[0]), &full(0, 0x12, 1));
    let arsc = table(
        &pool(&[], false),
        &[package(0x7f, &["string"], &["a"], 3, &[t])],
    );
    let tb = parse(&arsc).unwrap();
    assert_eq!(tb.packages[0].entries[0].id, 0x7f04_0000);
}

#[test]
fn same_id_in_two_configs_are_both_kept() {
    let a = type_chunk(1, 0, 0, 1, &dense_offsets(&[0]), &full(0, 0x10, 1));
    let b = type_chunk(1, 0, 21, 1, &dense_offsets(&[0]), &full(0, 0x10, 2));
    let arsc = table(
        &pool(&[], false),
        &[package(0x7f, &["integer"], &["n"], 0, &[a, b])],
    );
    let tb = parse(&arsc).unwrap();
    let hits: Vec<_> = tb.by_id(0x7f01_0000).collect();
    assert_eq!(hits.len(), 2);
    let cfgs: Vec<String> = hits
        .iter()
        .map(|(p, e)| describe_config(&p.configs[e.config as usize]))
        .collect();
    assert_eq!(cfgs[0], "default");
    assert!(cfgs[1].starts_with("v21"), "{cfgs:?}");
}

#[test]
fn dense_holes_sparse_offset16_bag_and_compact() {
    // dense with a NO_ENTRY hole: entries 0 and 2 exist
    let mut ents = full(0, 0x10, 10);
    let second = ents.len() as u32;
    ents.extend(full(0, 0x10, 30));
    let dense = type_chunk(1, 0, 0, 3, &dense_offsets(&[0, u32::MAX, second]), &ents);

    // sparse: only entry index 300 exists
    let mut sp = Vec::new();
    w16(&mut sp, 300);
    w16(&mut sp, 0);
    let sparse = type_chunk(2, FLAG_SPARSE, 0, 1, &sp, &full(0, 0x10, 99));

    // offset16: entry 1 at byte 8 (= 2 * 4), entry 0 absent
    let mut o16 = Vec::new();
    w16(&mut o16, 0xffff);
    w16(&mut o16, 2);
    let mut e16 = full(0, 0x10, 0); // padding entry at 0..16
    e16.extend(full(0, 0x10, 55));
    // value of first entry occupies 0..16, so second starts at 16 -> offset 4*4
    o16[2..4].copy_from_slice(&4u16.to_le_bytes());
    let off16 = type_chunk(3, FLAG_OFFSET16, 0, 2, &o16, &e16);

    let b = type_chunk(
        4,
        0,
        0,
        1,
        &dense_offsets(&[0]),
        &bag(
            0,
            0x0100_0001,
            &[(0x0101_0000, 0x10, 5), (0x0101_0001, 0x03, 0)],
        ),
    );
    let c = type_chunk(5, 0, 0, 1, &dense_offsets(&[0]), &compact(0, 0x12, 1));

    let arsc = table(
        &pool(&["hello"], false),
        &[package(
            0x7f,
            &["a", "b", "c", "d", "e"],
            &["k"],
            0,
            &[dense, sparse, off16, b, c],
        )],
    );
    let tb = parse(&arsc).unwrap();
    assert!(tb.complete, "{:?}", tb.diagnostics);
    let ids: Vec<u32> = tb.packages[0].entries.iter().map(|e| e.id).collect();
    assert_eq!(
        ids,
        [
            0x7f01_0000,
            0x7f01_0002,
            0x7f02_012c,
            0x7f03_0001,
            0x7f04_0000,
            0x7f05_0000
        ]
    );
    let val = |id| match &tb.by_id(id).next().unwrap().1.value {
        Value::Simple(r) => *r,
        v => panic!("{v:?}"),
    };
    assert_eq!(val(0x7f01_0002).data, 30);
    assert_eq!(val(0x7f02_012c).data, 99);
    assert_eq!(val(0x7f03_0001).data, 55);
    assert_eq!(
        val(0x7f05_0000),
        Res {
            data_type: 0x12,
            data: 1
        }
    );
    let Value::Bag { parent, items } = &tb.by_id(0x7f04_0000).next().unwrap().1.value else {
        panic!("not a bag")
    };
    assert_eq!(*parent, 0x0100_0001);
    assert_eq!(items.len(), 2);
    assert_eq!(items[1].0, 0x0101_0001);
    // TYPE_STRING resolves in the global pool.
    assert_eq!(
        tb.render(Res {
            data_type: 3,
            data: 0
        }),
        "\"hello\""
    );
    // Unresolved system reference keeps its raw ID.
    assert_eq!(
        tb.render(Res {
            data_type: 1,
            data: 0x0101_0000
        }),
        "@0x01010000"
    );
}

#[test]
fn extended_length_global_string_is_kept() {
    let arsc = table(&pool(&["long form"], true), &[]);
    let tb = parse(&arsc).unwrap();
    assert_eq!(tb.strings, ["long form"]);
    assert!(tb.complete);
}

#[test]
fn overrunning_chunks_degrade_to_diagnostics() {
    let t = type_chunk(
        1,
        0,
        0,
        1,
        &dense_offsets(&[0x7fff_0000]),
        &full(0, 0x10, 1),
    );
    let arsc = table(&pool(&[], false), &[package(0x7f, &["a"], &["k"], 0, &[t])]);
    let tb = parse(&arsc).unwrap();
    assert!(!tb.complete);
    assert!(tb.packages[0].entries.is_empty());
    assert!(
        tb.diagnostics[0].contains("overruns"),
        "{:?}",
        tb.diagnostics
    );

    // A bag whose count claims more items than the chunk holds.
    let mut b = bag(0, 0, &[(1, 0x10, 1)]);
    b[12..16].copy_from_slice(&1_000_000u32.to_le_bytes());
    let t = type_chunk(1, 0, 0, 1, &dense_offsets(&[0]), &b);
    let arsc = table(&pool(&[], false), &[package(0x7f, &["a"], &["k"], 0, &[t])]);
    let tb = parse(&arsc).unwrap();
    assert!(!tb.complete);
    assert!(tb.packages[0].entries.is_empty());
}

#[test]
fn dense_entry_count_beyond_16_bits_is_rejected() {
    let mut t = type_chunk(1, 0, 0, 0, &[], &[]);
    t[12..16].copy_from_slice(&0x2_0000u32.to_le_bytes());
    let arsc = table(&pool(&[], false), &[package(0x7f, &["a"], &["k"], 0, &[t])]);
    let tb = parse(&arsc).unwrap();
    assert!(!tb.complete);
    assert!(tb.diagnostics[0].contains("16-bit"), "{:?}", tb.diagnostics);
}

#[test]
fn bad_chunk_size_stops_the_walk_without_looping() {
    let mut arsc = table(&pool(&[], false), &[package(0x7f, &["a"], &["k"], 0, &[])]);
    // corrupt the package chunk size to zero-progress
    let off = 12 + pool(&[], false).len();
    arsc[off + 4..off + 8].copy_from_slice(&0u32.to_le_bytes());
    let tb = parse(&arsc).unwrap();
    assert!(!tb.complete);
    assert!(tb.packages.is_empty());
}

#[test]
fn non_table_input_is_an_error() {
    assert!(parse(b"nope").is_err());
    assert!(parse(&[1, 0, 12, 0, 12, 0, 0, 0, 0, 0, 0, 0]).is_err());
}
