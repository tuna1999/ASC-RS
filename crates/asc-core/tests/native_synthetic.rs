//! Synthetic APK: one class with an overloaded native pair (direct static +
//! virtual public instance, both `code_off = 0`) plus a non-native virtual,
//! and two ELF libs exporting short/long JNI names. Exercises the DEX walk,
//! the direct+virtual coverage, short/long matching and the ABI cross-check.

use asc_core::run_native;

fn p16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn p32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn p64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

/// DEX 035: `LNat;` with `nat()V` (direct static native), `nat(I)V`
/// (virtual public native) and `other(I)V` (virtual, not native).
fn dex() -> Vec<u8> {
    // strings sorted: I, LNat;, V, nat, other
    let strs: [&[u8]; 5] = [b"I", b"LNat;", b"V", b"nat", b"other"];
    let mut b = vec![0u8; 0x400];
    b[..8].copy_from_slice(b"dex\n035\0");
    p32(&mut b, 0x24, 0x70);
    p32(&mut b, 0x28, 0x1234_5678);
    // (size, off) pairs: string 0x70, type 0x84, proto 0x94, method 0xAC, class_def 0xC4
    for (at, size, off) in [
        (0x38, 5, 0x70),
        (0x40, 3, 0x84),
        (0x48, 2, 0x94),
        (0x58, 3, 0xAC),
        (0x60, 1, 0xC4),
    ] {
        p32(&mut b, at, size);
        p32(&mut b, at + 4, off);
    }
    // string data at 0x110, ids point at each entry
    let mut sd = 0x110usize;
    for (i, s) in strs.iter().enumerate() {
        p32(&mut b, 0x70 + i * 4, sd as u32);
        b[sd] = s.len() as u8; // utf16 length (ASCII)
        b[sd + 1..sd + 1 + s.len()].copy_from_slice(s);
        sd += s.len() + 2;
    }
    // types: I, LNat;, V
    for (i, s) in [0u32, 1, 2].iter().enumerate() {
        p32(&mut b, 0x84 + i * 4, *s);
    }
    // protos: 0 = V(I) (params at 0xE4), 1 = V()
    for (i, params) in [0xE4u32, 0].iter().enumerate() {
        p32(&mut b, 0x94 + i * 12, 2); // shorty "V"
        p32(&mut b, 0x94 + i * 12 + 4, 2); // return V
        p32(&mut b, 0x94 + i * 12 + 8, *params);
    }
    // methods: (class, proto, name): nat()V, nat(I)V, other(I)V
    for (i, (proto, name)) in [(1u16, 3u32), (0, 3), (0, 4)].iter().enumerate() {
        p16(&mut b, 0xAC + i * 8, 1);
        p16(&mut b, 0xAC + i * 8 + 2, *proto);
        p32(&mut b, 0xAC + i * 8 + 4, *name);
    }
    // class_def: class type 1, access public, super none, class_data at 0xEC
    p32(&mut b, 0xC4, 1);
    p32(&mut b, 0xC4 + 4, 1);
    p32(&mut b, 0xC4 + 8, 0xFFFF_FFFF);
    p32(&mut b, 0xC4 + 16, 0xFFFF_FFFF);
    p32(&mut b, 0xC4 + 24, 0xEC);
    // type_list for V(I) at 0xE4
    p32(&mut b, 0xE4, 1);
    p16(&mut b, 0xE8, 0);
    // class_data at 0xEC: 0 static, 0 inst, 1 direct, 2 virtual
    let cd: [u8; 12] = [
        0, 0, 1, 2, // counts
        0, 0x89, 0x02, 0, // direct: idx 0, flags 0x109 (uleb 0x89 0x02), code_off 0
        1, 0x81, 0x02, 0, // virtual: idx 1, flags 0x101, code_off 0 ...
    ];
    b[0xEC..0xEC + 12].copy_from_slice(&cd);
    // second virtual: delta 1 -> idx 2, flags 0x1 (not native), code_off 0
    b[0xF8..0xFB].copy_from_slice(&[1, 1, 0]);
    let n = b.len() as u32;
    p32(&mut b, 0x20, n);
    b
}

/// ELF64 LE with .dynsym/.dynstr sections exporting `names`.
fn elf(machine: u16, names: &[&str]) -> Vec<u8> {
    let mut strs = vec![0u8];
    let mut syms = vec![0u8; 24];
    for n in names {
        let mut s = [0u8; 24];
        s[..4].copy_from_slice(&(strs.len() as u32).to_le_bytes());
        s[4] = 0x12;
        s[6..8].copy_from_slice(&7u16.to_le_bytes());
        syms.extend_from_slice(&s);
        strs.extend_from_slice(n.as_bytes());
        strs.push(0);
    }
    let mut b = vec![0u8; 0x400];
    b[..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    p16(&mut b, 0x12, machine);
    p64(&mut b, 0x28, 0x100);
    p16(&mut b, 0x3A, 64);
    p16(&mut b, 0x3C, 3);
    p32(&mut b, 0x100 + 64 + 4, 11);
    p64(&mut b, 0x100 + 64 + 0x18, 0x200);
    p64(&mut b, 0x100 + 64 + 0x20, syms.len() as u64);
    p32(&mut b, 0x100 + 64 + 0x28, 2);
    p32(&mut b, 0x100 + 128 + 4, 3);
    p64(&mut b, 0x100 + 128 + 0x18, 0x300);
    p64(&mut b, 0x100 + 128 + 0x20, strs.len() as u64);
    b[0x200..0x200 + syms.len()].copy_from_slice(&syms);
    b[0x300..0x300 + strs.len()].copy_from_slice(&strs);
    b
}

/// STORED-only ZIP (CRC left 0: `read_entry` does not verify it).
fn zip(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let (mut out, mut cd) = (Vec::new(), Vec::new());
    for (name, data) in files {
        let off = out.len() as u32;
        let hdr = |sig: u32, central: bool| {
            let mut h = sig.to_le_bytes().to_vec();
            if central {
                h.extend_from_slice(&[20, 0]);
            }
            h.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            h.extend_from_slice(&(data.len() as u32).to_le_bytes());
            h.extend_from_slice(&(data.len() as u32).to_le_bytes());
            h.extend_from_slice(&(name.len() as u16).to_le_bytes());
            h.extend_from_slice(&[0, 0]);
            h
        };
        out.extend(hdr(0x0403_4b50, false));
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        cd.extend(hdr(0x0201_4b50, true));
        cd.extend_from_slice(&[0; 10]); // comment len, disk, int attr, ext attr
        cd.extend_from_slice(&off.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }
    let cd_off = out.len() as u32;
    out.extend_from_slice(&cd);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

#[test]
fn pairs_direct_and_virtual_natives_with_short_and_long_exports() {
    let apk = zip(&[
        ("classes.dex", dex()),
        (
            "lib/arm64-v8a/liba.so",
            elf(183, &["JNI_OnLoad", "Java_Nat_nat__I"]),
        ),
        // e_machine 183 (aarch64) under the x86 dir: must be flagged.
        ("lib/x86/libb.so", elf(183, &["Java_Nat_nat"])),
    ]);
    let path = std::env::temp_dir().join(format!("asc_native_synth_{}.apk", std::process::id()));
    std::fs::write(&path, apk).unwrap();
    let r = run_native(&path);
    std::fs::remove_file(&path).ok();
    let r = r.expect("run_native");

    assert!(r.complete, "{:?}", r.errors);
    // Non-native `other` is excluded; direct AND virtual both counted.
    assert_eq!((r.direct_count, r.virtual_count), (1, 1));
    let by = |params: usize| r.methods.iter().find(|m| m.params.len() == params).unwrap();
    let (nat0, nat1) = (by(0), by(1));
    assert_eq!((nat0.kind, nat0.code_off), ("direct", 0));
    assert_eq!((nat1.kind, nat1.code_off), ("virtual", 0));
    assert_eq!(nat0.long_jni, "Java_Nat_nat__");
    assert_eq!(nat1.long_jni, "Java_Nat_nat__I");
    // Short name `Java_Nat_nat` binds both overloads; the long form only nat(I).
    assert_eq!(nat0.matched_libs, ["lib/x86/libb.so"]);
    assert_eq!(
        nat1.matched_libs,
        ["lib/arm64-v8a/liba.so", "lib/x86/libb.so"]
    );
    assert_eq!(r.matched_methods, 2);
    let a = &r.libs[0];
    assert!(a.jni_onload && a.abi_mismatch == Some(false) && a.matched_methods == 1);
    assert_eq!(r.libs[1].abi_mismatch, Some(true));
    assert_eq!(r.libs[1].matched_methods, 2);
}
