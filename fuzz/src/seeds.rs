//! Seed corpus generation. Re-used by the `gen-seeds` binary and
//! by the integration tests in `tests/seeds.rs`.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Root directory (relative to cwd) that `gen-seeds` writes into.
pub const SEEDS_ROOT: &str = "seeds";

/// Emit every target's seed corpus. Returns the total number of
/// files written.
pub fn emit_all(root: &Path) -> io::Result<usize> {
    fs::create_dir_all(root)?;
    let targets = crate::registry();
    let mut emitted = 0usize;
    for t in &targets {
        let dir = root.join(t.default_seed);
        fs::create_dir_all(&dir)?;
        let added = match t.name {
            "dummy" => emit_dummy(&dir)?,
            "fuzz_dex_header" | "fuzz_dex041" | "fuzz_class_data" | "fuzz_code_item"
            | "fuzz_encoded_value" | "fuzz_annotations" => emit_dex(&dir)?,
            "fuzz_disasm" => emit_disasm(&dir, root)?,
            "fuzz_uleb128" => emit_uleb(&dir)?,
            "fuzz_mutf8" => emit_mutf8(&dir)?,
            "fuzz_ref_walker" => emit_bytecode(&dir)?,
            "fuzz_zip_directory" => emit_zip(&dir)?,
            "fuzz_elf" => emit_elf(&dir)?,
            "fuzz_signing" => emit_signing(&dir)?,
            "fuzz_arsc" => emit_arsc(&dir)?,
            "fuzz_axml" => emit_axml(&dir)?,
            "fuzz_apk_open" | "fuzz_inspect" | "fuzz_xapk" => emit_apk_file(&dir)?,
            "fuzz_hermes" => emit_hermes(&dir)?,
            "fuzz_rebuild" => {
                // Reuses the dex_minimal seed; nothing extra to emit
                // unless the directory is empty (e.g. on first run
                // before emit_dex populated it).
                let src = root.join("dex_minimal");
                if dir.exists() && dir != src {
                    copy_dir(&src, &dir)?
                } else {
                    0
                }
            }
            other => {
                eprintln!("gen-seeds: no emitter for '{other}', skipping");
                0
            }
        };
        emitted += added;
        eprintln!(
            "  [{}] {} file(s) under seeds/{}",
            t.name, added, t.default_seed
        );
    }
    Ok(emitted)
}

fn emit_dummy(dir: &Path) -> io::Result<usize> {
    let mut n = 0;
    n += write_bytes(dir.join("empty.bin"), b"")?;
    n += write_bytes(dir.join("one.bin"), &[0x42])?;
    n += write_bytes(
        dir.join("continuation.bin"),
        &[0x80, 0x80, 0x80, 0x80, 0x01],
    )?;
    Ok(n)
}

fn emit_dex(dir: &Path) -> io::Result<usize> {
    let mut n = 0;
    n += write_bytes(dir.join("dex_minimal.bin"), &dex_minimal_header())?;
    n += write_bytes(dir.join("dex_truncated.bin"), &dex_minimal_header()[..32])?;
    n += write_bytes(dir.join("dex041_two_header.bin"), &dex041_two_header())?;
    n += write_bytes(dir.join("dex_empty.bin"), b"")?;
    n += write_bytes(
        dir.join("dex_random_256.bin"),
        &random_deterministic(256, 0xDEAD_BEEF),
    )?;
    Ok(n)
}

fn emit_uleb(dir: &Path) -> io::Result<usize> {
    let mut n = 0;
    n += write_bytes(dir.join("uleb_one.bin"), &[0x01])?;
    n += write_bytes(
        dir.join("uleb_five_byte.bin"),
        &[0x80, 0x80, 0x80, 0x80, 0x01],
    )?;
    n += write_bytes(dir.join("uleb_corrupt_long.bin"), &{
        let mut v = vec![0x80u8; 9];
        v.push(0x01);
        v
    })?;
    n += write_bytes(dir.join("uleb_max_one_byte.bin"), &[0x7F])?;
    n += write_bytes(
        dir.join("uleb_stream.bin"),
        &[0x05, 0x80, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x00],
    )?;
    Ok(n)
}

fn emit_mutf8(dir: &Path) -> io::Result<usize> {
    let mut n = 0;
    n += write_bytes(dir.join("mutf8_ascii.bin"), b"hello world")?;
    n += write_bytes(dir.join("mutf8_truncated.bin"), &[0xE4, 0xB8])?;
    n += write_bytes(dir.join("mutf8_surrogate.bin"), &[0xED, 0xA0, 0x80])?;
    n += write_bytes(dir.join("mutf8_overlong.bin"), &[0xC0, 0x80])?;
    n += write_bytes(dir.join("mutf8_empty.bin"), b"")?;
    Ok(n)
}

fn emit_hermes(dir: &Path) -> io::Result<usize> {
    const MAGIC: [u8; 8] = [0xC6, 0x1F, 0xBC, 0x03, 0xC1, 0x03, 0x19, 0x1F];
    // Minimal valid v96 bundle: 0 functions, 3 strings (ASCII +
    // UTF-16 small + UTF-16 overflow).
    let mut storage: Vec<u8> = b"hello".to_vec();
    storage.extend_from_slice(&[0x68, 0x00, 0xE9, 0x00]); // "hé" UTF-16LE
    let s0 = 5u32 << 24; // "hello" at 0, len 5, ascii
    let s1 = 1u32 | (2u32 << 24); // utf16, len 2 units, off 0
    let s2 = 0xFFu32 << 24; // overflow marker, index 0
    let mut b = Vec::new();
    b.extend_from_slice(&MAGIC);
    b.extend_from_slice(&96u32.to_le_bytes());
    b.extend_from_slice(&[0u8; 20]); // sourceHash
    b.extend_from_slice(&0u32.to_le_bytes()); // fileLength (patched)
    b.extend_from_slice(&0u32.to_le_bytes()); // globalCodeIndex
    b.extend_from_slice(&0u32.to_le_bytes()); // functionCount
    b.extend_from_slice(&1u32.to_le_bytes()); // stringKindCount
    b.extend_from_slice(&0u32.to_le_bytes()); // identifierCount
    b.extend_from_slice(&3u32.to_le_bytes()); // stringCount
    b.extend_from_slice(&1u32.to_le_bytes()); // overflowStringCount
    b.extend_from_slice(&(storage.len() as u32).to_le_bytes());
    for v in [0u32; 11] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(&[0u8; 20]); // options + padding → 128
    b.extend_from_slice(&1u32.to_le_bytes()); // kinds RLE: string ×3
    b.extend_from_slice(&s0.to_le_bytes());
    b.extend_from_slice(&s1.to_le_bytes());
    b.extend_from_slice(&s2.to_le_bytes());
    b.extend_from_slice(&9u32.to_le_bytes()); // overflow: off 9
    b.extend_from_slice(&2u32.to_le_bytes()); // len 2 units
    b.extend_from_slice(&storage);
    let file_len = b.len() as u32;
    b[32..36].copy_from_slice(&file_len.to_le_bytes());
    let mut n = 0;
    n += write_bytes(dir.join("hermes_v96.bin"), &b)?;
    n += write_bytes(dir.join("hermes_magic_only.bin"), &MAGIC)?;
    let bad_version = {
        let mut v = b.clone();
        v[8..12].copy_from_slice(&95u32.to_le_bytes());
        v
    };
    n += write_bytes(dir.join("hermes_bad_version.bin"), &bad_version)?;
    n += write_bytes(dir.join("hermes_truncated.bin"), &b[..100])?;
    Ok(n)
}

fn emit_bytecode(dir: &Path) -> io::Result<usize> {
    let mut n = 0;
    n += write_bytes(dir.join("bytecode_empty.bin"), b"")?;
    n += write_bytes(dir.join("bytecode_nop.bin"), &[0x00, 0x00, 0x00, 0x00])?;
    n += write_bytes(
        dir.join("bytecode_mixed.bin"),
        &[0x00, 0x00, 0x0E, 0x00, 0x01, 0x00, 0x1A, 0x00],
    )?;
    n += write_bytes(
        dir.join("bytecode_random_64.bin"),
        &random_deterministic(64, 0xC0DE_CAFE),
    )?;
    Ok(n)
}

fn emit_signing(dir: &Path) -> io::Result<usize> {
    // 40 junk bytes + signing block (one v2 pair with an empty signer
    // list) + EOCD whose cd_offset points just past the block.
    let mut value = 0u32.to_le_bytes().to_vec();
    let mut pair = (value.len() as u64 + 4).to_le_bytes().to_vec();
    pair.extend(0x7109_871au32.to_le_bytes());
    pair.append(&mut value);
    let size = (pair.len() + 24) as u64;
    let mut b = vec![0u8; 40];
    b.extend(size.to_le_bytes());
    b.extend(&pair);
    b.extend(size.to_le_bytes());
    b.extend(b"APK Sig Block 42");
    let cd = b.len() as u32;
    b.extend(0x0605_4b50u32.to_le_bytes());
    b.extend([0u8; 12]);
    b.extend(cd.to_le_bytes());
    b.extend([0u8; 2]);
    let mut n = write_bytes(dir.join("signing_v2_empty.bin"), &b)?;
    n += write_bytes(dir.join("signing_empty.bin"), b"")?;
    Ok(n)
}

fn emit_arsc(dir: &Path) -> io::Result<usize> {
    // Table header + empty global pool + one empty package (id 0x7f).
    let mut pool = vec![1u8, 0, 28, 0, 28, 0, 0, 0];
    pool.extend([0u8; 20]);
    pool[20..24].copy_from_slice(&28u32.to_le_bytes()); // stringsStart
    let mut pkg = vec![0u8; 288];
    pkg[..4].copy_from_slice(&[0x00, 0x02, 0x20, 0x01]);
    pkg[4..8].copy_from_slice(&288u32.to_le_bytes());
    pkg[8] = 0x7f;
    let size = (12 + pool.len() + pkg.len()) as u32;
    let mut t = vec![0x02, 0x00, 0x0c, 0x00];
    t.extend(size.to_le_bytes());
    t.extend(1u32.to_le_bytes());
    t.extend(&pool);
    t.extend(&pkg);
    let mut n = write_bytes(dir.join("arsc_empty_package.bin"), &t)?;
    n += write_bytes(dir.join("arsc_empty.bin"), b"")?;
    Ok(n)
}

/// Seed corpus for `fuzz_axml`: one minimal valid document (pool + one
/// plain element) and one AOSP-shaped document with a namespace event
/// and typed attributes.
fn emit_axml(dir: &Path) -> io::Result<usize> {
    let mut n = write_bytes(dir.join("00_axml_minimal.bin"), &axml_minimal())?;
    n += write_bytes(dir.join("01_axml_ns_attrs.bin"), &axml_ns_attrs())?;
    Ok(n)
}

fn emit_elf(dir: &Path) -> io::Result<usize> {
    // ELF64 LE header only: parses, reports "no readable symbol table".
    let mut h = vec![0u8; 0x40];
    h[..4].copy_from_slice(b"\x7fELF");
    h[4] = 2;
    h[5] = 1;
    h[0x12] = 183;
    let mut n = write_bytes(dir.join("elf64_header_only.bin"), &h)?;
    n += write_bytes(dir.join("elf_empty.bin"), b"")?;
    Ok(n)
}

/// Seed corpus for the file-backed targets: `Apk::open` and the
/// `asc_core` path entry points both take a path, so the seeds are whole
/// container files rather than raw payloads.
fn emit_apk_file(dir: &Path) -> io::Result<usize> {
    let mut n = write_bytes(
        dir.join("zip_one_stored_class.bin"),
        &zip_one_stored_class(),
    )?;
    n += write_bytes(dir.join("zip_multi_entry.bin"), &zip_multi_entry())?;
    n += write_bytes(dir.join("zip_eocd_only.bin"), &zip_eocd_only())?;
    n += write_bytes(dir.join("dex_minimal.bin"), &dex_minimal_header())?;
    n += write_bytes(dir.join("apk_empty.bin"), b"")?;
    Ok(n)
}

fn emit_zip(dir: &Path) -> io::Result<usize> {
    let mut n = 0;
    n += write_bytes(dir.join("zip_eocd_only.bin"), &zip_eocd_only())?;
    n += write_bytes(
        dir.join("zip_one_stored_class.bin"),
        &zip_one_stored_class(),
    )?;
    n += write_bytes(dir.join("zip_multi_entry.bin"), &zip_multi_entry())?;
    n += write_bytes(dir.join("zip_empty.bin"), b"")?;
    n += write_bytes(
        dir.join("zip_random_256.bin"),
        &random_deterministic(256, 0x1234_5678),
    )?;
    Ok(n)
}

/// Seed corpus for the renderer-backed target: one DEX that PARSES
/// (so mutations land inside the pools and instruction stream instead
/// of dying at the magic/checksum gate) plus the shared `dex` seeds so
/// the cheap gates stay fuzzed too. `fuzz_disasm` re-seals the
/// signature for 7 of every 8 inputs; these raw copies are the
/// un-sealed case it deliberately leaves alone.
fn emit_disasm(dir: &Path, root: &Path) -> io::Result<usize> {
    let mut n = write_bytes(
        dir.join("dex_switch_try_array.bin"),
        &crate::dex_builder::dex_with_switch_try_array(),
    )?;
    // Reuse the shared dex seeds so the cheap gates stay fuzzed too.
    let src = root.join("dex_minimal");
    if dir != src && src.is_dir() {
        n += copy_dir(&src, dir)?;
    }
    Ok(n)
}

// =====================================================================
// Raw byte constructors (visible to tests via `pub`)
// =====================================================================

/// 0x70-byte DEX header with magic 035 and all pool counts zero.
pub fn dex_minimal_header() -> Vec<u8> {
    let mut h = vec![0u8; 0x70];
    h[0..8].copy_from_slice(b"dex\n035\x00");
    h[0x20..0x24].copy_from_slice(&0x70u32.to_le_bytes());
    h[0x24..0x28].copy_from_slice(&0x70u32.to_le_bytes());
    h[0x28..0x2A].copy_from_slice(b"\x01L");
    h
}

/// Two back-to-back minimal headers; second one bumps version to 041.
pub fn dex041_two_header() -> Vec<u8> {
    let mut v = dex_minimal_header();
    let mut second = dex_minimal_header();
    second[4..8].copy_from_slice(b"041\x00");
    v.extend_from_slice(&second);
    v
}

/// EOCD-only ZIP: signature + 18 bytes of zeros.
pub fn zip_eocd_only() -> Vec<u8> {
    let mut v = Vec::with_capacity(22);
    v.extend_from_slice(b"PK\x05\x06");
    v.extend_from_slice(&[0u8; 18]);
    v
}

/// One STORED entry named `classes.dex` with a 16-byte zero payload.
pub fn zip_one_stored_class() -> Vec<u8> {
    let name = b"classes.dex";
    let payload = [0u8; 16];
    let crc = crc32(&payload);
    let size = payload.len() as u32;

    let mut v = Vec::new();
    v.extend_from_slice(b"PK\x03\x04");
    v.extend_from_slice(&20u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&crc.to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    v.extend_from_slice(&(name.len() as u16).to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(name);
    v.extend_from_slice(&payload);

    let cd_offset = v.len() as u32;
    v.extend_from_slice(b"PK\x01\x02");
    v.extend_from_slice(&20u16.to_le_bytes());
    v.extend_from_slice(&20u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&crc.to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    v.extend_from_slice(&(name.len() as u16).to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&cd_offset.to_le_bytes());
    v.extend_from_slice(name);

    let cd_size = (v.len() as u32) - cd_offset;
    v.extend_from_slice(b"PK\x05\x06");
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&cd_size.to_le_bytes());
    v.extend_from_slice(&cd_offset.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v
}

/// Three-entry ZIP (classes.dex + a.dex + b.dex, all STORED).
pub fn zip_multi_entry() -> Vec<u8> {
    let one = zip_one_stored_class();
    let mut v = one[..one.len() - 22].to_vec();
    for name in [b"a.dex".as_slice(), b"b.dex".as_slice()] {
        let cd_offset = v.len() as u32;
        v.extend_from_slice(b"PK\x01\x02");
        v.extend_from_slice(&20u16.to_le_bytes());
        v.extend_from_slice(&20u16.to_le_bytes());
        for _ in 0..6 {
            v.extend_from_slice(&0u16.to_le_bytes());
        }
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&cd_offset.to_le_bytes());
        v.extend_from_slice(name);
    }
    let cd_size = v.len() as u32;
    v.extend_from_slice(b"PK\x05\x06");
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&3u16.to_le_bytes());
    v.extend_from_slice(&3u16.to_le_bytes());
    v.extend_from_slice(&cd_size.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v
}

/// Minimal valid binary AXML: root chunk, one-string UTF-16 pool, a
/// single START/END element pair. Mirrors the byte layout asserted by
/// `asc-manifest`'s own fixture builder.
pub fn axml_minimal() -> Vec<u8> {
    let pool = string_pool_utf16(&["item"]);
    let start = element_chunk(0xFFFF_FFFF, 0, &[]);
    let end = end_element_chunk(0xFFFF_FFFF, 0);
    seal_root(pool, start, end)
}

/// AOSP-shaped document: namespace event + `<rules debug="true"
/// android:backups="0x10">` with typed attributes, a nested child, and
/// the matching END_NAMESPACE.
pub fn axml_ns_attrs() -> Vec<u8> {
    const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";
    let strings = [
        "rules",
        "domain-config",
        "debug",
        "true",
        "backups",
        ANDROID_NS,
        "android",
    ];
    let pool = string_pool_utf16(&strings);
    let (name_rules, name_child) = (0u32, 1u32);
    let attrs = [
        // debug="true" — TYPE_STRING with rawValue + data set.
        (0xFFFF_FFFF, 2u32, 3u32, 0x03u8, 3u32),
        // android:backups=0x10 — TYPE_INT_HEX under the android NS.
        (5u32, 4u32, 0xFFFF_FFFF, 0x11u8, 0x10u32),
    ];
    let start = element_chunk(0xFFFF_FFFF, name_rules, &attrs);
    let child = element_chunk(0xFFFF_FFFF, name_child, &[]);
    let end_child = end_element_chunk(0xFFFF_FFFF, name_child);
    let end = end_element_chunk(0xFFFF_FFFF, name_rules);
    // START/END_NAMESPACE bodies: prefix idx 6 ("android"), uri idx 5.
    let ns = ns_chunk(0x0100, 6, 5);
    let ns_end = ns_chunk(0x0101, 6, 5);
    let mut doc = seal_root(pool, ns, start);
    doc.extend_from_slice(&child);
    doc.extend_from_slice(&end_child);
    doc.extend_from_slice(&end);
    doc.extend_from_slice(&ns_end);
    let total = doc.len() as u32;
    doc[4..8].copy_from_slice(&total.to_le_bytes());
    doc
}

/// Root + string pool + one leading inner chunk; caller appends the rest
/// and patches the root size. Returned header already carries the size
/// of what is present so intermediate states stay parseable-by-parts.
fn seal_root(pool: Vec<u8>, a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    let mut doc = Vec::new();
    doc.extend_from_slice(&0x0003u16.to_le_bytes()); // RES_XML_TYPE
    doc.extend_from_slice(&0x0008u16.to_le_bytes()); // headerSize
    doc.extend_from_slice(&0u32.to_le_bytes()); // size (patched later)
    doc.extend_from_slice(&pool);
    doc.extend_from_slice(&a);
    doc.extend_from_slice(&b);
    let total = doc.len() as u32;
    doc[4..8].copy_from_slice(&total.to_le_bytes());
    doc
}

/// UTF-16 string-pool chunk, the format `asc_manifest` fixtures use.
fn string_pool_utf16(strings: &[&str]) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    let mut offsets = Vec::with_capacity(strings.len());
    for s in strings {
        let units: Vec<u16> = s.encode_utf16().collect();
        offsets.push(data.len() as u32);
        data.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for u in units {
            data.extend_from_slice(&u.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes()); // NUL terminator
    }
    while !data.len().is_multiple_of(4) {
        data.push(0);
    }
    let strings_start = 28 + strings.len() * 4;
    let size = strings_start + data.len();
    let mut pool = Vec::with_capacity(size);
    pool.extend_from_slice(&0x0001u16.to_le_bytes()); // RES_STRING_POOL_TYPE
    pool.extend_from_slice(&28u16.to_le_bytes()); // headerSize
    pool.extend_from_slice(&(size as u32).to_le_bytes());
    pool.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes()); // styleCount
    pool.extend_from_slice(&0u32.to_le_bytes()); // flags: UTF-16
    pool.extend_from_slice(&(strings_start as u32).to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
    for off in offsets {
        pool.extend_from_slice(&off.to_le_bytes());
    }
    pool.extend_from_slice(&data);
    pool
}

/// START_ELEMENT chunk with `(ns, name, raw, type, data)` attributes.
fn element_chunk(ns: u32, name: u32, attrs: &[(u32, u32, u32, u8, u32)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x0102u16.to_le_bytes()); // START_ELEMENT
    out.extend_from_slice(&16u16.to_le_bytes()); // headerSize
    let size_off = out.len();
    out.extend_from_slice(&0u32.to_le_bytes()); // size (patched)
    out.extend_from_slice(&1u32.to_le_bytes()); // lineNumber
    out.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // comment
    out.extend_from_slice(&ns.to_le_bytes());
    out.extend_from_slice(&name.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes()); // attributeStart
    out.extend_from_slice(&20u16.to_le_bytes()); // attributeSize
    out.extend_from_slice(&(attrs.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // idIndex
    out.extend_from_slice(&0u16.to_le_bytes()); // classIndex
    out.extend_from_slice(&0u16.to_le_bytes()); // styleIndex
    for (a_ns, a_name, raw, ty, data) in attrs {
        out.extend_from_slice(&a_ns.to_le_bytes());
        out.extend_from_slice(&a_name.to_le_bytes());
        out.extend_from_slice(&raw.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes()); // typedValue.size
        out.push(0); // res0
        out.push(*ty); // dataType
        out.extend_from_slice(&data.to_le_bytes());
    }
    let size = out.len() as u32;
    out[size_off..size_off + 4].copy_from_slice(&size.to_le_bytes());
    out
}

/// END_ELEMENT chunk (ns + name at chunk_start + 16).
fn end_element_chunk(ns: u32, name: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x0103u16.to_le_bytes()); // END_ELEMENT
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(&24u32.to_le_bytes()); // size
    out.extend_from_slice(&1u32.to_le_bytes()); // lineNumber
    out.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // comment
    out.extend_from_slice(&ns.to_le_bytes());
    out.extend_from_slice(&name.to_le_bytes());
    out
}

/// Namespace event chunk (0x0100 start / 0x0101 end): prefix + uri.
fn ns_chunk(kind: u16, prefix: u32, uri: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(&24u32.to_le_bytes()); // size
    out.extend_from_slice(&1u32.to_le_bytes()); // lineNumber
    out.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // comment
    out.extend_from_slice(&prefix.to_le_bytes());
    out.extend_from_slice(&uri.to_le_bytes());
    out
}

// =====================================================================
// Utilities
// =====================================================================

pub fn write_bytes(path: PathBuf, bytes: &[u8]) -> io::Result<usize> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::File::create(&path)?;
    f.write_all(bytes)?;
    Ok(1)
}

pub fn copy_dir(src: &Path, dst: &Path) -> io::Result<usize> {
    if src == dst {
        return Ok(fs::read_dir(src)?.flatten().count());
    }
    fs::create_dir_all(dst)?;
    let mut count = 0;
    for entry in fs::read_dir(src)?.flatten() {
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from == to {
            count += 1;
            continue;
        }
        fs::copy(&from, &to)?;
        count += 1;
    }
    Ok(count)
}

/// xorshift64 from a fixed u64.
pub fn random_deterministic(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        out.push(s as u8);
    }
    out
}

/// CRC-32 (IEEE).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Recursively count files under `dir`.
pub fn count_files(dir: &Path) -> io::Result<usize> {
    if !dir.is_dir() {
        return Ok(0);
    }
    let mut count = 0;
    for entry in fs::read_dir(dir)?.flatten() {
        let p = entry.path();
        if p.is_dir() {
            count += count_files(&p)?;
        } else {
            count += 1;
        }
    }
    Ok(count)
}
