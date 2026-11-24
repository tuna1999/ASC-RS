//! Bounded ELF dynamic-symbol reader (32/64-bit, either endianness).
//!
//! Purpose: list the *defined* global/weak dynamic symbols of a shared
//! object so callers can look for `JNI_OnLoad` and `Java_*` exports. It
//! never disassembles code. Hostile metadata is expected (packers
//! contradict their own section/hash tables), so a disagreement is a note,
//! not an error, and every read is bounds-checked.
//!
//! Primary path: section headers, first `SHT_DYNSYM` + its `sh_link`
//! string table. Fallback (no usable dynsym section, e.g. stripped section
//! headers): `PT_DYNAMIC` → `DT_SYMTAB`/`DT_STRTAB`, symbol count from
//! `DT_HASH.nchain` or a bounded `DT_GNU_HASH` walk.
//!
//! [`jni_tables`] separately scans non-executable `PT_LOAD` data for
//! static `JNINativeMethod` arrays (the `RegisterNatives` input).

use std::collections::{HashMap, HashSet};

/// Max symbols examined.
pub const MAX_SYMBOLS: usize = 65_536;
/// Max `.dynsym` bytes read.
pub const MAX_DYNSYM: usize = 8 << 20;
/// Max `.dynstr` bytes read.
pub const MAX_DYNSTR: usize = 16 << 20;
const MAX_NAME: usize = 4096;
const MAX_DYN_ENTRIES: usize = 4096;
const MAX_SECTIONS: usize = 65_535;

/// Which metadata the symbol table was recovered from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfPath {
    Sections,
    Dynamic,
    /// Neither path yielded a symbol table; `exports` is empty *because
    /// nothing was readable*, not because there are none.
    None,
}

/// Result of [`parse_elf`].
#[derive(Debug, Clone)]
pub struct ElfInfo {
    pub bits: u8,
    pub little_endian: bool,
    /// `e_machine` (e.g. 40 ARM, 183 AArch64, 3 x86, 62 x86-64).
    pub machine: u16,
    pub path: ElfPath,
    /// Symbols examined (excluding the null symbol).
    pub symbols_seen: usize,
    /// Defined global/weak symbol names, version suffix (`@…`) removed.
    pub exports: Vec<String>,
    /// `false` when a cap, bad extent or missing table limited the scan.
    pub complete: bool,
    pub notes: Vec<String>,
}

struct R<'a> {
    b: &'a [u8],
    le: bool,
}

impl R<'_> {
    fn n(&self, off: u64, len: usize) -> Option<u64> {
        let off = usize::try_from(off).ok()?;
        let s = self.b.get(off..off.checked_add(len)?)?;
        let mut v = 0u64;
        for (i, &x) in s.iter().enumerate() {
            let sh = if self.le { i } else { len - 1 - i } * 8;
            v |= u64::from(x) << sh;
        }
        Some(v)
    }
    fn u16(&self, off: u64) -> Option<u64> {
        self.n(off, 2)
    }
    fn u32(&self, off: u64) -> Option<u64> {
        self.n(off, 4)
    }
    /// Address-sized word (4 or 8 bytes).
    fn w(&self, off: u64, is64: bool) -> Option<u64> {
        self.n(off, if is64 { 8 } else { 4 })
    }
}

/// Parse `b` as an ELF shared object. `Err` only for a header that is not
/// a usable ELF at all.
pub fn parse_elf(b: &[u8]) -> Result<ElfInfo, &'static str> {
    let (is64, le) = header(b)?;
    let r = R { b, le };
    let machine = r.u16(0x12).unwrap_or(0) as u16;
    let mut info = ElfInfo {
        bits: if is64 { 64 } else { 32 },
        little_endian: le,
        machine,
        path: ElfPath::None,
        symbols_seen: 0,
        exports: Vec::new(),
        complete: true,
        notes: Vec::new(),
    };
    let via_sections = from_sections(&r, is64, &mut info);
    if !via_sections {
        info.notes.clear();
        info.complete = true;
        if !from_dynamic(&r, is64, &mut info) {
            info.path = ElfPath::None;
            info.complete = false;
            info.notes.push(
                "no readable dynamic symbol table (sections and PT_DYNAMIC both failed)".into(),
            );
        }
    }
    Ok(info)
}

/// `(is64, little_endian)` of a usable ELF header.
fn header(b: &[u8]) -> Result<(bool, bool), &'static str> {
    if b.len() < 0x34 || &b[..4] != b"\x7fELF" {
        return Err("not an ELF file");
    }
    let is64 = match b[4] {
        1 => false,
        2 => true,
        _ => return Err("bad ELF class"),
    };
    let le = match b[5] {
        1 => true,
        2 => false,
        _ => return Err("bad ELF data encoding"),
    };
    if is64 && b.len() < 0x40 {
        return Err("truncated ELF64 header");
    }
    Ok((is64, le))
}

/// Section-header path. `false` = not usable (caller falls back).
fn from_sections(r: &R, is64: bool, info: &mut ElfInfo) -> bool {
    let (shoff, shentsize, shnum) = if is64 {
        (r.n(0x28, 8), r.u16(0x3A), r.u16(0x3C))
    } else {
        (r.n(0x20, 4), r.u16(0x2E), r.u16(0x30))
    };
    let (Some(shoff), Some(shentsize), Some(shnum)) = (shoff, shentsize, shnum) else {
        return false;
    };
    let min_ent = if is64 { 64 } else { 40 };
    if shoff == 0 || shnum == 0 || (shentsize as usize) < min_ent {
        return false;
    }
    let sec = |i: u64| shoff.checked_add(i.checked_mul(shentsize)?);
    // (offset, size, link, entsize) of section i, with its type.
    let field = |i: u64| -> Option<(u64, u64, u64, u64, u64)> {
        let h = sec(i)?;
        let ty = r.u32(h + 4)?;
        Some(if is64 {
            (
                ty,
                r.n(h + 0x18, 8)?,
                r.n(h + 0x20, 8)?,
                r.u32(h + 0x28)?,
                r.n(h + 0x38, 8)?,
            )
        } else {
            (
                ty,
                r.u32(h + 0x10)?,
                r.u32(h + 0x14)?,
                r.u32(h + 0x18)?,
                r.u32(h + 0x24)?,
            )
        })
    };
    let Some((symoff, symsz, link, entsz)) = (0..shnum.min(MAX_SECTIONS as u64)).find_map(|i| {
        let (ty, off, size, link, entsz) = field(i)?;
        (ty == 11).then_some((off, size, link, entsz))
    }) else {
        return false;
    };
    let Some((sty, stroff, strsz, _, _)) = field(link) else {
        return false;
    };
    if sty != 3 {
        return false;
    }
    let symsize = if is64 { 24 } else { 16 };
    if entsz != symsize && entsz != 0 {
        info.notes.push(format!(
            "dynsym sh_entsize {entsz} != {symsize}; using {symsize}"
        ));
    }
    info.path = ElfPath::Sections;
    read_symbols(r, is64, info, symoff, symsz, stroff, strsz);
    true
}

/// `PT_DYNAMIC` fallback.
fn from_dynamic(r: &R, is64: bool, info: &mut ElfInfo) -> bool {
    let Some(segs) = segments(r, is64) else {
        return false;
    };
    let Some(dynv) = dynamic_entries(r, is64, &segs) else {
        return false;
    };
    let to_off = |va: u64| va_to_off(&segs, va);
    let tag = |t: u64| dynv.iter().find(|e| e.0 == t).map(|e| e.1);
    let (symtab, strtab, strsz, hash, gnu) = (tag(6), tag(5), tag(10), tag(4), tag(0x6fff_fef5));
    let (Some(symva), Some(strva)) = (symtab, strtab) else {
        return false;
    };
    let (Some(symoff), Some(stroff)) = (to_off(symva), to_off(strva)) else {
        return false;
    };
    let symsize = if is64 { 24 } else { 16 };
    let count = if let Some(h) = hash.and_then(to_off) {
        r.u32(h + 4)
    } else if let Some(g) = gnu.and_then(to_off) {
        gnu_count(r, g)
    } else {
        None
    };
    let Some(count) = count else {
        return false;
    };
    info.path = ElfPath::Dynamic;
    let strsz = strsz.unwrap_or(r.b.len() as u64 - stroff.min(r.b.len() as u64));
    read_symbols(
        r,
        is64,
        info,
        symoff,
        count.saturating_mul(symsize),
        stroff,
        strsz,
    );
    true
}

/// One program header.
#[derive(Clone, Copy)]
struct Seg {
    ty: u64,
    flags: u64,
    off: u64,
    va: u64,
    fsz: u64,
}

const PT_LOAD: u64 = 1;
const PF_X: u64 = 1;

/// All program headers, `None` when the table itself is unreadable.
fn segments(r: &R, is64: bool) -> Option<Vec<Seg>> {
    let (phoff, phentsize, phnum) = if is64 {
        (r.n(0x20, 8)?, r.u16(0x36)?, r.u16(0x38)?)
    } else {
        (r.n(0x1C, 4)?, r.u16(0x2A)?, r.u16(0x2C)?)
    };
    let min_ent = if is64 { 56 } else { 32 };
    if phoff == 0 || phnum == 0 || (phentsize as usize) < min_ent {
        return None;
    }
    (0..phnum)
        .map(|i| {
            let h = phoff.checked_add(i * phentsize)?;
            Some(if is64 {
                Seg {
                    ty: r.u32(h)?,
                    flags: r.u32(h + 4)?,
                    off: r.n(h + 8, 8)?,
                    va: r.n(h + 0x10, 8)?,
                    fsz: r.n(h + 0x20, 8)?,
                }
            } else {
                Seg {
                    ty: r.u32(h)?,
                    off: r.u32(h + 4)?,
                    va: r.u32(h + 8)?,
                    fsz: r.u32(h + 0x10)?,
                    flags: r.u32(h + 0x18)?,
                }
            })
        })
        .collect()
}

/// File offset of virtual address `va` inside some `PT_LOAD`.
fn va_to_off(segs: &[Seg], va: u64) -> Option<u64> {
    segs.iter()
        .filter(|s| s.ty == PT_LOAD)
        .find_map(|s| (va >= s.va && va - s.va < s.fsz).then(|| s.off.checked_add(va - s.va)))
        .flatten()
}

/// `(tag, value)` pairs of the first `PT_DYNAMIC`, up to `DT_NULL`.
fn dynamic_entries(r: &R, is64: bool, segs: &[Seg]) -> Option<Vec<(u64, u64)>> {
    let d = segs.iter().find(|s| s.ty == 2)?;
    let esz = if is64 { 16 } else { 8 };
    let mut out = Vec::new();
    for i in 0..(d.fsz / esz).min(MAX_DYN_ENTRIES as u64) {
        let Some(p) = d.off.checked_add(i * esz) else {
            break;
        };
        let (Some(tag), Some(val)) = (r.w(p, is64), r.w(p.saturating_add(esz / 2), is64)) else {
            break;
        };
        if tag == 0 {
            break;
        }
        out.push((tag, val));
    }
    Some(out)
}

/// Symbol count from a `DT_GNU_HASH` table: highest bucket start, then walk
/// its chain to the terminator bit. Bounded by [`MAX_SYMBOLS`].
fn gnu_count(r: &R, g: u64) -> Option<u64> {
    let nbuckets = r.u32(g)?;
    let symoffset = r.u32(g + 4)?;
    let bloom = r.u32(g + 8)?;
    let word = if r.b.get(4) == Some(&2) { 8 } else { 4 };
    if nbuckets == 0 || nbuckets as usize > MAX_SYMBOLS || bloom as usize > MAX_SYMBOLS {
        return None;
    }
    let buckets = g + 16 + bloom * word;
    let chains = buckets + nbuckets * 4;
    let mut max = 0;
    for i in 0..nbuckets {
        max = max.max(r.u32(buckets + i * 4)?);
    }
    if max < symoffset {
        return Some(symoffset);
    }
    let mut i = max - symoffset;
    loop {
        if i as usize > MAX_SYMBOLS {
            return None;
        }
        if r.u32(chains + i * 4)? & 1 != 0 {
            return Some(symoffset + i + 1);
        }
        i += 1;
    }
}

fn read_symbols(
    r: &R,
    is64: bool,
    info: &mut ElfInfo,
    symoff: u64,
    symbytes: u64,
    stroff: u64,
    strsz: u64,
) {
    let file = r.b.len() as u64;
    let symsize: u64 = if is64 { 24 } else { 16 };
    if symbytes > MAX_DYNSYM as u64 {
        info.complete = false;
        info.notes.push(format!(
            "dynsym {symbytes} bytes exceeds {MAX_DYNSYM} cap; truncated"
        ));
    }
    if strsz > MAX_DYNSTR as u64 {
        info.complete = false;
        info.notes.push(format!(
            "dynstr {strsz} bytes exceeds {MAX_DYNSTR} cap; truncated"
        ));
    }
    let symbytes = symbytes.min(MAX_DYNSYM as u64);
    let strsz = strsz.min(MAX_DYNSTR as u64);
    if stroff > file || strsz > file - stroff {
        info.complete = false;
        info.notes
            .push("dynstr extent outside file; clamped".into());
    }
    let strs =
        r.b.get(stroff as usize..)
            .map_or(&[][..], |s| &s[..s.len().min(strsz as usize)]);
    let mut count = symbytes / symsize;
    if symoff > file || count * symsize > file - symoff {
        info.complete = false;
        info.notes
            .push("dynsym extent outside file; clamped".into());
        count = file.saturating_sub(symoff) / symsize;
    }
    if count as usize > MAX_SYMBOLS {
        info.complete = false;
        info.notes
            .push(format!("more than {MAX_SYMBOLS} symbols; truncated"));
        count = MAX_SYMBOLS as u64;
    }
    let mut bad = 0usize;
    for i in 1..count {
        let p = symoff + i * symsize;
        let (name, st_info, shndx) = if is64 {
            (r.u32(p), r.n(p + 4, 1), r.u16(p + 6))
        } else {
            (r.u32(p), r.n(p + 12, 1), r.u16(p + 14))
        };
        let (Some(name), Some(st_info), Some(shndx)) = (name, st_info, shndx) else {
            break;
        };
        info.symbols_seen += 1;
        let bind = st_info >> 4;
        if shndx == 0 || !(bind == 1 || bind == 2) {
            continue;
        }
        let Some(tail) = strs.get(name as usize..) else {
            bad += 1;
            continue;
        };
        let raw = &tail[..tail
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(tail.len())
            .min(MAX_NAME)];
        let raw = &raw[..raw.iter().position(|&c| c == b'@').unwrap_or(raw.len())];
        if !raw.is_empty() {
            info.exports.push(String::from_utf8_lossy(raw).into_owned());
        }
    }
    if bad > 0 {
        info.complete = false;
        info.notes
            .push(format!("{bad} symbol name offsets outside dynstr"));
    }
}

/// Most `JNINativeMethod` entries [`jni_tables`] reports per library.
pub const MAX_JNI_ENTRIES: usize = 4096;

/// Most relocations read per table.
const MAX_RELOCS: u64 = 1 << 20;

/// One statically initialised `JNINativeMethod { name, signature, fnPtr }`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JniEntry {
    pub name: String,
    pub signature: String,
    /// Virtual address of the implementation; `None` when it is bound
    /// through a symbolic relocation (an imported or preemptible symbol).
    pub fn_addr: Option<u64>,
}

/// Result of [`jni_tables`].
#[derive(Debug, Clone, Default)]
pub struct JniTables {
    pub entries: Vec<JniEntry>,
    /// `false` when a cap or an undecoded relocation format limited the scan.
    pub complete: bool,
    pub notes: Vec<String>,
}

/// Find statically initialised `JNINativeMethod` arrays (the input of
/// `RegisterNatives`) in the non-executable data of `b`.
///
/// A candidate is three consecutive pointer-sized words in a non-executable
/// `PT_LOAD`: a pointer to a NUL-terminated method name, a pointer to a
/// well-formed JNI method descriptor, and a pointer into an executable
/// segment (or a symbolic relocation). Pointer words are resolved through
/// `RELATIVE` relocations (`DT_RELA`) or, failing that, the word stored in
/// the file (`DT_REL`, `DT_RELR` and non-PIE layouts keep it there).
/// Tables built at run time (heap arrays, strings decrypted in
/// `JNI_OnLoad`) are invisible to this scan.
pub fn jni_tables(b: &[u8]) -> Result<JniTables, &'static str> {
    let (is64, le) = header(b)?;
    let r = R { b, le };
    let mut out = JniTables {
        complete: true,
        ..JniTables::default()
    };
    let Some(segs) = segments(&r, is64) else {
        out.complete = false;
        out.notes
            .push("no program headers; JNI table scan skipped".into());
        return Ok(out);
    };
    let machine = r.u16(0x12).unwrap_or(0);
    let dynv = dynamic_entries(&r, is64, &segs).unwrap_or_default();
    let (relative, symbolic) = relocations(&r, is64, machine, &segs, &dynv, &mut out);
    let word: u64 = if is64 { 8 } else { 4 };
    let ptr = |off: u64| -> Option<u64> {
        match relative.get(&off) {
            Some(&v) => Some(v),
            None => r.w(off, is64).filter(|&v| v != 0),
        }
    };
    let cstr = |va: u64| -> Option<&[u8]> {
        let s = b.get(usize::try_from(va_to_off(&segs, va)?).ok()?..)?;
        let n = s.iter().take(MAX_NAME).position(|&c| c == 0)?;
        Some(&s[..n])
    };
    let is_exec = |va: u64| {
        segs.iter()
            .any(|s| s.ty == PT_LOAD && s.flags & PF_X != 0 && va >= s.va && va - s.va < s.fsz)
    };
    let mut seen = HashSet::new();
    for s in segs
        .iter()
        .filter(|s| s.ty == PT_LOAD && s.flags & PF_X == 0)
    {
        let end = s.off.saturating_add(s.fsz).min(b.len() as u64);
        let mut p = s.off.next_multiple_of(word);
        while p + 3 * word <= end {
            let hit = (|| {
                let name = cstr(ptr(p)?)?;
                if !jni_name_ok(name) {
                    return None;
                }
                let sig = cstr(ptr(p + word)?)?;
                if !jni_sig_ok(sig) {
                    return None;
                }
                let f = p + 2 * word;
                let fn_addr = if symbolic.contains(&f) {
                    None
                } else {
                    let mut v = ptr(f)?;
                    if machine == 40 {
                        v &= !1; // Thumb bit
                    }
                    if !is_exec(v) {
                        return None;
                    }
                    Some(v)
                };
                Some(JniEntry {
                    name: String::from_utf8_lossy(name).into_owned(),
                    signature: String::from_utf8_lossy(sig).into_owned(),
                    fn_addr,
                })
            })();
            let Some(e) = hit else {
                p += word;
                continue;
            };
            if out.entries.len() >= MAX_JNI_ENTRIES {
                out.complete = false;
                out.notes.push(format!(
                    "more than {MAX_JNI_ENTRIES} JNI entries; truncated"
                ));
                return Ok(out);
            }
            if seen.insert(e.clone()) {
                out.entries.push(e);
            }
            p += 3 * word;
        }
    }
    Ok(out)
}

/// File offset → value for `RELATIVE` relocations with an explicit addend,
/// plus the file offsets of every non-`RELATIVE` (symbolic) relocation.
fn relocations(
    r: &R,
    is64: bool,
    machine: u64,
    segs: &[Seg],
    dynv: &[(u64, u64)],
    out: &mut JniTables,
) -> (HashMap<u64, u64>, HashSet<u64>) {
    let mut relative = HashMap::new();
    let mut symbolic = HashSet::new();
    let rel_type: u64 = match machine {
        183 => 1027,
        62 | 3 => 8,
        40 => 23,
        243 => 3,
        _ => u64::MAX,
    };
    let tag = |t: u64| dynv.iter().find(|e| e.0 == t).map(|e| e.1);
    let w: u64 = if is64 { 8 } else { 4 };
    let mut classify = |at: u64, info: u64, addend: Option<u64>| {
        let ty = if is64 {
            info & 0xffff_ffff
        } else {
            info & 0xff
        };
        let Some(at) = va_to_off(segs, at) else {
            return;
        };
        if ty != rel_type {
            symbolic.insert(at);
        } else if let Some(a) = addend {
            relative.insert(at, a);
        }
    };
    for (table, size, rela) in [(tag(7), tag(8), true), (tag(17), tag(18), false)] {
        let (Some(va), Some(size)) = (table, size) else {
            continue;
        };
        let Some(off) = va_to_off(segs, va) else {
            continue;
        };
        let esz = if rela { 3 * w } else { 2 * w };
        let count = size / esz;
        if count > MAX_RELOCS {
            out.complete = false;
            out.notes
                .push(format!("more than {MAX_RELOCS} relocations; truncated"));
        }
        for i in 0..count.min(MAX_RELOCS) {
            let Some(e) = off.checked_add(i * esz) else {
                break;
            };
            let (Some(at), Some(info)) = (r.w(e, is64), r.w(e.saturating_add(w), is64)) else {
                break;
            };
            let addend = if rela {
                r.w(e.saturating_add(2 * w), is64)
            } else {
                None
            };
            classify(at, info, addend);
        }
    }
    // Android packed relocations: DT_ANDROID_REL(A) + size tag.
    for (t, sz, rela) in [
        (0x6000_000f, 0x6000_0010, false),
        (0x6000_0011, 0x6000_0012, true),
    ] {
        let (Some(va), Some(size)) = (tag(t), tag(sz)) else {
            continue;
        };
        let data = va_to_off(segs, va).and_then(|o| {
            r.b.get(usize::try_from(o).ok()?..)?
                .get(..usize::try_from(size).ok()?)
        });
        let res = match data {
            Some(d) => decode_aps2(d, is64, rela, &mut |at, info, a| classify(at, info, a)),
            None => Err("APS2 table outside the file"),
        };
        if let Err(why) = res {
            out.complete = false;
            out.notes.push(format!(
                "Android packed relocations (APS2): {why}; table entries may be missed"
            ));
        }
    }
    (relative, symbolic)
}

/// Decode an Android `APS2` packed relocation table (bionic
/// `linker_reloc_iterators.h` `packed_reloc_iterator`): a SLEB128 stream
/// of relocation groups whose offset / info / addend are delta-coded.
/// Calls `f(r_offset, r_info, addend)` per relocation (`addend` only for
/// RELA). Stops at `MAX_RELOCS`; any malformed stream is an error.
fn decode_aps2(
    d: &[u8],
    is64: bool,
    rela: bool,
    f: &mut dyn FnMut(u64, u64, Option<u64>),
) -> Result<(), &'static str> {
    const BY_INFO: u64 = 1;
    const BY_OFFSET_DELTA: u64 = 2;
    const BY_ADDEND: u64 = 4;
    const HAS_ADDEND: u64 = 8;
    let mask = if is64 { u64::MAX } else { 0xffff_ffff };
    let body = d.strip_prefix(b"APS2").ok_or("bad magic")?;
    let mut pos = 0usize;
    let mut sleb = || -> Result<u64, &'static str> {
        let (mut v, mut shift) = (0u64, 0u32);
        loop {
            let b = *body.get(pos).ok_or("truncated")?;
            pos += 1;
            if shift < 64 {
                v |= u64::from(b & 0x7f) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    v |= u64::MAX << shift;
                }
                return Ok(v & mask);
            }
            if shift >= 70 {
                return Err("overlong SLEB128");
            }
        }
    };
    let total = sleb()?;
    let mut offset = sleb()?;
    let (mut info, mut addend) = (0u64, 0u64);
    let mut done = 0u64;
    while done < total {
        let size = sleb()?;
        let flags = sleb()?;
        if size == 0 || size > total - done {
            return Err("bad group size");
        }
        let has_addend = flags & HAS_ADDEND != 0;
        if has_addend && !rela {
            return Err("addend in a REL table");
        }
        let delta = if flags & BY_OFFSET_DELTA != 0 {
            sleb()?
        } else {
            0
        };
        if flags & BY_INFO != 0 {
            info = sleb()?;
        }
        if has_addend && flags & BY_ADDEND != 0 {
            addend = addend.wrapping_add(sleb()?) & mask;
        } else if !has_addend {
            addend = 0;
        }
        for _ in 0..size {
            if done >= MAX_RELOCS {
                return Err("more than the relocation cap");
            }
            offset = offset.wrapping_add(if flags & BY_OFFSET_DELTA != 0 {
                delta
            } else {
                sleb()?
            }) & mask;
            if flags & BY_INFO == 0 {
                info = sleb()?;
            }
            if has_addend && flags & BY_ADDEND == 0 {
                addend = addend.wrapping_add(sleb()?) & mask;
            }
            f(offset, info, rela.then_some(addend));
            done += 1;
        }
    }
    Ok(())
}

/// Plausible Java method name: no descriptor punctuation, no controls.
fn jni_name_ok(s: &[u8]) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.iter()
            .all(|&c| c >= 0x80 || c.is_ascii_alphanumeric() || matches!(c, b'_' | b'$' | b'-'))
}

/// Strict JNI method descriptor: `(` field types `)` field type or `V`.
fn jni_sig_ok(s: &[u8]) -> bool {
    fn field(s: &[u8], mut i: usize) -> Option<usize> {
        while s.get(i) == Some(&b'[') {
            i += 1;
        }
        match *s.get(i)? {
            b'Z' | b'B' | b'S' | b'C' | b'I' | b'J' | b'F' | b'D' => Some(i + 1),
            b'L' => {
                let start = i + 1;
                let len = s[start..].iter().position(|&c| c == b';')?;
                let ok = len > 0
                    && s[start..start + len]
                        .iter()
                        .all(|&c| c > b' ' && !matches!(c, b'(' | b')' | b'.' | b'['));
                ok.then_some(start + len + 1)
            }
            _ => None,
        }
    }
    if s.first() != Some(&b'(') {
        return false;
    }
    let mut i = 1;
    while s.get(i) != Some(&b')') {
        match field(s, i) {
            Some(n) => i = n,
            None => return false,
        }
    }
    i += 1;
    if s.get(i) == Some(&b'V') {
        return i + 1 == s.len();
    }
    field(s, i) == Some(s.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(v: &mut Vec<u8>, off: usize, x: &[u8]) {
        if v.len() < off + x.len() {
            v.resize(off + x.len(), 0);
        }
        v[off..off + x.len()].copy_from_slice(x);
    }

    /// Little-endian ELF64 with dynsym+dynstr. `sections`: keep section
    /// headers; otherwise only PT_LOAD+PT_DYNAMIC(DT_HASH) are present.
    fn elf64(names: &[(&str, u8, u16)], sections: bool) -> Vec<u8> {
        let mut strs = vec![0u8];
        let mut syms = vec![0u8; 24];
        for (n, info, shndx) in names {
            let off = strs.len() as u32;
            strs.extend_from_slice(n.as_bytes());
            strs.push(0);
            let mut s = [0u8; 24];
            s[..4].copy_from_slice(&off.to_le_bytes());
            s[4] = *info;
            s[6..8].copy_from_slice(&shndx.to_le_bytes());
            syms.extend_from_slice(&s);
        }
        let nsyms = (syms.len() / 24) as u32;
        let (symoff, stroff, hashoff, dynoff) = (0x200usize, 0x600usize, 0x700usize, 0x800usize);
        let mut b = vec![0u8; 0x40];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        put(&mut b, 0x12, &183u16.to_le_bytes());
        put(&mut b, 0x36, &56u16.to_le_bytes());
        put(&mut b, 0x3A, &64u16.to_le_bytes());
        put(&mut b, symoff, &syms);
        put(&mut b, stroff, &strs);
        // hash: nbucket, nchain
        put(&mut b, hashoff, &[1, 0, 0, 0]);
        put(&mut b, hashoff + 4, &nsyms.to_le_bytes());
        let dynv: [(u64, u64); 5] = [
            (4, hashoff as u64),
            (5, stroff as u64),
            (6, symoff as u64),
            (10, strs.len() as u64),
            (0, 0),
        ];
        for (i, (t, v)) in dynv.iter().enumerate() {
            put(&mut b, dynoff + i * 16, &t.to_le_bytes());
            put(&mut b, dynoff + i * 16 + 8, &v.to_le_bytes());
        }
        // phdrs at 0x40: PT_LOAD identity map, PT_DYNAMIC
        put(&mut b, 0x20, &0x40u64.to_le_bytes());
        put(&mut b, 0x38, &2u16.to_le_bytes());
        put(&mut b, 0x40, &1u32.to_le_bytes());
        put(&mut b, 0x40 + 0x20, &0x1000u64.to_le_bytes()); // filesz
        put(&mut b, 0x40 + 56, &2u32.to_le_bytes());
        put(&mut b, 0x40 + 56 + 8, &(dynoff as u64).to_le_bytes());
        put(&mut b, 0x40 + 56 + 0x20, &80u64.to_le_bytes());
        b.resize(0x1000, 0);
        if sections {
            // shstr-less: section 1 = DYNSYM(link 2), 2 = STRTAB
            let sh = 0x900usize;
            put(&mut b, 0x28, &(sh as u64).to_le_bytes());
            put(&mut b, 0x3C, &3u16.to_le_bytes());
            put(&mut b, sh + 64 + 4, &11u32.to_le_bytes());
            put(&mut b, sh + 64 + 0x18, &(symoff as u64).to_le_bytes());
            put(&mut b, sh + 64 + 0x20, &(syms.len() as u64).to_le_bytes());
            put(&mut b, sh + 64 + 0x28, &2u32.to_le_bytes());
            put(&mut b, sh + 128 + 4, &3u32.to_le_bytes());
            put(&mut b, sh + 128 + 0x18, &(stroff as u64).to_le_bytes());
            put(&mut b, sh + 128 + 0x20, &(strs.len() as u64).to_le_bytes());
        }
        b
    }

    const G: u8 = 0x12; // GLOBAL FUNC

    #[test]
    fn section_and_dynamic_paths_agree() {
        let names = [
            ("JNI_OnLoad", G, 7),
            ("Java_a_B_c@@VERS_1.0", G, 7),
            ("undef", G, 0),
            ("local", 0x02, 7),
        ];
        for sections in [true, false] {
            let i = parse_elf(&elf64(&names, sections)).unwrap();
            assert_eq!(
                i.path,
                if sections {
                    ElfPath::Sections
                } else {
                    ElfPath::Dynamic
                }
            );
            assert_eq!(i.exports, ["JNI_OnLoad", "Java_a_B_c"]);
            assert_eq!(i.machine, 183);
            assert!(i.complete, "{:?}", i.notes);
        }
    }

    /// Segment offsets near `u64::MAX` must not overflow offset math
    /// (a debug-build panic before; wrap-around in release).
    #[test]
    fn huge_segment_offsets_do_not_overflow() {
        let mut b = elf64(&[("JNI_OnLoad", G, 7)], false);
        // PT_LOAD only: PT_DYNAMIC stays readable so va_to_off is reached.
        put(&mut b, 0x40 + 8, &(u64::MAX - 8).to_le_bytes());
        let i = parse_elf(&b).unwrap();
        assert!(i.exports.is_empty());
    }

    #[test]
    fn hostile_input_is_reported_not_zero() {
        assert!(parse_elf(b"MZ").is_err());
        assert!(parse_elf(&[0x7f, b'E', b'L', b'F', 9, 1, 0, 0]).is_err());
        // header only: parses, but flags that no table was readable
        let mut h = elf64(&[], true);
        h.truncate(0x40);
        let i = parse_elf(&h).unwrap();
        assert_eq!(i.path, ElfPath::None);
        assert!(!i.complete && i.exports.is_empty());
        // dynsym extent past EOF is clamped and flagged
        let mut b = elf64(&[("Java_x", G, 7)], true);
        put(&mut b, 0x900 + 64 + 0x20, &(1u64 << 40).to_le_bytes());
        let i = parse_elf(&b).unwrap();
        assert!(!i.complete);
    }

    /// AArch64 ELF64: RX `PT_LOAD` va 0..0x1000, RW `PT_LOAD` file 0x1000
    /// mapped at va 0x2000, `PT_DYNAMIC` with `DT_RELA` at va 0x2800.
    /// `words`: (file offset, value) stored in place; `relocs`: (va, type,
    /// addend).
    fn jni_elf(words: &[(usize, u64)], relocs: &[(u64, u64, u64)]) -> Vec<u8> {
        let mut b = vec![0u8; 0x2000];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        put(&mut b, 0x12, &183u16.to_le_bytes());
        put(&mut b, 0x20, &0x40u64.to_le_bytes());
        put(&mut b, 0x36, &56u16.to_le_bytes());
        put(&mut b, 0x38, &3u16.to_le_bytes());
        // (type, flags, off, va, filesz)
        let ph: [(u32, u32, u64, u64, u64); 3] = [
            (1, 5, 0, 0, 0x1000),
            (1, 6, 0x1000, 0x2000, 0x1000),
            (2, 6, 0x1800, 0x2800, 0x40),
        ];
        for (i, (t, f, o, v, s)) in ph.iter().enumerate() {
            let h = 0x40 + i * 56;
            put(&mut b, h, &t.to_le_bytes());
            put(&mut b, h + 4, &f.to_le_bytes());
            put(&mut b, h + 8, &o.to_le_bytes());
            put(&mut b, h + 0x10, &v.to_le_bytes());
            put(&mut b, h + 0x20, &s.to_le_bytes());
        }
        put(
            &mut b,
            0x1100,
            b"nativeInit\0(Ljava/lang/String;[I)V\0bad\0not a sig\0",
        );
        for (i, (va, ty, add)) in relocs.iter().enumerate() {
            let e = 0x1400 + i * 24;
            put(&mut b, e, &va.to_le_bytes());
            put(&mut b, e + 8, &ty.to_le_bytes());
            put(&mut b, e + 16, &add.to_le_bytes());
        }
        let dynv: [(u64, u64); 3] = [(7, 0x2400), (8, relocs.len() as u64 * 24), (0, 0)];
        for (i, (t, v)) in dynv.iter().enumerate() {
            put(&mut b, 0x1800 + i * 16, &t.to_le_bytes());
            put(&mut b, 0x1808 + i * 16, &v.to_le_bytes());
        }
        for (o, v) in words {
            put(&mut b, *o, &v.to_le_bytes());
        }
        b
    }

    const NAME: u64 = 0x2100;
    const SIG: u64 = 0x210b;

    fn sleb(mut v: i64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if (v == 0 && b & 0x40 == 0) || (v == -1 && b & 0x40 != 0) {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    /// `jni_elf` whose only relocation table is an APS2 `DT_ANDROID_RELA`
    /// stream (`vals` SLEB128-encoded after the magic) at va 0x2400.
    fn aps2_elf(vals: &[i64], cut: usize) -> Vec<u8> {
        let mut blob = b"APS2".to_vec();
        for v in vals {
            sleb(*v, &mut blob);
        }
        blob.truncate(blob.len() - cut);
        let mut b = jni_elf(&[], &[]);
        put(&mut b, 0x1400, &blob);
        put(&mut b, 0x1800, &0x6000_0011u64.to_le_bytes());
        put(&mut b, 0x1810, &0x6000_0012u64.to_le_bytes());
        put(&mut b, 0x1818, &(blob.len() as u64).to_le_bytes());
        b
    }

    #[test]
    fn jni_tables_decode_aps2_packed_relocations() {
        let (n, s) = (NAME as i64, SIG as i64);
        let vals = [
            4,
            0x2200 - 8, // count, start offset
            // group: 3 relocs, by info + offset delta, addend per reloc
            3,
            1 | 2 | 8,
            8,
            1027,
            n,
            s - n,
            0x501 - s, // negative delta
            // group: 1 symbolic reloc (no addend) at 0x2250
            1,
            1 | 2,
            0x40,
            257,
        ];
        let t = jni_tables(&aps2_elf(&vals, 0)).unwrap();
        assert!(t.complete, "{:?}", t.notes);
        assert_eq!(
            t.entries,
            [JniEntry {
                name: "nativeInit".into(),
                signature: "(Ljava/lang/String;[I)V".into(),
                fn_addr: Some(0x501),
            }]
        );
        // A truncated stream keeps what decoded and says it is incomplete.
        let t = jni_tables(&aps2_elf(&vals, 2)).unwrap();
        assert!(!t.complete);
        assert!(
            t.notes
                .iter()
                .any(|m| m.contains("APS2") && m.contains("truncated")),
            "{:?}",
            t.notes
        );
        // Garbage magic is reported, not trusted.
        let mut b = aps2_elf(&vals, 0);
        put(&mut b, 0x1400, b"XXXX");
        let t = jni_tables(&b).unwrap();
        assert!(
            t.notes.iter().any(|m| m.contains("bad magic")),
            "{:?}",
            t.notes
        );
    }

    #[test]
    fn jni_tables_resolve_rela_in_place_and_symbolic_pointers() {
        const REL: u64 = 1027;
        let relocs = [
            // entry 0 (va 0x2200): all three RELATIVE
            (0x2200, REL, NAME),
            (0x2208, REL, SIG),
            (0x2210, REL, 0x500 | 1),
            // entry 1 (va 0x2240): signature pointer lands mid-string
            (0x2240, REL, NAME),
            (0x2248, REL, 0x211e), // "[I)V"
            (0x2250, 257, 0),
        ];
        // entry 2 (file 0x1280 / va 0x2280): pointers stored in place
        let words = [(0x1280, NAME), (0x1288, SIG), (0x1290, 0x600)];
        let t = jni_tables(&jni_elf(&words, &relocs)).unwrap();
        assert!(t.complete, "{:?}", t.notes);
        let sig = "(Ljava/lang/String;[I)V";
        let e = |f| JniEntry {
            name: "nativeInit".into(),
            signature: sig.into(),
            fn_addr: f,
        };
        assert_eq!(t.entries, [e(Some(0x501)), e(Some(0x600))]);
    }

    #[test]
    fn jni_tables_reject_bad_signature_and_data_fn_pointer() {
        const REL: u64 = 1027;
        let relocs = [
            (0x2200, REL, NAME),
            (0x2208, REL, 0x2123), // "bad"
            (0x2210, REL, 0x500),
            (0x2240, REL, NAME),
            (0x2248, REL, SIG),
            (0x2250, REL, 0x2100), // fn into data
            (0x2280, REL, NAME),
            (0x2288, REL, SIG),
            (0x2290, 257, 0), // symbolic fn
        ];
        let t = jni_tables(&jni_elf(&[], &relocs)).unwrap();
        assert_eq!(t.entries.len(), 1);
        assert_eq!(t.entries[0].fn_addr, None);
    }

    #[test]
    fn jni_signature_grammar() {
        for ok in ["()V", "(IJ)Z", "([[Ljava/lang/Object;)[B", "(La/B;)La/B;"] {
            assert!(jni_sig_ok(ok.as_bytes()), "{ok}");
        }
        for bad in [
            "", "()", "(V)V", "()VV", "(L;)V", "(La.B;)V", "(I", "([)V", "()[V",
        ] {
            assert!(!jni_sig_ok(bad.as_bytes()), "{bad}");
        }
    }
}
