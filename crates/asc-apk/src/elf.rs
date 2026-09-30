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
    let (phoff, phentsize, phnum) = if is64 {
        (r.n(0x20, 8), r.u16(0x36), r.u16(0x38))
    } else {
        (r.n(0x1C, 4), r.u16(0x2A), r.u16(0x2C))
    };
    let (Some(phoff), Some(phentsize), Some(phnum)) = (phoff, phentsize, phnum) else {
        return false;
    };
    let min_ent = if is64 { 56 } else { 32 };
    if phoff == 0 || phnum == 0 || (phentsize as usize) < min_ent {
        return false;
    }
    // (type, offset, vaddr, filesz)
    let mut loads = Vec::new();
    let mut dynamic = None;
    for i in 0..phnum {
        let h = phoff + i * phentsize;
        let Some(ty) = r.u32(h) else { return false };
        let seg = if is64 {
            (r.n(h + 8, 8), r.n(h + 0x10, 8), r.n(h + 0x20, 8))
        } else {
            (r.u32(h + 4), r.u32(h + 8), r.u32(h + 0x10))
        };
        let (Some(off), Some(va), Some(fsz)) = seg else {
            return false;
        };
        match ty {
            1 => loads.push((off, va, fsz)),
            2 => dynamic = dynamic.or(Some((off, fsz))),
            _ => {}
        }
    }
    let to_off = |va: u64| {
        loads
            .iter()
            .find_map(|&(off, v, fsz)| (va >= v && va - v < fsz).then(|| off + (va - v)))
    };
    let Some((doff, dsz)) = dynamic else {
        return false;
    };
    let esz = if is64 { 16 } else { 8 };
    let (mut symtab, mut strtab, mut strsz, mut hash, mut gnu) = (None, None, None, None, None);
    for i in 0..(dsz / esz).min(MAX_DYN_ENTRIES as u64) {
        let p = doff + i * esz;
        let (Some(tag), Some(val)) = (r.w(p, is64), r.w(p + esz / 2, is64)) else {
            break;
        };
        match tag {
            0 => break,
            4 => hash = Some(val),
            5 => strtab = Some(val),
            6 => symtab = Some(val),
            10 => strsz = Some(val),
            0x6fff_fef5 => gnu = Some(val),
            _ => {}
        }
    }
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
}
