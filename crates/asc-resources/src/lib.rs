//! Bounded `resources.arsc` reader (display/triage only).
//!
//! Layout follows AOSP `ResourceTypes.h` (android-14.0.0_r1). Facts that
//! matter and are easy to get wrong:
//! - a resource ID is `(package_id << 24) | ((type_id + typeIdOffset) << 16)
//!   | entry_index`; the entry's *key string index* is a different field;
//! - `TYPE_STRING` values index the table's GLOBAL string pool, not the
//!   package key pool;
//! - type chunks may be dense (u32 offsets), `FLAG_OFFSET16` (u16 offsets,
//!   x4, `0xFFFF` = absent) or `FLAG_SPARSE` (`idx:u16, offset/4:u16`);
//!   entries may be full, complex (bag) or compact (key u16, data type in
//!   the high byte of flags).
//!
//! Errors inside a chunk never guess where the next chunk starts: the
//! container's walk stops, a diagnostic is recorded and
//! [`Table::complete`] becomes `false`.

use asc_apk::string_pool::{self, Limits, PoolError};

const RES_TABLE: u16 = 0x0002;
const RES_STRING_POOL: u16 = 0x0001;
const RES_PACKAGE: u16 = 0x0200;
const RES_TYPE: u16 = 0x0201;

const FLAG_SPARSE: u8 = 0x01;
const FLAG_OFFSET16: u8 = 0x02;
const ENTRY_COMPLEX: u16 = 0x0001;
const ENTRY_COMPACT: u16 = 0x0008;

/// Cap on strings per pool.
const MAX_STRINGS: u32 = 1 << 20;
/// Decoded string bytes across every pool of the table.
const MAX_STRING_BYTES: u64 = 32 * 1024 * 1024;
/// Entries plus bag items retained (bounds allocation, not just input size).
const MAX_ITEMS: usize = 1 << 21;
const MAX_DIAGNOSTICS: usize = 100;
const MAX_PACKAGES: usize = 256;

/// A typed value (`Res_value`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Res {
    pub data_type: u8,
    pub data: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Simple(Res),
    /// Complex entry: parent style reference and `(name reference, value)`.
    Bag {
        parent: u32,
        items: Vec<(u32, Res)>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Full resource ID.
    pub id: u32,
    /// Type chunk `id` (before `typeIdOffset`).
    pub type_id: u8,
    pub entry_index: u16,
    /// Index into the package key pool (NOT part of the ID).
    pub key_index: u32,
    /// Index into [`Package::configs`].
    pub config: u32,
    pub flags: u16,
    pub value: Value,
}

#[derive(Debug, Clone, Default)]
pub struct Package {
    pub id: u32,
    pub name: String,
    pub type_names: Vec<String>,
    pub key_names: Vec<String>,
    pub type_id_offset: u32,
    /// Raw `ResTable_config` bytes per distinct type chunk config.
    pub configs: Vec<Vec<u8>>,
    pub entries: Vec<Entry>,
}

impl Package {
    /// Type name for a chunk `id`; `?NN` when the pool has no such slot.
    pub fn type_name(&self, type_id: u8) -> String {
        match (type_id as usize)
            .checked_sub(1)
            .and_then(|i| self.type_names.get(i))
        {
            Some(s) if !s.is_empty() => s.clone(),
            _ => format!("?{type_id}"),
        }
    }

    pub fn key_name(&self, e: &Entry) -> &str {
        self.key_names
            .get(e.key_index as usize)
            .map_or("", String::as_str)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Table {
    /// Global value string pool.
    pub strings: Vec<String>,
    pub packages: Vec<Package>,
    pub diagnostics: Vec<String>,
    /// `false` when any structure was skipped or malformed.
    pub complete: bool,
    /// Chunks with a valid extent but an unknown type (skipped, counted).
    pub skipped_chunks: usize,
}

struct Ctx<'a> {
    b: &'a [u8],
    t: Table,
    items: usize,
    string_bytes: u64,
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(off..off.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(off..off.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// `(type, header_size, end)` of the chunk at `off`, validated against `limit`.
fn chunk(b: &[u8], off: usize, limit: usize) -> Result<(u16, usize, usize), String> {
    let (Some(ty), Some(hs), Some(size)) = (u16_at(b, off), u16_at(b, off + 2), u32_at(b, off + 4))
    else {
        return Err(format!("chunk header at {off} truncated"));
    };
    let (hs, size) = (hs as usize, size as usize);
    let end = off.checked_add(size).filter(|&e| e <= limit);
    match end {
        Some(end) if hs >= 8 && hs <= size => Ok((ty, hs, end)),
        _ => Err(format!(
            "chunk at {off}: bad extent (type 0x{ty:04x}, header {hs}, size {size}, limit {limit})"
        )),
    }
}

impl Ctx<'_> {
    fn diag(&mut self, s: String) {
        self.t.complete = false;
        if self.t.diagnostics.len() < MAX_DIAGNOSTICS {
            self.t.diagnostics.push(s);
        }
    }

    fn pool(&mut self, off: usize, end: usize, what: &str) -> Vec<String> {
        let lim = Limits {
            max_count: MAX_STRINGS,
            max_bytes: MAX_STRING_BYTES.saturating_sub(self.string_bytes),
        };
        match string_pool::parse(self.b, off, end, lim) {
            Ok(p) => {
                self.string_bytes += p.strings.iter().map(|s| s.len() as u64).sum::<u64>();
                if p.bad_slots > 0 {
                    // Lenient like Android's lazy pool: noted, not incomplete.
                    if self.t.diagnostics.len() < MAX_DIAGNOSTICS {
                        self.t.diagnostics.push(format!(
                            "{what}: {} undecodable string slot(s) read as empty",
                            p.bad_slots
                        ));
                    }
                }
                p.strings
            }
            Err(e) => {
                let kind = match e {
                    PoolError::Truncated(_) => "truncated",
                    PoolError::Bad(_) => "bad",
                };
                self.diag(format!("{what}: {kind} string pool: {e}"));
                Vec::new()
            }
        }
    }

    fn package(&mut self, off: usize, hs: usize, end: usize) {
        let b = self.b;
        let (Some(id), Some(type_strings), Some(key_strings)) = (
            u32_at(b, off + 8),
            u32_at(b, off + 268),
            u32_at(b, off + 276),
        ) else {
            return self.diag(format!("package at {off}: header truncated"));
        };
        if hs < 284 {
            return self.diag(format!("package at {off}: header size {hs} < 284"));
        }
        if id > 0xff {
            return self.diag(format!(
                "package at {off}: id 0x{id:x} does not fit a resource ID"
            ));
        }
        let name_units: Vec<u16> = b[off + 12..off + 268]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        let mut p = Package {
            id,
            name: String::from_utf16_lossy(&name_units),
            type_id_offset: if hs >= 288 {
                u32_at(b, off + 284).unwrap_or(0)
            } else {
                0
            },
            ..Package::default()
        };
        for (rel, is_type) in [(type_strings, true), (key_strings, false)] {
            if rel == 0 {
                continue;
            }
            let pool_off = off.saturating_add(rel as usize);
            match chunk(b, pool_off, end) {
                Ok((RES_STRING_POOL, _, pend)) => {
                    let s = self.pool(
                        pool_off,
                        pend,
                        if is_type { "type names" } else { "key names" },
                    );
                    if is_type {
                        p.type_names = s;
                    } else {
                        p.key_names = s;
                    }
                }
                Ok((ty, ..)) => self.diag(format!(
                    "package at {off}: pool offset holds chunk 0x{ty:04x}"
                )),
                Err(e) => self.diag(format!("package at {off}: {e}")),
            }
        }
        let mut pos = off + hs;
        while pos < end {
            let (ty, chs, cend) = match chunk(b, pos, end) {
                Ok(c) => c,
                Err(e) => {
                    self.diag(e);
                    break;
                }
            };
            if ty == RES_TYPE {
                self.type_chunk(&mut p, pos, chs, cend);
            } else if ty != RES_STRING_POOL && ty != 0x0202 && ty != 0x0203 {
                self.t.skipped_chunks += 1;
            }
            pos = cend;
        }
        self.t.packages.push(p);
    }

    fn type_chunk(&mut self, p: &mut Package, off: usize, hs: usize, end: usize) {
        let b = self.b;
        let (Some(&type_id), Some(&flags), Some(count), Some(entries_start), Some(cfg_size)) = (
            b.get(off + 8),
            b.get(off + 9),
            u32_at(b, off + 12),
            u32_at(b, off + 16),
            u32_at(b, off + 20),
        ) else {
            return self.diag(format!("type chunk at {off}: header truncated"));
        };
        if type_id == 0 || hs < 24 {
            return self.diag(format!(
                "type chunk at {off}: invalid id {type_id} / header {hs}"
            ));
        }
        // Config is read by its declared size, clamped to the header.
        let cfg_len = (cfg_size as usize).clamp(4, hs - 20);
        let config = b[off + 20..off + 20 + cfg_len].to_vec();
        let eff_type = p.type_id_offset.saturating_add(type_id as u32);
        if eff_type > 0xff {
            return self.diag(format!(
                "type chunk at {off}: type {type_id}+offset {} exceeds 8 bits",
                p.type_id_offset
            ));
        }
        let sparse = flags & FLAG_SPARSE != 0;
        let off16 = flags & FLAG_OFFSET16 != 0;
        if !sparse && count > 0x1_0000 {
            return self.diag(format!(
                "type chunk at {off}: {count} dense entries exceed the 16-bit entry index"
            ));
        }
        let width = if !sparse && off16 { 2 } else { 4 };
        let table_end = (count as usize)
            .checked_mul(width)
            .and_then(|n| (off + hs).checked_add(n))
            .filter(|&e| e <= end);
        let Some(_) = table_end else {
            return self.diag(format!("type chunk at {off}: offset table overruns chunk"));
        };
        let Some(base) = off
            .checked_add(entries_start as usize)
            .filter(|&x| x <= end)
        else {
            return self.diag(format!(
                "type chunk at {off}: entriesStart {entries_start} overruns chunk"
            ));
        };
        let cfg_idx = match p.configs.iter().position(|c| *c == config) {
            Some(i) => i,
            None => {
                p.configs.push(config);
                p.configs.len() - 1
            }
        } as u32;
        for i in 0..count as usize {
            let (index, rel) = if sparse {
                let w = u32_at(b, off + hs + 4 * i).unwrap_or(0);
                ((w & 0xffff) as u16, (w >> 16) * 4)
            } else if off16 {
                let w = u16_at(b, off + hs + 2 * i).unwrap_or(0xffff);
                (i as u16, if w == 0xffff { u32::MAX } else { w as u32 * 4 })
            } else {
                (i as u16, u32_at(b, off + hs + 4 * i).unwrap_or(u32::MAX))
            };
            if rel == u32::MAX {
                continue; // NO_ENTRY: absent, not an error
            }
            if self.items >= MAX_ITEMS {
                return self.diag("retained entry budget exhausted; table truncated".into());
            }
            let Some(at) = base.checked_add(rel as usize).filter(|&x| x < end) else {
                self.diag(format!(
                    "type chunk at {off}: entry {index} offset {rel} overruns chunk"
                ));
                continue;
            };
            match self.entry(at, end) {
                Ok((key_index, eflags, value)) => {
                    self.items += 1;
                    p.entries.push(Entry {
                        id: (p.id << 24) | (eff_type << 16) | index as u32,
                        type_id,
                        entry_index: index,
                        key_index,
                        config: cfg_idx,
                        flags: eflags,
                        value,
                    });
                }
                Err(e) => self.diag(format!("type chunk at {off}: entry {index}: {e}")),
            }
        }
    }

    fn res(&self, at: usize, end: usize) -> Option<Res> {
        if at.checked_add(8)? > end {
            return None;
        }
        Some(Res {
            data_type: self.b[at + 3],
            data: u32_at(self.b, at + 4)?,
        })
    }

    fn entry(&mut self, at: usize, end: usize) -> Result<(u32, u16, Value), String> {
        let b = self.b;
        if at.checked_add(8).is_none_or(|e| e > end) {
            return Err("entry header truncated".into());
        }
        let size = u16_at(b, at).unwrap_or(0) as usize;
        let flags = u16_at(b, at + 2).unwrap_or(0);
        if flags & ENTRY_COMPACT != 0 {
            let key = u16_at(b, at).unwrap_or(0) as u32;
            let v = Res {
                data_type: (flags >> 8) as u8,
                data: u32_at(b, at + 4).unwrap_or(0),
            };
            return Ok((key, flags, Value::Simple(v)));
        }
        let key = u32_at(b, at + 4).unwrap_or(0);
        if size < 8 {
            return Err(format!("entry size {size} < 8"));
        }
        if flags & ENTRY_COMPLEX == 0 {
            let v = self.res(at + size, end).ok_or("value truncated")?;
            return Ok((key, flags, Value::Simple(v)));
        }
        if size < 16 || at + 16 > end {
            return Err(format!("complex entry size {size} < 16"));
        }
        let parent = u32_at(b, at + 8).unwrap_or(0);
        let count = u32_at(b, at + 12).unwrap_or(0) as usize;
        let start = at + size;
        let need = count.checked_mul(12).and_then(|n| start.checked_add(n));
        if need.is_none_or(|e| e > end) {
            return Err(format!("bag of {count} items overruns chunk"));
        }
        if count > MAX_ITEMS - self.items {
            return Err(format!("bag of {count} items exceeds retained budget"));
        }
        self.items += count;
        let items = (0..count)
            .map(|i| {
                let m = start + 12 * i;
                let r = self.res(m + 4, end).expect("bounds checked above");
                (u32_at(b, m).unwrap_or(0), r)
            })
            .collect();
        Ok((key, flags, Value::Bag { parent, items }))
    }
}

/// Parse a `resources.arsc` blob. Structural failures in the outer table
/// header are `Err`; everything else degrades to diagnostics.
pub fn parse(bytes: &[u8]) -> Result<Table, String> {
    let (ty, hs, mut end) = {
        let ty = u16_at(bytes, 0).ok_or("resources.arsc: truncated header")?;
        let hs = u16_at(bytes, 2).ok_or("resources.arsc: truncated header")? as usize;
        let size = u32_at(bytes, 4).ok_or("resources.arsc: truncated header")? as usize;
        (ty, hs, size)
    };
    if ty != RES_TABLE {
        return Err(format!("not a resource table (chunk type 0x{ty:04x})"));
    }
    if hs < 12 || hs > bytes.len() {
        return Err(format!("resource table header size {hs} invalid"));
    }
    let mut cx = Ctx {
        b: bytes,
        t: Table {
            complete: true,
            ..Table::default()
        },
        items: 0,
        string_bytes: 0,
    };
    if end > bytes.len() || end < hs {
        cx.diag(format!("table size {end} vs file {}; clamped", bytes.len()));
        end = bytes.len();
    }
    let mut pos = hs;
    let mut have_global = false;
    while pos < end {
        let (cty, chs, cend) = match chunk(bytes, pos, end) {
            Ok(c) => c,
            Err(e) => {
                cx.diag(e);
                break;
            }
        };
        match cty {
            RES_STRING_POOL if !have_global => {
                have_global = true;
                cx.t.strings = cx.pool(pos, cend, "global strings");
            }
            RES_PACKAGE => {
                if cx.t.packages.len() >= MAX_PACKAGES {
                    cx.diag("package limit reached".into());
                    break;
                }
                cx.package(pos, chs, cend);
            }
            _ => cx.t.skipped_chunks += 1,
        }
        pos = cend;
    }
    Ok(cx.t)
}

impl Table {
    /// Every `(package, entry)` with resource ID `id` (one per config).
    pub fn by_id(&self, id: u32) -> impl Iterator<Item = (&Package, &Entry)> {
        self.packages
            .iter()
            .flat_map(|p| p.entries.iter().map(move |e| (p, e)))
            .filter(move |(_, e)| e.id == id)
    }

    /// Render a typed value. `TYPE_STRING` resolves in the GLOBAL pool;
    /// references keep their raw ID (system `0x01…` included).
    pub fn render(&self, r: Res) -> String {
        match r.data_type {
            0x00 => "null".into(),
            0x01 => format!("@0x{:08x}", r.data),
            0x02 => format!("?0x{:08x}", r.data),
            0x03 => match self.strings.get(r.data as usize) {
                Some(s) => format!("{s:?}"),
                None => format!("<string #{} out of range>", r.data),
            },
            0x04 => format!("{}", f32::from_bits(r.data)),
            0x10 => format!("{}", r.data as i32),
            0x11 => format!("0x{:x}", r.data),
            0x12 => (r.data != 0).to_string(),
            0x1c..=0x1f => format!("#{:08x}", r.data),
            t => format!("type=0x{t:02x} data=0x{:08x}", r.data),
        }
    }
}

/// Human-readable config: known leading fields plus raw hex. `default`
/// when every byte after `size` is zero.
pub fn describe_config(c: &[u8]) -> String {
    if c.len() <= 4 || c[4..].iter().all(|&b| b == 0) {
        return "default".into();
    }
    let mut parts = Vec::new();
    let ch = |i: usize| c.get(i).copied().filter(|&b| b != 0).map(|b| b as char);
    if let Some(l0) = ch(8) {
        let mut s = String::from(l0);
        s.extend(ch(9));
        if let Some(c0) = ch(10) {
            s.push('-');
            s.push(c0);
            s.extend(ch(11));
        }
        parts.push(s);
    }
    if let Some(d) = u16_at(c, 14).filter(|&d| d != 0) {
        parts.push(format!("{d}dpi"));
    }
    if let Some(v) = u16_at(c, 24).filter(|&v| v != 0) {
        parts.push(format!("v{v}"));
    }
    let hex: String = c[4..].iter().map(|b| format!("{b:02x}")).collect();
    parts.push(format!("raw={hex}"));
    parts.join(" ")
}

#[cfg(test)]
mod tests;
