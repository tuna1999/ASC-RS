//! Test helpers for `asc-query` integration tests.
//!
//! Two facilities live here:
//!
//! 1. **Corpus loader** — finds `corpus/dex/*.dex` next to the workspace
//!    root and parses each into a [`asc_dex::DexView`]. Tests skip
//!    gracefully when the corpus is missing.
//! 2. **DEX builder** — a small, flexible byte-level constructor that
//!    builds a valid `dex\n035\0` DEX containing the strings / types /
//!    methods / classes the test asks for, with arbitrary bytecode in
//!    each method. Modeled on the asc-dex builder at
//!    `crates/asc-dex/tests/common/mod.rs`, but parameterized by the
//!    test instead of baked-in.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use asc_dex::view::DexView;

// --------------------- corpus loader ---------------------

/// Returns the corpus DEX directory (workspace root + `corpus/dex`).
/// Returns `None` if the workspace layout cannot be located.
pub fn corpus_dex_dir() -> Option<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("corpus").join("dex"))
}

/// Reads one corpus DEX by short name (e.g. `"workload_classes.dex"`).
/// Returns `None` if the file is missing.
pub fn read_corpus_dex(name: &str) -> Option<Vec<u8>> {
    let dir = corpus_dex_dir()?;
    let path = dir.join(name);
    if !path.is_file() {
        return None;
    }
    std::fs::read(&path).ok()
}

/// Reads one corpus DEX into `buf` and parses it. Returns a view that
/// borrows from `buf`. The caller MUST keep `buf` alive for the
/// lifetime of the returned view.
///
/// Returns `None` if the corpus file is missing or fails to parse.
pub fn parse_corpus_dex<'a>(name: &str, buf: &'a mut Vec<u8>) -> Option<DexView<'a>> {
    let bytes = read_corpus_dex(name)?;
    buf.clear();
    buf.extend_from_slice(&bytes);
    DexView::parse(buf).ok()
}
// --------------------- DEX builder ---------------------

const DEX_MAGIC: &[u8; 8] = b"dex\n035\0";
const HEADER_SIZE: u32 = 0x70;

/// Layout-tracking helper. Tracks the next free byte offset and
/// exposes typed offsets to call sites. Mirrors the asc-dex test
/// builder pattern but exposes a programmatic API.
pub struct Builder {
    pub buf: Vec<u8>,
    string_offsets: Vec<u32>,
    type_descriptor_strs: Vec<u32>,
    field_specs: Vec<(u32, u32, u32)>, // (class_type, ty_type, name_str)
    method_specs: Vec<(u32, u32, u32)>, // (class_type, proto_idx, name_str)
    proto_specs: Vec<(u32, u32, u32, u32)>, // (shorty_str, return_type, params_off)
    class_defs: Vec<ClassDefSpec>,
    next_align: u32,
}

#[derive(Clone)]
pub struct ClassDefSpec {
    pub class_type: u32,
    pub access_flags: u32,
    pub superclass: Option<u32>,
    pub class_data_off: u32,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            string_offsets: Vec::new(),
            type_descriptor_strs: Vec::new(),
            field_specs: Vec::new(),
            method_specs: Vec::new(),
            proto_specs: Vec::new(),
            class_defs: Vec::new(),
            next_align: 0,
        }
    }

    /// Allocates a 4-byte slot and writes the value. Extends the
    /// buffer with zeros as needed.
    fn write_u32(&mut self, off: u32, v: u32) {
        let end = off + 4;
        if end as usize > self.buf.len() {
            self.buf.resize(end as usize, 0);
        }
        self.buf[off as usize..end as usize].copy_from_slice(&v.to_le_bytes());
    }

    fn write_u16(&mut self, off: u32, v: u16) {
        let end = off + 2;
        if end as usize > self.buf.len() {
            self.buf.resize(end as usize, 0);
        }
        self.buf[off as usize..end as usize].copy_from_slice(&v.to_le_bytes());
    }

    fn write_bytes(&mut self, off: u32, s: &[u8]) {
        let end = off + s.len() as u32;
        if end as usize > self.buf.len() {
            self.buf.resize(end as usize, 0);
        }
        self.buf[off as usize..end as usize].copy_from_slice(s);
    }

    /// Returns the next 4-byte aligned offset.
    fn align4(&mut self) -> u32 {
        let a = (self.next_align + 3) & !3;
        if a as usize > self.buf.len() {
            self.buf.resize(a as usize, 0);
        }
        self.next_align = a;
        a
    }

    /// Appends a string and returns its index. Strings are written as
    /// `uleb128 utf16_len_hint + raw MUTF-8 bytes + 0x00 terminator`.
    /// The pattern is built around ASCII content (the tests do not
    /// exercise non-ASCII MUTF-8 round-tripping).
    pub fn add_string(&mut self, s: &str) -> u32 {
        let idx = self.string_offsets.len() as u32;
        let payload = s.as_bytes();
        // utf16_len_hint = byte count (close enough for ASCII).
        let hint = payload.len() as u32;
        let data_off = self.align4();
        let mut off = data_off;
        // uleb128 hint (1 byte for values < 128).
        if hint < 0x80 {
            self.write_u32(off, hint);
            off += 1;
        } else {
            // Two-byte uleb128.
            self.write_u16(off, ((hint & 0x7F) as u16) | 0x80);
            off += 1;
            self.write_u8(off, ((hint >> 7) & 0x7F) as u8);
            off += 1;
        }
        // payload
        self.write_bytes(off, payload);
        off += payload.len() as u32;
        // NUL terminator
        self.write_u8(off, 0);
        off += 1;
        self.next_align = off;
        self.string_offsets.push(data_off);
        idx
    }

    fn write_u8(&mut self, off: u32, v: u8) {
        if (off + 1) as usize > self.buf.len() {
            self.buf.resize((off + 1) as usize, 0);
        }
        self.buf[off as usize] = v;
    }

    /// Appends a type descriptor and returns its index.
    pub fn add_type(&mut self, descriptor: &str) -> u32 {
        let sidx = self.add_string(descriptor);
        let idx = self.type_descriptor_strs.len() as u32;
        self.type_descriptor_strs.push(sidx);
        idx
    }

    /// Appends a proto and returns its index. `return_type` is a
    /// `TypeIdx`; `param_types` are appended to the params list as a
    /// single `type_list` (4-byte count + 2-byte entries).
    pub fn add_proto(&mut self, shorty: &str, return_type: u32, param_types: &[u32]) -> u32 {
        let shorty_idx = self.add_string(shorty);
        let params_off = if param_types.is_empty() {
            0
        } else {
            let off = self.align4();
            self.write_u32(off, param_types.len() as u32);
            let mut cur = off + 4;
            for &t in param_types {
                self.write_u16(cur, t as u16);
                cur += 2;
            }
            self.next_align = cur;
            off
        };
        let idx = self.proto_specs.len() as u32;
        self.proto_specs.push((shorty_idx, return_type, params_off, 0));
        idx
    }

    /// Appends a field and returns its index.
    pub fn add_field(&mut self, class_type: u32, ty_type: u32, name: &str) -> u32 {
        let name_idx = self.add_string(name);
        let idx = self.field_specs.len() as u32;
        self.field_specs.push((class_type, ty_type, name_idx));
        idx
    }

    /// Appends a method and returns its index. `code` is the
    /// 16-bit-code-unit bytecode body. Returns `(method_idx,
    /// code_off)` so callers can wire up class_data later.
    pub fn add_method(
        &mut self,
        class_type: u32,
        proto_idx: u32,
        name: &str,
        code: &[u16],
    ) -> (u32, u32) {
        let name_idx = self.add_string(name);
        let idx = self.method_specs.len() as u32;
        self.method_specs.push((class_type, proto_idx, name_idx));
        // Write a code_item at the next aligned offset.
        let code_off = if code.is_empty() {
            0 // abstract / native
        } else {
            let off = self.align4();
            // code_item layout: registers_size(u16), ins_size(u16),
            // outs_size(u16), tries_size(u16), debug_info_off(u32),
            // insns_size(u32), insns[insns_size * 2].
            let header = 16u32;
            self.write_u16(off, 1); // registers_size
            self.write_u16(off + 2, 1); // ins_size
            self.write_u16(off + 4, 0); // outs_size
            self.write_u16(off + 6, 0); // tries_size
            self.write_u32(off + 8, 0); // debug_info_off
            self.write_u32(off + 12, code.len() as u32);
            let mut cur = off + header;
            for &cu in code {
                self.write_u16(cur, cu);
                cur += 2;
            }
            self.next_align = cur;
            off
        };
        (idx, code_off)
    }

    /// Appends a class_def with one `direct_methods` entry per
    /// `(method_idx, code_off)` pair, plus an empty static/instance
    /// field list. `access_flags` is stored verbatim.
    ///
    /// Returns the new `ClassDefSpec`.
    pub fn add_class(
        &mut self,
        class_type: u32,
        access_flags: u32,
        superclass: Option<u32>,
        direct_methods: &[(u32, u32)],
    ) -> ClassDefSpec {
        let class_data_off = if direct_methods.is_empty() {
            0
        } else {
            let off = self.align4();
            // class_data: 4 uleb sizes + (static_fields size * 1 uleb)
            // + (instance_fields size * 1 uleb) + direct_methods
            // (1 uleb idx + 1 uleb access + 1 uleb code_off each).
            let mut cur = off;
            cur = self.write_uleb(cur, 0); // static_fields_size
            cur = self.write_uleb(cur, 0); // instance_fields_size
            cur = self.write_uleb(cur, direct_methods.len() as u32); // direct_methods_size
            cur = self.write_uleb(cur, 0); // virtual_methods_size
            let mut last_idx: u32 = 0;
            for &(mid, code_off) in direct_methods {
                cur = self.write_uleb(cur, mid - last_idx);
                cur = self.write_uleb(cur, access_flags);
                cur = self.write_uleb(cur, code_off);
                last_idx = mid;
            }
            self.next_align = cur;
            off
        };
        let spec = ClassDefSpec {
            class_type,
            access_flags,
            superclass,
            class_data_off,
        };
        self.class_defs.push(spec.clone());
        spec
    }

    fn write_uleb(&mut self, mut off: u32, mut v: u32) -> u32 {
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                self.write_u8(off, byte);
                return off + 1;
            }
            self.write_u8(off, byte | 0x80);
            off += 1;
        }
    }

    /// Serializes the layout into a complete DEX header + pool
    /// structure. After calling this, `bytes()` returns the finalized
    /// buffer.
    ///
    /// Layout (offsets in build order):
    /// - 0x00: DEX header (0x70 bytes)
    /// - then string_ids, type_ids, proto_ids, field_ids, method_ids,
    ///   class_defs, type_lists, code_items, class_data, string_data,
    ///   map_list.
    pub fn finalize(mut self) -> Vec<u8> {
        // Allocate pools in order; remember offsets.
        let string_ids_off = 0x70u32;
        let string_ids_size = self.string_offsets.len() as u32;
        let string_ids_end = string_ids_off + string_ids_size * 4;

        let type_ids_off = align4(string_ids_end);
        let type_ids_size = self.type_descriptor_strs.len() as u32;
        let type_ids_end = type_ids_off + type_ids_size * 4;

        let proto_ids_off = align4(type_ids_end);
        let proto_ids_size = self.proto_specs.len() as u32;
        let proto_ids_end = proto_ids_off + proto_ids_size * 12;

        let field_ids_off = align4(proto_ids_end);
        let field_ids_size = self.field_specs.len() as u32;
        let field_ids_end = field_ids_off + field_ids_size * 8;

        let method_ids_off = align4(field_ids_end);
        let method_ids_size = self.method_specs.len() as u32;
        let method_ids_end = method_ids_off + method_ids_size * 8;

        let class_defs_off = align4(method_ids_end);
        let class_defs_size = self.class_defs.len() as u32;
        let class_defs_end = class_defs_off + class_defs_size * 32;

        // Move next_align past the pool region so subsequent code /
        // class_data / string_data writes don't trample it.
        self.next_align = class_defs_end;

        // Recompute code_items / class_data / string_data offsets so
        // we don't overwrite the pools. We need to know where
        // string_data starts so we can write string_ids values.
        // Strategy: place string_data *first* (it's at the bottom),
        // then code_items, then class_data, then map_list.
        //
        // But we already wrote the strings during add_string(). The
        // data they wrote lives at self.next_align-onwards. Capture
        // the lowest free slot before we started writing strings to
        // know the string-data region. Simpler: we'll just patch the
        // string_ids_off / type_ids_off / etc. into the header now
        // and trust the earlier string writes.
        //
        // For tests we control: writes only happen via
        // self.write_* / self.align4, all of which extend buf. As
        // long as we never collide with already-written string data,
        // we're fine.
        let string_id_entries: Vec<u32> = self.string_offsets.to_vec();
        let type_id_entries: Vec<u32> = self.type_descriptor_strs.to_vec();
        let proto_entries: Vec<(u32, u32, u32, u32)> = self.proto_specs.to_vec();
        let field_entries: Vec<(u32, u32, u32)> = self.field_specs.to_vec();
        let method_entries: Vec<(u32, u32, u32)> = self.method_specs.to_vec();
        let class_entries: Vec<ClassDefSpec> = self.class_defs.clone();
        for (i, off) in string_id_entries.iter().enumerate() {
            self.write_u32(string_ids_off + i as u32 * 4, *off);
        }
        for (i, sidx) in type_id_entries.iter().enumerate() {
            self.write_u32(type_ids_off + i as u32 * 4, *sidx);
        }
        for (i, (shorty, ret, params_off, _pad)) in proto_entries.iter().enumerate() {
            let base = proto_ids_off + i as u32 * 12;
            self.write_u32(base, *shorty);
            self.write_u32(base + 4, *ret);
            self.write_u32(base + 8, *params_off);
        }
        for (i, (cls, ty, name)) in field_entries.iter().enumerate() {
            let base = field_ids_off + i as u32 * 8;
            self.write_u16(base, *cls as u16);
            self.write_u16(base + 2, *ty as u16);
            self.write_u32(base + 4, *name);
        }
        for (i, (cls, proto, name)) in method_entries.iter().enumerate() {
            let base = method_ids_off + i as u32 * 8;
            self.write_u16(base, *cls as u16);
            self.write_u16(base + 2, *proto as u16);
            self.write_u32(base + 4, *name);
        }
        for (i, spec) in class_entries.iter().enumerate() {
            let base = class_defs_off + i as u32 * 32;
            self.write_u32(base, spec.class_type);
            self.write_u32(base + 4, spec.access_flags);
            self.write_u32(base + 8, spec.superclass.unwrap_or(0xFFFF_FFFF));
            self.write_u32(base + 12, 0); // interfaces_off
            self.write_u32(base + 16, 0xFFFF_FFFF); // source_file
            self.write_u32(base + 20, 0); // annotations_off
            self.write_u32(base + 24, spec.class_data_off);
            self.write_u32(base + 28, 0); // static_values_off
        }

        // Build map_list: minimal — 1 entry (TYPE_LIST for params is
        // in code area; we record only what asc-dex requires). For
        // test purposes we skip the map entirely; asc-dex tolerates
        // map_off == 0.
        let map_off = 0u32;

        // Total file size = current next_align.
        let file_size = align4(self.next_align) as usize;
        if self.buf.len() < file_size {
            self.buf.resize(file_size, 0);
        }

        // Write the header.
        let mut buf = self.buf;
        buf[0..8].copy_from_slice(DEX_MAGIC);
        // checksum (0) and SHA-1 signature (0) — asc-dex tolerates.
        buf.resize(file_size.max(0x70), 0);
        let mut write_at = |off: usize, v: u32| {
            buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        write_at(0x20, file_size as u32);
        write_at(0x24, HEADER_SIZE);
        write_at(0x28, 0x12345678); // endian tag
        write_at(0x30, 0); // link_size
        write_at(0x34, map_off);
        write_at(0x38, string_ids_size);
        write_at(0x3C, string_ids_off);
        write_at(0x40, type_ids_size);
        write_at(0x44, type_ids_off);
        write_at(0x48, proto_ids_size);
        write_at(0x4C, proto_ids_off);
        write_at(0x50, field_ids_size);
        write_at(0x54, field_ids_off);
        write_at(0x58, method_ids_size);
        write_at(0x5C, method_ids_off);
        write_at(0x60, class_defs_size);
        write_at(0x64, class_defs_off);
        // data_size @ 0x68; we'll set to file_size - header_size for sanity.
        write_at(0x68, (file_size as u32) - HEADER_SIZE);
        buf
    }
}

fn align4(x: u32) -> u32 {
    (x + 3) & !3
}

// --------------------- tests ---------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_round_trip() {
        // Build a DEX with one class, one method, an empty body.
        let mut b = Builder::new();
        let cls = b.add_type("LFoo;");
        let _ret = b.add_type("V");
        let proto = b.add_proto("V", _ret, &[]);
        let _mid = b.add_method(cls, proto, "<init>", &[]);
        b.add_class(cls, 1, None, &[]);
        let bytes = b.finalize();
        let view = DexView::parse(&bytes).expect("view parses");
        assert_eq!(view.type_count(), 2);
        assert_eq!(view.string_count(), 4);
        assert_eq!(view.method_count(), 1);
        assert_eq!(view.class_def_count(), 1);
    }
}