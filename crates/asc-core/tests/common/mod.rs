//! Shared synthetic-DEX/APK builders for asc-core integration tests.
//!
//! `Dex` is the minimal DEX writer originally written for
//! `tests/paranoid.rs`: every pool is sorted and indices are looked up
//! by value. `write_apk` wraps entry buffers in a STORED APK.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;

use asc_dex::mutf8::from_utf16;

pub fn u(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

pub type Proto = (&'static str, Vec<&'static str>);
/// Method-id entry: owning class descriptor is an owned `String` so
/// tests can build descriptors at runtime.
pub type Member = (String, &'static str, Proto);

pub const OBJECT: &str = "Ljava/lang/Object;";
pub const STRING: &str = "Ljava/lang/String;";
pub const STRINGS: &str = "[Ljava/lang/String;";
pub const ACC_PUBLIC_STATIC: u32 = 0x0009;
pub const ACC_STATIC_CTOR: u32 = 0x10008;

fn shorty(p: &Proto) -> String {
    std::iter::once(p.0)
        .chain(p.1.iter().copied())
        .map(|t| if t.len() == 1 { t } else { "L" })
        .collect()
}

/// Minimal DEX writer: every pool is sorted, indices are looked up by value.
pub struct Dex {
    pub strings: Vec<Vec<u16>>,
    pub types: Vec<String>,
    pub protos: Vec<Proto>,
    pub fields: Vec<(&'static str, &'static str, &'static str)>,
    pub methods: Vec<Member>,
}

impl Dex {
    /// `seed_types` are always present in the type pool (superclasses,
    /// marker classes) even when no member references them.
    pub fn new(
        seed_types: &[&str],
        fields: Vec<(&'static str, &'static str, &'static str)>,
        methods: Vec<Member>,
        literals: &[Vec<u16>],
    ) -> Self {
        let mut types: BTreeSet<String> = seed_types.iter().map(|s| s.to_string()).collect();
        let mut strings: BTreeSet<Vec<u16>> = literals.iter().cloned().collect();
        let mut protos: Vec<Proto> = Vec::new();
        for (c, t, n) in &fields {
            types.insert(c.to_string());
            types.insert(t.to_string());
            strings.insert(u(n));
        }
        for (c, n, p) in &methods {
            types.insert(c.to_string());
            types.insert(p.0.to_string());
            types.extend(p.1.iter().map(|t| t.to_string()));
            strings.insert(u(n));
            strings.insert(u(&shorty(p)));
            if !protos.contains(p) {
                protos.push(p.clone());
            }
        }
        strings.extend(types.iter().map(|t| u(t)));
        Self {
            strings: strings.into_iter().collect(),
            types: types.into_iter().collect(),
            protos,
            fields,
            methods,
        }
    }
    pub fn string(&self, s: &[u16]) -> u32 {
        self.strings.iter().position(|x| x == s).unwrap() as u32
    }
    pub fn type_(&self, t: &str) -> u32 {
        self.types.iter().position(|x| x == t).unwrap() as u32
    }
    pub fn field(&self, name: &str) -> u16 {
        self.fields.iter().position(|f| f.2 == name).unwrap() as u16
    }
    pub fn method(&self, class: &str, name: &str) -> u16 {
        self.methods
            .iter()
            .position(|m| m.0 == class && m.1 == name)
            .unwrap() as u16
    }

    /// `classes`: (descriptor, static field names, [(method name, flags, regs, ins, insns)]).
    #[allow(clippy::type_complexity)]
    pub fn finish(
        &self,
        classes: &[(&str, Vec<&str>, Vec<(&str, u32, u16, u16, Vec<u16>)>)],
    ) -> Vec<u8> {
        let ids_len = 0x70
            + self.strings.len() * 4
            + self.types.len() * 4
            + self.protos.len() * 12
            + self.fields.len() * 8
            + self.methods.len() * 8
            + classes.len() * 32;
        let mut out = vec![0u8; ids_len];
        let mut ids = 0x70;
        let mut put = |out: &mut Vec<u8>, bytes: &[u8]| {
            out[ids..ids + bytes.len()].copy_from_slice(bytes);
            ids += bytes.len();
        };
        let uleb = |out: &mut Vec<u8>, mut v: u32| loop {
            let b = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        };
        let align = |out: &mut Vec<u8>| out.resize(out.len().next_multiple_of(4), 0);

        let header = [
            (0x38, self.strings.len()),
            (0x40, self.types.len()),
            (0x48, self.protos.len()),
            (0x50, self.fields.len()),
            (0x58, self.methods.len()),
            (0x60, classes.len()),
        ];
        let mut offs = 0x70;
        for (at, n) in header {
            out[at..at + 4].copy_from_slice(&(n as u32).to_le_bytes());
            out[at + 4..at + 8].copy_from_slice(&(offs as u32).to_le_bytes());
            offs += n * [4, 4, 12, 8, 8, 32][(at - 0x38) / 8];
        }

        for s in &self.strings {
            let off = out.len() as u32;
            uleb(&mut out, s.len() as u32);
            out.extend(from_utf16(s));
            out.push(0);
            put(&mut out, &off.to_le_bytes());
        }
        for t in &self.types {
            put(&mut out, &self.string(&u(t)).to_le_bytes());
        }
        for p in &self.protos {
            let params = if p.1.is_empty() {
                0
            } else {
                align(&mut out);
                let off = out.len() as u32;
                out.extend((p.1.len() as u32).to_le_bytes());
                for t in &p.1 {
                    out.extend((self.type_(t) as u16).to_le_bytes());
                }
                off
            };
            put(&mut out, &self.string(&u(&shorty(p))).to_le_bytes());
            put(&mut out, &self.type_(p.0).to_le_bytes());
            put(&mut out, &params.to_le_bytes());
        }
        for (c, t, n) in &self.fields {
            put(&mut out, &(self.type_(c) as u16).to_le_bytes());
            put(&mut out, &(self.type_(t) as u16).to_le_bytes());
            put(&mut out, &self.string(&u(n)).to_le_bytes());
        }
        for (c, n, p) in &self.methods {
            put(&mut out, &(self.type_(c) as u16).to_le_bytes());
            let proto = self.protos.iter().position(|q| q == p).unwrap() as u16;
            put(&mut out, &proto.to_le_bytes());
            put(&mut out, &self.string(&u(n)).to_le_bytes());
        }
        for (desc, sfields, methods) in classes {
            let mut code_offs = Vec::new();
            for (_, _, regs, ins, insns) in methods {
                align(&mut out);
                code_offs.push(out.len() as u32);
                for v in [*regs, *ins, 4, 0] {
                    out.extend(v.to_le_bytes());
                }
                out.extend(0u32.to_le_bytes());
                out.extend((insns.len() as u32).to_le_bytes());
                out.extend(insns.iter().flat_map(|w| w.to_le_bytes()));
            }
            let data_off = out.len() as u32;
            let mut sf: Vec<u16> = sfields.iter().map(|f| self.field(f)).collect();
            sf.sort();
            let mut dm: Vec<(u16, u32, u32)> = methods
                .iter()
                .zip(&code_offs)
                .map(|((n, flags, ..), off)| (self.method(desc, n), *flags, *off))
                .collect();
            dm.sort();
            for n in [sf.len(), 0, dm.len(), 0] {
                uleb(&mut out, n as u32);
            }
            let mut prev = 0;
            for f in sf {
                uleb(&mut out, (f - prev) as u32);
                uleb(&mut out, 0x1A); // private static final
                prev = f;
            }
            prev = 0;
            for (m, flags, off) in dm {
                uleb(&mut out, (m - prev) as u32);
                uleb(&mut out, flags);
                uleb(&mut out, off);
                prev = m;
            }
            for v in [
                self.type_(desc),
                1,
                self.type_(OBJECT),
                0,
                u32::MAX,
                0,
                data_off,
                0,
            ] {
                put(&mut out, &v.to_le_bytes());
            }
        }
        // asc-dex sizes class_data conservatively (8 bytes/entry), and
        // real DEX files always have map_list after it.
        out.resize(out.len() + 64, 0);
        let size = out.len() as u32;
        out[..8].copy_from_slice(b"dex\n035\0");
        out[0x20..0x24].copy_from_slice(&size.to_le_bytes());
        out[0x24..0x28].copy_from_slice(&0x70u32.to_le_bytes());
        out[0x28..0x2C].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        out[0x68..0x6C].copy_from_slice(&(size - ids_len as u32).to_le_bytes());
        out[0x6C..0x70].copy_from_slice(&(ids_len as u32).to_le_bytes());
        // Real adler32 over everything from signature-end to EOF,
        // written LAST so it covers every header field: droidsaw-dex
        // (used whole by `disasm`) verifies it, while asc-rebuild
        // (getclass) recomputes it anyway.
        let sum = adler2::adler32(&out[0x0C..]).unwrap_or(0);
        out[0x08..0x0C].copy_from_slice(&sum.to_le_bytes());
        out
    }
}

/// STORED APK with the given root entries, under the OS temp dir.
pub fn write_apk(tag: &str, entries: &[(&str, Vec<u8>)]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("asc_core_{tag}_{}.apk", std::process::id()));
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
    let opts =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in entries {
        zip.start_file(*name, opts).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap();
    path
}

/// A truncated DEX magic (parses as an error, not as a silent skip).
pub fn corrupt_dex() -> Vec<u8> {
    let mut b = b"dex\n035\0".to_vec();
    b.extend(std::iter::repeat(0u8).take(8));
    b
}
