//! Byte-level DEX builder for the seed corpus.
//!
//! Ported (duplicated, per repo convention) from
//! `crates/asc-decompile/tests/common/mod.rs` — only the pieces a
//! seed corpus needs: header, id pools, string_data, code_item,
//! class_data, encoded_array, map_list, adler32 + SHA-1. The test
//! module's `Ev` enum is kept because the call-site seed needs it;
//! its field support, encoded_value variants and the
//! `hide_post_o_map_entries` knob are not.
//!
//! Why it exists: `dex_minimal_header()` is a zeroed 0x70 header that
//! no parser accepts, so a mutation corpus built from it can only ever
//! exercise a DEX parser's *gate*. A target that has to reach a
//! renderer (e.g. `fuzz_disasm`) needs a seed that parses, so that
//! mutations land inside the pools and instruction stream instead of
//! at the magic/checksum check.

/// DEX version used by the seeds; 039 supports call sites and method
/// handles.
const VERSION: &str = "039";

// ── adler32 / sha1 ──────────────────────────────────────────────────

/// Adler-32 (RFC 1950) over `data`.
fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

/// SHA-1 (FIPS 180-4) digest of `data`.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 80];
    for block in msg.as_chunks::<64>().0 {
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let o = i * 4;
            *word = u32::from_be_bytes([block[o], block[o + 1], block[o + 2], block[o + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        for (slot, v) in h.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(v);
        }
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn p16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn p32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
const fn align4(x: usize) -> usize {
    (x + 3) & !3
}

// ── LEB128 ──────────────────────────────────────────────────────────

/// ULEB128 encoding of `v`.
fn uleb(v: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut v = v;
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// SLEB128 encoding of `v`.
fn sleb(v: i32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut v = v;
    loop {
        let byte = (v as u8) & 0x7F;
        v >>= 7;
        let done = (v == 0 && byte & 0x40 == 0) || (v == -1 && byte & 0x40 != 0);
        out.push(if done { byte } else { byte | 0x80 });
        if done {
            return out;
        }
    }
}

/// MUTF-8 encoding (DEX §3.3); the seed pools are ASCII.
fn mutf8(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for ch in s.chars() {
        let cp = ch as u32;
        if cp < 0x80 && cp != 0 {
            out.push(cp as u8);
        } else if cp < 0x800 {
            out.push(0xC0 | (cp >> 6) as u8);
            out.push(0x80 | (cp & 0x3F) as u8);
        } else {
            out.push(0xE0 | ((cp >> 12) & 0x0F) as u8);
            out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
            out.push(0x80 | (cp & 0x3F) as u8);
        }
    }
    out
}

// ── instruction encoders (dalvik instruction-formats table) ─────────

/// 11n — `const/4` (0x12), `return` (0x0f).
fn insn_11n(op: u8, a: u16, b: i8) -> Vec<u16> {
    vec![((b as u16 & 0x0F) << 12) | ((a & 0x0F) << 8) | u16::from(op)]
}

/// 21c — `const-method-type` (0xff) and friends.
fn insn_21c(op: u8, aa: u16, idx: u16) -> Vec<u16> {
    vec![((aa & 0xFF) << 8) | u16::from(op), idx]
}

/// 31t — `packed-switch` (0x2b), `sparse-switch` (0x2c),
/// `fill-array-data` (0x26).
fn insn_31t(op: u8, aa: u16, offset: i32) -> Vec<u16> {
    let w = (offset as u32).to_le_bytes();
    vec![
        ((aa & 0xFF) << 8) | u16::from(op),
        u16::from_le_bytes([w[0], w[1]]),
        u16::from_le_bytes([w[2], w[3]]),
    ]
}

/// 35c — `invoke-custom` (0xfa), ≤ 5 argument registers.
fn insn_35c(op: u8, arg_count: u16, idx: u16, regs: [u16; 5]) -> Vec<u16> {
    let [c, d, e, f, g] = regs;
    vec![
        ((arg_count & 0x0F) << 12) | ((g & 0x0F) << 8) | u16::from(op),
        idx,
        ((f & 0x0F) << 12) | ((e & 0x0F) << 8) | ((d & 0x0F) << 4) | (c & 0x0F),
    ]
}

/// 45cc — `invoke-polymorphic` (proto in code unit 3).
fn insn_45cc(op: u8, arg_count: u16, method: u16, proto: u16, regs: [u16; 5]) -> Vec<u16> {
    let [c, d, e, f, g] = regs;
    vec![
        ((arg_count & 0x0F) << 12) | ((g & 0x0F) << 8) | u16::from(op),
        method,
        ((f & 0x0F) << 12) | ((e & 0x0F) << 8) | ((d & 0x0F) << 4) | (c & 0x0F),
        proto,
    ]
}

// ── payload builders ────────────────────────────────────────────────

/// `packed-switch-payload` (ident 0x0100); the spec stores
/// `target_addr - switch_addr`.
fn packed_switch_payload(first_key: i32, targets: &[i32]) -> Vec<u16> {
    let mut out = vec![0x0100u16, targets.len() as u16];
    push_i32(&mut out, first_key);
    for t in targets {
        push_i32(&mut out, *t);
    }
    out
}

/// `sparse-switch-payload` (ident 0x0200): keys, then branch offsets.
fn sparse_switch_payload(keys: &[i32], targets: &[i32]) -> Vec<u16> {
    assert_eq!(keys.len(), targets.len());
    let mut out = vec![0x0200u16, keys.len() as u16];
    for k in keys {
        push_i32(&mut out, *k);
    }
    for t in targets {
        push_i32(&mut out, *t);
    }
    out
}

/// `array-payload` (ident 0x0300) over little-endian `data`.
fn array_payload(width: u16, data: &[u8]) -> Vec<u16> {
    assert!(matches!(width, 1 | 2 | 4 | 8), "element_width");
    assert_eq!(data.len() as u32 % u32::from(width), 0);
    let count = data.len() as u32 / u32::from(width);
    let mut out = vec![0x0300u16, width, count as u16, (count >> 16) as u16];
    for c in data.chunks(2) {
        out.push(if c.len() == 2 {
            u16::from_le_bytes([c[0], c[1]])
        } else {
            u16::from(c[0])
        });
    }
    out
}

fn push_i32(out: &mut Vec<u16>, v: i32) {
    let w = v.to_le_bytes();
    out.push(u16::from_le_bytes([w[0], w[1]]));
    out.push(u16::from_le_bytes([w[2], w[3]]));
}

// ── try / catch ─────────────────────────────────────────────────────

/// One `try_item` (8 bytes).
#[derive(Clone, Copy, Debug)]
struct TrySpec {
    start_addr: u32,
    insn_count: u16,
    /// Byte offset into the `encoded_catch_handler_list`.
    handler_off: u16,
}

/// One `encoded_catch_handler` (DEX §6.6.1).
#[derive(Clone, Debug)]
struct HandlerSpec {
    catches: Vec<(u16, u32)>,
    catch_all: Option<u32>,
}

impl HandlerSpec {
    fn bytes(&self) -> Vec<u8> {
        let size = if self.catch_all.is_some() {
            -(self.catches.len() as i32)
        } else {
            self.catches.len() as i32
        };
        let mut out = sleb(size);
        for (type_idx, addr) in &self.catches {
            out.extend(uleb(u32::from(*type_idx)));
            out.extend(uleb(*addr));
        }
        if let Some(addr) = self.catch_all {
            out.extend(uleb(addr));
        }
        out
    }
}

// ── DEX spec model ──────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Method {
    /// `method_ids` index.
    name: u32,
    flags: u16,
    code: Option<Code>,
}

#[derive(Clone, Debug)]
struct Code {
    registers: u16,
    ins: u16,
    outs: u16,
    units: Vec<u16>,
    tries: Vec<TrySpec>,
    handlers: Vec<HandlerSpec>,
}

impl Code {
    fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.registers.to_le_bytes());
        out.extend_from_slice(&self.ins.to_le_bytes());
        out.extend_from_slice(&self.outs.to_le_bytes());
        out.extend_from_slice(&(self.tries.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // debug_info_off
        out.extend_from_slice(&(self.units.len() as u32).to_le_bytes());
        for u in &self.units {
            out.extend_from_slice(&u.to_le_bytes());
        }
        if self.tries.is_empty() {
            return out;
        }
        if !self.units.len().is_multiple_of(2) {
            out.extend_from_slice(&[0, 0]); // 4-byte alignment padding
        }
        for t in &self.tries {
            out.extend_from_slice(&t.start_addr.to_le_bytes());
            out.extend_from_slice(&t.insn_count.to_le_bytes());
            out.extend_from_slice(&t.handler_off.to_le_bytes());
        }
        out.extend(uleb(self.handlers.len() as u32));
        for h in &self.handlers {
            out.extend(h.bytes());
        }
        out
    }
}

#[derive(Clone, Debug)]
struct ClassSpec {
    flags: u32,
    class_idx: u32,
    superclass: Option<u32>,
    interfaces: Vec<u32>,
    direct_methods: Vec<Method>,
    virtual_methods: Vec<Method>,
}

#[derive(Clone, Copy, Debug)]
struct MethodId {
    class_idx: u16,
    proto_idx: u16,
    name_idx: u32,
}

#[derive(Clone, Debug)]
struct ProtoSpec {
    shorty: u32,
    ret: u32,
    params: Vec<u32>,
}

#[derive(Clone, Copy, Debug)]
struct MethodHandle {
    /// 0..=8 per DEX `method_handle_type_codes`; 4 = invoke-static.
    kind: u16,
    /// `method_ids` index for kinds 4..=8.
    member: u16,
}

/// One `encoded_value` (DEX §6.3) in the call-site array.
#[derive(Clone, Copy, Debug)]
enum Ev {
    /// VALUE_INT (0x04), minimal width.
    Int(i32),
    /// VALUE_STRING (0x17), minimal width.
    Str(u32),
    /// VALUE_METHOD_TYPE (0x15).
    MethodType(u32),
    /// VALUE_METHOD_HANDLE (0x16).
    MethodHandle(u32),
}

impl Ev {
    fn bytes(&self) -> Vec<u8> {
        let (value_type, v): (u8, u32) = match self {
            Self::Int(v) => (0x04, *v as u32),
            Self::Str(v) => (0x17, *v),
            Self::MethodType(v) => (0x15, *v),
            Self::MethodHandle(v) => (0x16, *v),
        };
        let raw = v.to_le_bytes();
        let len = raw.iter().rposition(|&b| b != 0).map_or(1, |i| i + 1);
        let mut out = vec![((len - 1) as u8) << 5 | value_type];
        out.extend_from_slice(&raw[..len]);
        out
    }
}

/// `encoded_array_item` body (ULEB128 count + values).
fn encoded_array(values: &[Ev]) -> Vec<u8> {
    let mut out = uleb(values.len() as u32);
    for v in values {
        out.extend(v.bytes());
    }
    out
}

// =====================================================================
// Assembler
// =====================================================================

/// The whole file, before assembly.
#[derive(Default, Clone, Debug)]
#[allow(
    private_interfaces,
    reason = "the pool types are only ever built by this module's own `dex_with_switch_try_array`"
)]
pub struct DexSpec {
    pub strings: Vec<String>,
    pub types: Vec<u32>,
    pub protos: Vec<ProtoSpec>,
    pub methods: Vec<MethodId>,
    pub classes: Vec<ClassSpec>,
    pub handles: Vec<MethodHandle>,
    /// `call_site_ids` entries: each is one `encoded_array_item` body.
    pub call_sites: Vec<Vec<u8>>,
}

impl DexSpec {
    /// `type_ids` index of `descriptor`, appended when absent.
    fn ty(&mut self, descriptor: &str) -> u32 {
        let s = self.str(descriptor);
        if let Some(i) = self.types.iter().position(|&x| x == s) {
            return i as u32;
        }
        self.types.push(s);
        self.types.len() as u32 - 1
    }

    /// `string_ids` index of `s`, appended when absent. The pool is
    /// not re-sorted: index stability is what the seed needs, and the
    /// parser only records ordering violations.
    fn str(&mut self, s: &str) -> u32 {
        if let Some(i) = self.strings.iter().position(|x| x == s) {
            return i as u32;
        }
        self.strings.push(s.to_string());
        self.strings.len() as u32 - 1
    }

    /// `proto_ids` index of `(shorty, ret, params)`, appended when absent.
    fn proto(&mut self, shorty: &str, ret: u32, params: &[u32]) -> u32 {
        let shorty = self.str(shorty);
        if let Some(i) = self
            .protos
            .iter()
            .position(|p| p.shorty == shorty && p.ret == ret && p.params == params)
        {
            return i as u32;
        }
        self.protos.push(ProtoSpec {
            shorty,
            ret,
            params: params.to_vec(),
        });
        self.protos.len() as u32 - 1
    }

    /// Append a `method_ids` row, returning its index.
    fn method(&mut self, class_idx: u32, proto_idx: u32, name: &str) -> u32 {
        let name_idx = self.str(name);
        self.methods.push(MethodId {
            class_idx: class_idx as u16,
            proto_idx: proto_idx as u16,
            name_idx,
        });
        self.methods.len() as u32 - 1
    }

    /// Assemble the DEX bytes. SHA-1 is written before adler32
    /// because the signature bytes live inside the adler32 range.
    pub fn build(&self) -> Vec<u8> {
        let mut o = 0x70usize;
        let string_ids_off = o;
        o += 4 * self.strings.len();
        let type_ids_off = o;
        o += 4 * self.types.len();
        let proto_ids_off = o;
        o += 12 * self.protos.len();
        let field_ids_off = o; // no fields, but the header wants an offset
        let method_ids_off = o;
        o += 8 * self.methods.len();
        let class_defs_off = o;
        o += 32 * self.classes.len();
        let call_site_ids_off = o;
        o += 4 * self.call_sites.len();
        let method_handles_off = o;
        o += 8 * self.handles.len();
        let data_off = align4(o);

        // Data section. `buf` index 0 is absolute offset `data_off`,
        // which is 4-aligned, so `align4(len)` == aligning the
        // absolute offset.
        let mut d = Data {
            buf: vec![0u8; data_off - o],
            base: data_off,
        };

        // type_list items, in the order the replay below expects.
        let mut type_lists: Vec<(u32, Vec<u16>)> = Vec::new();
        for p in &self.protos {
            if !p.params.is_empty() {
                d.align();
                let at = d.off();
                type_lists.push((at, p.params.iter().map(|t| *t as u16).collect()));
                d.u32(p.params.len() as u32);
                for t in p.params.iter() {
                    d.u16(*t as u16);
                }
            }
        }
        for c in &self.classes {
            if !c.interfaces.is_empty() {
                d.align();
                let at = d.off();
                type_lists.push((at, c.interfaces.iter().map(|t| *t as u16).collect()));
                d.u32(c.interfaces.len() as u32);
                for t in &c.interfaces {
                    d.u16(*t as u16);
                }
            }
        }

        // string_data items.
        let mut string_data_offs = Vec::with_capacity(self.strings.len());
        for s in &self.strings {
            d.align();
            string_data_offs.push(d.off());
            d.raw(&uleb(s.chars().map(char::len_utf16).sum::<usize>() as u32));
            d.raw(&mutf8(s));
            d.u8(0);
        }

        // code_items first, then class_data: the class_data entry
        // carries the code offsets, so the code items must already be
        // placed. Section order inside `data` is free.
        let mut class_data_offs = Vec::with_capacity(self.classes.len());
        for c in &self.classes {
            let mut offs: Vec<u32> = Vec::new();
            for m in c.direct_methods.iter().chain(c.virtual_methods.iter()) {
                let off = match &m.code {
                    Some(code) => {
                        d.align();
                        let at = d.off();
                        d.raw(&code.body());
                        at
                    }
                    None => 0,
                };
                offs.push(off);
            }

            d.align();
            class_data_offs.push(d.off());
            let mut cd: Vec<u8> = Vec::new();
            cd.extend(uleb(0)); // static_fields_size
            cd.extend(uleb(0)); // instance_fields_size
            cd.extend(uleb(c.direct_methods.len() as u32));
            cd.extend(uleb(c.virtual_methods.len() as u32));
            let mut next = 0usize;
            for list in [&c.direct_methods, &c.virtual_methods] {
                let mut acc = 0u32;
                for (i, m) in list.iter().enumerate() {
                    assert!(
                        m.name >= acc,
                        "class_data method_idx_diff must be non-decreasing"
                    );
                    cd.extend(uleb(m.name - acc));
                    cd.extend(uleb(u32::from(m.flags)));
                    cd.extend(uleb(offs[next + i]));
                    acc = m.name;
                }
                next += list.len();
            }
            d.raw(&cd);
        }

        // encoded_array items (call sites first).
        let mut call_site_arrays = Vec::with_capacity(self.call_sites.len());
        for a in &self.call_sites {
            d.align();
            call_site_arrays.push(d.off());
            d.raw(a);
        }

        d.align();
        let map_off = d.off() as usize;
        let entries = self.map_entries();
        let file_size = map_off + 4 + entries.len() * 12;
        assert_eq!(file_size % 4, 0, "file_size must be 4-aligned");

        let mut b = vec![0u8; file_size];
        b[data_off..data_off + d.buf.len()].copy_from_slice(&d.buf);

        // header
        b[..8].copy_from_slice(format!("dex\n{VERSION}\0").as_bytes());
        p32(&mut b, 0x20, file_size as u32);
        p32(&mut b, 0x24, 0x70);
        p32(&mut b, 0x28, 0x1234_5678);
        p32(&mut b, 0x34, map_off as u32);
        p32(&mut b, 0x38, self.strings.len() as u32);
        p32(&mut b, 0x3C, string_ids_off as u32);
        p32(&mut b, 0x40, self.types.len() as u32);
        p32(&mut b, 0x44, type_ids_off as u32);
        p32(&mut b, 0x48, self.protos.len() as u32);
        p32(&mut b, 0x4C, proto_ids_off as u32);
        p32(&mut b, 0x50, 0); // field_ids_size
        p32(&mut b, 0x54, field_ids_off as u32);
        p32(&mut b, 0x58, self.methods.len() as u32);
        p32(&mut b, 0x5C, method_ids_off as u32);
        p32(&mut b, 0x60, self.classes.len() as u32);
        p32(&mut b, 0x64, class_defs_off as u32);
        p32(&mut b, 0x68, (file_size - data_off) as u32);
        p32(&mut b, 0x6C, data_off as u32);

        // string_ids / type_ids
        for (i, o) in string_data_offs.iter().enumerate() {
            p32(&mut b, string_ids_off + i * 4, *o);
        }
        for (i, t) in self.types.iter().enumerate() {
            p32(&mut b, type_ids_off + i * 4, *t);
        }

        // proto_ids (consume type_lists in order, skipping empties)
        let mut ti = 0usize;
        for (i, p) in self.protos.iter().enumerate() {
            let base = proto_ids_off + i * 12;
            p32(&mut b, base, p.shorty);
            p32(&mut b, base + 4, p.ret);
            if p.params.is_empty() {
                p32(&mut b, base + 8, 0);
            } else {
                p32(&mut b, base + 8, type_lists[ti].0);
                ti += 1;
            }
        }

        for (i, m) in self.methods.iter().enumerate() {
            let base = method_ids_off + i * 8;
            p16(&mut b, base, m.class_idx);
            p16(&mut b, base + 2, m.proto_idx);
            p32(&mut b, base + 4, m.name_idx);
        }

        // class_defs
        for (i, c) in self.classes.iter().enumerate() {
            let base = class_defs_off + i * 32;
            p32(&mut b, base, c.class_idx);
            p32(&mut b, base + 4, c.flags);
            p32(&mut b, base + 8, c.superclass.unwrap_or(0xFFFF_FFFF));
            if c.interfaces.is_empty() {
                p32(&mut b, base + 12, 0);
            } else {
                p32(&mut b, base + 12, type_lists[ti].0);
                ti += 1;
            }
            p32(&mut b, base + 16, 0xFFFF_FFFF); // source_file_idx
            p32(&mut b, base + 20, 0); // annotations_off
            p32(&mut b, base + 24, class_data_offs[i]);
            p32(&mut b, base + 28, 0); // static_values_off
        }

        for (i, a) in call_site_arrays.iter().enumerate() {
            p32(&mut b, call_site_ids_off + i * 4, *a);
        }
        for (i, h) in self.handles.iter().enumerate() {
            let base = method_handles_off + i * 8;
            p16(&mut b, base, h.kind);
            p16(&mut b, base + 2, 0);
            p32(&mut b, base + 4, u32::from(h.member));
        }

        // map_list
        let mut mo = map_off;
        p32(&mut b, mo, entries.len() as u32);
        mo += 4;
        for (ty, size, offset) in entries {
            p16(&mut b, mo, ty);
            p16(&mut b, mo + 2, 0);
            p32(&mut b, mo + 4, size);
            p32(&mut b, mo + 8, offset);
            mo += 12;
        }
        assert_eq!(mo, file_size);

        let sig = sha1(&b[0x20..file_size]);
        b[0x0C..0x20].copy_from_slice(&sig);
        let adler = adler32(&b[0x0C..file_size]);
        p32(&mut b, 0x08, adler);
        b
    }

    /// `map_list` rows. The variable-extent data sections
    /// (class_data / code_item / string_data / encoded_array) are
    /// declared with size 0: the parser reads only the call-site and
    /// method-handle rows, both of which live in the id sections.
    fn map_entries(&self) -> Vec<(u16, u32, u32)> {
        let mut o = 0x70usize;
        let string_ids_off = o;
        o += 4 * self.strings.len();
        let type_ids_off = o;
        o += 4 * self.types.len();
        let proto_ids_off = o;
        o += 12 * self.protos.len();
        // No field_ids rows: `field_ids_size` is 0.
        let method_ids_off = o;
        o += 8 * self.methods.len();
        let class_defs_off = o;
        o += 32 * self.classes.len();
        let call_site_ids_off = o;
        o += 4 * self.call_sites.len();
        let method_handles_off = o;
        o += 8 * self.handles.len();
        let _ = o;

        let mut e: Vec<(u16, u32, u32)> = vec![
            (0x0000, 1, 0),
            (0x0001, self.strings.len() as u32, string_ids_off as u32),
            (0x0002, self.types.len() as u32, type_ids_off as u32),
            (0x0003, self.protos.len() as u32, proto_ids_off as u32),
            (0x0005, self.methods.len() as u32, method_ids_off as u32),
            (0x0006, self.classes.len() as u32, class_defs_off as u32),
        ];
        if !self.call_sites.is_empty() {
            e.push((
                0x0007,
                self.call_sites.len() as u32,
                call_site_ids_off as u32,
            ));
        }
        if !self.handles.is_empty() {
            e.push((0x0008, self.handles.len() as u32, method_handles_off as u32));
        }
        if !self.call_sites.is_empty() {
            // TYPE_ENCODED_ARRAY_ITEM; ignored by the parser, but a
            // real DEX declares it and the row keeps the map
            // self-consistent.
            e.push((0x2003, self.call_sites.len() as u32, 0));
        }
        e.push((0x1000, 1, 0));
        e
    }
}

struct Data {
    buf: Vec<u8>,
    base: usize,
}

impl Data {
    fn off(&self) -> u32 {
        (self.base + self.buf.len()) as u32
    }
    /// Pad to a 4-byte boundary. `base` is 4-aligned by construction,
    /// so aligning the buffer length aligns the absolute offset.
    fn align(&mut self) -> usize {
        while !(self.base + self.buf.len()).is_multiple_of(4) {
            self.buf.push(0);
        }
        self.buf.len()
    }
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn raw(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
}

// =====================================================================
// The seed itself
// =====================================================================

/// DEX 039, one class `Lfoo/Bar;` with two direct methods whose bodies
/// between them cover every payload form the smali renderer lays out.
///
/// `a(I)I` — invocation plumbing, with a try/typed-catch/catch-all:
///
/// ```text
/// 0   const/4 v0, #0
/// 1   invoke-custom {v0}, call_site_0
/// 4   invoke-polymorphic {v0}, Lfoo/Bar;->poly()V, ()V
/// 7   const-method-handle v0, invoke-static Lfoo/Bar;-><clinit>()V
/// 9   return v0
/// ```
///
/// `b()V` — the switch and array payloads, one adjacent payload per
/// branch so each `31t` is literally followed by its own data:
///
/// ```text
/// 0   packed-switch v0            -> 3   (first_key -2, two targets back to addr 0)
/// 3   fill-array-data v1          -> 6   (width 4, 2 elements)
/// 6   fill-array-data v2          -> 11  (width 1, 5 elements)
/// 11  sparse-switch v0           -> 16  (keys -1 / 0x7fffffff)
/// 16  fill-array-data v3          -> 22  (width 2, 3 elements)
/// 22  fill-array-data v4          -> 27  (width 8, 2 elements)
/// 27  return-void
/// ```
///
/// The first class_def is always `Lfoo/Bar;`, so the target's
/// `Lfoo/Bar;` probe resolves; `Some("a")` selects method `a`.
pub fn dex_with_switch_try_array() -> Vec<u8> {
    let mut d = DexSpec::default();
    // Insert order is the pool order: droidsaw flags an unsorted
    // string_ids / proto_ids row (a recorded `parse_error`, but one
    // that would otherwise pollute every mutation's diagnostics).
    let class_idx = d.ty("Lfoo/Bar;");
    let _t_throwable = d.ty("Ljava/lang/Throwable;");
    let t_int = d.ty("I");
    // Appended after Throwable so the Throwable stays at index 1
    // (the try handler catches `(1, 1)` below).
    let t_void = d.ty("V");
    let p1 = d.proto("I", t_int, &[t_int]);
    let p0 = d.proto("V", t_void, &[]);

    // Call site 0 = [bootstrap handle, name string, method type, one
    // extra int argument].
    let boot = d.method(class_idx, p0, "<clinit>");
    let poly = d.method(class_idx, p0, "poly");
    let m_a = d.method(class_idx, p1, "a");
    let m_b = d.method(class_idx, p0, "b");
    let sam = d.str("apply");
    d.handles.push(MethodHandle {
        kind: 4, // invoke-static
        member: boot as u16,
    });
    d.call_sites.push(encoded_array(&[
        Ev::MethodHandle(0),
        Ev::Str(sam),
        Ev::MethodType(p1),
        Ev::Int(7),
    ]));

    let code_a = Code {
        registers: 4,
        ins: 0,
        outs: 1,
        units: [
            insn_11n(0x12, 0, 0), // 0 const/4 v0, #0
            // C = 1 register, matching `arg_count = 1`: a non-static
            // invoke with an empty register list is a code-item
            // invariant violation the parser rejects.
            insn_35c(0xfc, 1, 0, [1, 0, 0, 0, 0]), // 1 invoke-custom {v0}, call_site_0
            insn_45cc(0xfa, 1, poly as u16, p0 as u16, [1, 0, 0, 0, 0]), // 4 invoke-polymorphic
            insn_21c(0xfe, 0, 0),                  // 7 const-method-handle v0, mh 0
            insn_11n(0x0f, 0, 0),                  // 9 return v0
        ]
        .concat(),
        tries: Vec::new(),
        handlers: Vec::new(),
    };

    // `b()V` — every 31t immediately followed by its own payload,
    // assembled with TRACKED pcs: the payload offsets written below
    // point at the real payload positions (an earlier hand-counted
    // layout ignored payload sizes and left the 31t offsets pointing
    // into the middle of other payloads — the disasm renderer rejects
    // that as UnalignedTableDexPc). Payloads are padded to even code
    // units (4-byte alignment), another renderer invariant.
    fn emit_31t(
        units: &mut Vec<u16>,
        rel: &mut Vec<(usize, i32)>,
        op: u8,
        reg: u16,
        payload: Vec<u16>,
    ) {
        let insn_pc = units.len();
        units.extend(insn_31t(op, reg, 0));
        if units.len() % 2 == 1 {
            units.push(0x0000); // nop pad: payload must be 4-byte aligned
        }
        let payload_pc = units.len();
        units.extend(payload);
        rel.push((insn_pc, (payload_pc - insn_pc) as i32));
    }

    let mut units: Vec<u16> = Vec::new();
    let mut rel: Vec<(usize, i32)> = Vec::new();
    units.extend(insn_11n(0x12, 1, 1)); // const/4 v1, #1
    let try1_start = units.len() as u32; // packed-switch
    emit_31t(
        &mut units,
        &mut rel,
        0x2b,
        0,
        packed_switch_payload(-2, &[0, 0]),
    );
    emit_31t(
        &mut units,
        &mut rel,
        0x26,
        1,
        array_payload(4, &1u32.to_le_bytes().repeat(2)),
    );
    emit_31t(
        &mut units,
        &mut rel,
        0x26,
        2,
        array_payload(1, &[0x01, 0x7f, 0x80]),
    );
    let try2_start = units.len() as u32; // sparse-switch
    emit_31t(
        &mut units,
        &mut rel,
        0x2c,
        0,
        sparse_switch_payload(&[-1, 0x7fff_ffff], &[0, 0]),
    );
    emit_31t(
        &mut units,
        &mut rel,
        0x26,
        3,
        array_payload(2, &0x7fffu16.to_le_bytes().repeat(3)),
    );
    emit_31t(
        &mut units,
        &mut rel,
        0x26,
        4,
        array_payload(8, &0x1000_0000_8000_0000u64.to_le_bytes().repeat(2)),
    );
    let return_pc = units.len() as u32;
    units.push(0x000e); // return-void
    for (pc, r) in &rel {
        let w = (*r as u32).to_le_bytes();
        units[pc + 1] = u16::from_le_bytes([w[0], w[1]]);
        units[pc + 2] = u16::from_le_bytes([w[2], w[3]]);
    }

    let mut code_b = Code {
        registers: 6,
        ins: 0,
        outs: 0,
        units,
        // Two tries, each pointing at one handler: the first is
        // typed (on the packed-switch), the second is a bare
        // catch-all covering the rest of the body. Both start and
        // end addresses are instruction starts — a try end that is
        // not one is rejected. Handler offsets are relative to the
        // `encoded_catch_handler_list` start, so the second includes
        // the `handlers_size` ULEB and handler 0's bytes.
        tries: vec![TrySpec {
            start_addr: try1_start,
            insn_count: (try2_start - try1_start) as u16,
            handler_off: 1, // right after the handlers_size ULEB
        }],
        handlers: vec![
            HandlerSpec {
                catches: vec![(1, 1)],
                catch_all: None,
            },
            HandlerSpec {
                catches: Vec::new(),
                catch_all: Some(return_pc),
            },
        ],
    };
    // One try cannot name two handlers, so the catch-all gets its own
    // non-overlapping entry.
    code_b.tries.push(TrySpec {
        start_addr: try2_start,
        insn_count: (return_pc - try2_start) as u16,
        handler_off: 4,
    });

    d.classes.push(ClassSpec {
        flags: 0x0001, // public
        class_idx,
        superclass: None,
        interfaces: Vec::new(),
        // Both methods are DIRECT: droidsaw re-bases a *virtual*
        // method's `code_off` to 0, and the seed must keep the raw
        // offsets the assembler wrote.
        direct_methods: vec![
            Method {
                name: m_a,
                // public static: a *non-static* invoke with a single
                // register makes the register file fail the code-item
                // invariants (`0x01 < registers_size` and the
                // zero-argument non-static invoke check).
                flags: 0x0009, // public static
                code: Some(code_a),
            },
            Method {
                name: m_b,
                flags: 0x0008, // static
                code: Some(code_b),
            },
        ],
        virtual_methods: Vec::new(),
    });
    d.build()
}

/// Set the two literal units of the `31t` that starts at `units[0]`
/// (opcode, low, high) so it branches `rel_units` code units past
/// itself. The DEX spec stores `target_addr - switch_addr`, i.e. the
/// offset is in code-UNIT units.
fn set_rel32(units: &mut [u16], rel_units: usize) {
    let w = (rel_units as i32).to_le_bytes();
    units[1] = u16::from_le_bytes([w[0], w[1]]);
    units[2] = u16::from_le_bytes([w[2], w[3]]);
}
