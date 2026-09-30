//! Programmable byte-level DEX builder for the `disasm` gate.
//!
//! Every DEX used by `tests/disasm_synthetic.rs` is assembled here from
//! first principles (header, id pools, class_data, code_item, map_list,
//! call_site_ids / method_handles / encoded_array_items), so each
//! expectation in the gate can be derived from the bytes rather than
//! from the tool's own output. Per repo convention the builder is
//! duplicated per crate; this one exists only for `asc-decompile`.
//!
//! # What droidsaw-dex enforces at parse time
//!
//! `DexFile::parse_inner` (`parser/mod.rs`) runs, in order:
//!
//! 1. `DexHeader::parse` — magic `dex\n` + version in
//!    035/037/038/039/040/041, `magic[7] == 0`, `header_size == 0x70`,
//!    `endian_tag == 0x12345678`.
//! 2. `verify_checksum` — adler32 over `bytes[0x0C .. file_size]` must
//!    equal the stored `bytes[0x08..0x0C]`. SHA-1 is *not* enforced
//!    (only recorded in `input_checksums_canonical`) but the builder
//!    writes the canonical value anyway.
//! 3. `check_id_section_overlap` — the six id sections must not alias.
//! 4. id-pool indices in range: `type_id.descriptor_idx < strings`,
//!    `proto.shorty_idx < strings`, `proto.return_type_idx < types`,
//!    `class_def.class_idx < types`, and (via `method_summary`)
//!    `method.class_idx < types` / `method.proto_idx < protos`.
//! 5. `access_flags::validate` per scope (class `0x761F`, field
//!    `0x50DF`, method `0x31DFF`).
//!
//! `map_list` is read for `map_entries`, `method_handles`
//! (TYPE 0x0008) and `call_site_ids` (TYPE 0x0007) only; the other map
//! entries keep the file spec-shaped. The gate's self-check asserts
//! droidsaw sees the expected pool contents.
//!
//! `class_data` is read through `DexFile::list_methods` (static helpers:
//! `api.rs`), i.e. `field_idx_diff` / `method_idx_diff` are
//! *cumulative*, encoded as ULEB128, and `code_off == 0` marks
//! abstract/native methods.
//!
//! # Instruction helpers
//!
//! [`Code::units`] takes raw code units. The encoders below
//! ([`insn_11n`], [`insn_21h`], [`insn_21c`], [`insn_22t`],
//! [`insn_22s`], [`insn_31t`], [`insn_35c`], [`insn_3rc`],
//! [`insn_45cc`], [`insn_4rcc`], [`insn_51l`]) emit exactly the bytes the
//! dalvik-bytecode instruction-formats table prescribes, so a test body
//! reads like the spec:
//!
//! ```text
//! 11n  B|A|op          21c  AA|op BBBB        22s  2|op A|B CCCC
//! 21h  AA|op BBBB     31t  AA|op BBBBBBBB    35c  A|G|op BBBB F|E|D|C
//! 3rc  AA|op BBBB CCCC                   45cc  A|G|op BBBB F|E|D|C HHHH
//! 4rcc AA|op BBBB CCCC HHHH
//! ```

#![allow(dead_code)]

const fn align4(x: usize) -> usize {
    (x + 3) & !3
}

// ── adler32 / sha1 ───────────────────────────────────────────────────
//
// `asc-decompile` depends on neither crate, so both hashes the header
// needs are implemented here (15 + 45 lines) rather than adding a
// dev-dependency for two self-checks.

/// Adler-32 (RFC 1950) over `data`.
pub fn adler32(data: &[u8]) -> u32 {
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
pub fn sha1(data: &[u8]) -> [u8; 20] {
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
    for block in msg.chunks_exact(64) {
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let o = i * 4;
            *word = u32::from_be_bytes([block[o], block[o + 1], block[o + 2], block[o + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
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
                .wrapping_add(wi);
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

// ── LEB128 ───────────────────────────────────────────────────────────

/// ULEB128 encoding of `v`.
pub fn uleb(v: u32) -> Vec<u8> {
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
pub fn sleb(v: i32) -> Vec<u8> {
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

// ── instruction encoders ─────────────────────────────────────────────

/// 11n — `B|A|op` (1 code unit). `const/4` = 0x12.
pub fn insn_11n(op: u8, a: u16, b: i8) -> Vec<u16> {
    vec![((b as u16 & 0x0F) << 12) | ((a & 0x0F) << 8) | u16::from(op)]
}

/// 21h — `AA|op BBBB` (2 code units). `const/high16` = 0x15,
/// `const-wide/high16` = 0x19; the literal is `BBBB0000` resp.
/// `BBBB` in the top half of a 64-bit value.
pub fn insn_21h(op: u8, aa: u16, bbbb: u16) -> Vec<u16> {
    vec![((aa & 0xFF) << 8) | u16::from(op), bbbb]
}

/// 51l — `AA|op` + 4 literal code units (5 code units). `const-wide` = 0x18.
pub fn insn_51l(op: u8, aa: u16, lit: i64) -> Vec<u16> {
    let w = lit.to_le_bytes();
    let mut out = vec![((aa & 0xFF) << 8) | u16::from(op)];
    out.extend(w.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])));
    out
}

/// 21c — `AA|op BBBB` (2 code units), a 16-bit pool index.
/// `const-string` = 0x1a, `const-method-handle` = 0xfe,
/// `const-method-type` = 0xff.
pub fn insn_21c(op: u8, aa: u16, idx: u16) -> Vec<u16> {
    vec![((aa & 0xFF) << 8) | u16::from(op), idx]
}

/// 31t — `AA|op BBBBBBBB` (3 code units), a 32-bit branch offset.
/// `packed-switch` = 0x2b, `sparse-switch` = 0x2c, `fill-array-data` = 0x26.
pub fn insn_31t(op: u8, aa: u16, offset: i32) -> Vec<u16> {
    let w = (offset as u32).to_le_bytes();
    vec![
        ((aa & 0xFF) << 8) | u16::from(op),
        u16::from_le_bytes([w[0], w[1]]),
        u16::from_le_bytes([w[2], w[3]]),
    ]
}

/// 22t — `A|B|op CCCC` (2 code units), an 8-bit branch offset.
pub fn insn_22t(op: u8, a: u16, b: u16, cccc: i8) -> Vec<u16> {
    vec![
        ((b & 0x0F) << 12) | ((a & 0x0F) << 8) | u16::from(op),
        cccc as i16 as u16,
    ]
}

/// 22s — `A|B|op CCCC` (2 code units), a 16-bit literal.
pub fn insn_22s(op: u8, a: u16, b: u16, cccc: i16) -> Vec<u16> {
    vec![
        ((b & 0x0F) << 12) | ((a & 0x0F) << 8) | u16::from(op),
        cccc as u16,
    ]
}

/// 35c — `A|G|op BBBB F|E|D|C` (3 code units), ≤ 5 argument registers.
pub fn insn_35c(op: u8, arg_count: u16, idx: u16, regs: [u16; 5]) -> Vec<u16> {
    let [c, d, e, f, g] = regs;
    vec![
        ((arg_count & 0x0F) << 12) | ((g & 0x0F) << 8) | u16::from(op),
        idx,
        ((f & 0x0F) << 12) | ((e & 0x0F) << 8) | ((d & 0x0F) << 4) | (c & 0x0F),
    ]
}

/// 3rc — `AA|op BBBB CCCC` (3 code units), `AA` argument registers
/// starting at `CCCC`.
pub fn insn_3rc(op: u8, arg_count: u16, idx: u16, start_reg: u16) -> Vec<u16> {
    vec![((arg_count & 0xFF) << 8) | u16::from(op), idx, start_reg]
}

/// 45cc — `A|G|op BBBB F|E|D|C HHHH` (4 code units): method ref + proto ref.
pub fn insn_45cc(op: u8, arg_count: u16, method: u16, proto: u16, regs: [u16; 5]) -> Vec<u16> {
    let [c, d, e, f, g] = regs;
    vec![
        ((arg_count & 0x0F) << 12) | ((g & 0x0F) << 8) | u16::from(op),
        method,
        ((f & 0x0F) << 12) | ((e & 0x0F) << 8) | ((d & 0x0F) << 4) | (c & 0x0F),
        proto,
    ]
}

/// 4rcc — `AA|op BBBB CCCC HHHH` (4 code units): method ref + proto ref
/// over a register range.
pub fn insn_4rcc(op: u8, arg_count: u16, method: u16, proto: u16, start_reg: u16) -> Vec<u16> {
    vec![
        ((arg_count & 0xFF) << 8) | u16::from(op),
        method,
        start_reg,
        proto,
    ]
}

// ── payload builders ─────────────────────────────────────────────────

/// `packed-switch-payload` (ident 0x0100). `first_key` is the first
/// case key; `targets` are branch offsets **relative to the switch
/// instruction** (the spec stores `target_addr - switch_addr`).
pub fn packed_switch_payload(first_key: i32, targets: &[i32]) -> Vec<u16> {
    let mut out = vec![0x0100u16, targets.len() as u16];
    push_i32(&mut out, first_key);
    for t in targets {
        push_i32(&mut out, *t);
    }
    out
}

/// `sparse-switch-payload` (ident 0x0200): keys, then branch offsets.
pub fn sparse_switch_payload(keys: &[i32], targets: &[i32]) -> Vec<u16> {
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

/// `array-payload` (ident 0x0300): `width` bytes per element over
/// `data` (little-endian, already concatenated).
pub fn array_payload(width: u16, data: &[u8]) -> Vec<u16> {
    assert!(
        matches!(width, 1 | 2 | 4 | 8),
        "element_width must be 1/2/4/8"
    );
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

// ── try / catch ──────────────────────────────────────────────────────

/// One `try_item` (8 bytes).
#[derive(Clone, Copy, Debug)]
pub struct TrySpec {
    /// Code-unit address of the first covered instruction.
    pub start_addr: u32,
    pub insn_count: u16,
    /// Byte offset from the start of the `encoded_catch_handler_list`
    /// to this entry's `encoded_catch_handler`.
    pub handler_off: u16,
}

/// One `encoded_catch_handler` (DEX §6.6.1).
#[derive(Clone, Debug)]
pub struct HandlerSpec {
    pub catches: Vec<(u16, u32)>,
    pub catch_all: Option<u32>,
}

impl HandlerSpec {
    pub fn bytes(&self) -> Vec<u8> {
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

// ── DEX spec model ───────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Method {
    /// `method_ids` index.
    pub name: u32,
    pub flags: u16,
    pub code: Option<Code>,
}

#[derive(Clone, Debug)]
pub struct Code {
    pub registers: u16,
    pub ins: u16,
    pub outs: u16,
    pub units: Vec<u16>,
    pub tries: Vec<TrySpec>,
    pub handlers: Vec<HandlerSpec>,
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
            out.extend_from_slice(&h.bytes());
        }
        out
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FieldSpec {
    /// `field_ids` index.
    pub idx: u32,
    pub flags: u16,
}

#[derive(Clone, Debug)]
pub struct ClassSpec {
    pub flags: u32,
    /// `type_ids` index of the class itself.
    pub class_idx: u32,
    /// `type_ids` index of the superclass (`None` = no superclass).
    pub superclass: Option<u32>,
    pub interfaces: Vec<u32>,
    pub static_fields: Vec<FieldSpec>,
    pub instance_fields: Vec<FieldSpec>,
    pub direct_methods: Vec<Method>,
    pub virtual_methods: Vec<Method>,
}

#[derive(Clone, Copy, Debug)]
pub struct FieldId {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct MethodId {
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
}

#[derive(Clone, Debug)]
pub struct ProtoSpec {
    pub shorty: u32,
    pub ret: u32,
    pub params: Vec<u32>,
}

#[derive(Clone, Copy, Debug)]
pub struct MethodHandle {
    /// 0..=8 per DEX `method_handle_type_codes`.
    pub kind: u16,
    /// `method_ids` index for kinds 4..=8, `field_ids` index for 0..=3.
    pub member: u16,
}

#[derive(Clone, Debug)]
pub enum Ev {
    /// VALUE_INT (0x04), minimal width.
    Int(i32),
    /// VALUE_STRING (0x17), minimal width.
    Str(u32),
    /// VALUE_TYPE (0x18), minimal width.
    Type(u32),
    /// VALUE_METHOD (0x1a), minimal width.
    Method(u32),
    /// VALUE_METHOD_TYPE (0x15), minimal width — a `proto_ids` index.
    MethodType(u32),
    /// VALUE_METHOD_HANDLE (0x16), minimal width.
    MethodHandle(u32),
}

impl Ev {
    pub fn bytes(&self) -> Vec<u8> {
        let (value_type, v): (u8, u32) = match self {
            Self::Int(v) => (0x04, *v as u32),
            Self::Str(v) => (0x17, *v),
            Self::Type(v) => (0x18, *v),
            Self::Method(v) => (0x1a, *v),
            Self::MethodType(v) => (0x15, *v),
            Self::MethodHandle(v) => (0x16, *v),
        };
        let raw = v.to_le_bytes();
        // Minimal spec width: enough bytes for the value's magnitude.
        let len = raw.iter().rposition(|&b| b != 0).map_or(1, |i| i + 1);
        let mut out = vec![((len - 1) as u8) << 5 | value_type];
        out.extend_from_slice(&raw[..len]);
        out
    }
}

/// Bytes of an `encoded_array_item` (ULEB128 count + values).
pub fn encoded_array(values: &[Ev]) -> Vec<u8> {
    let mut out = uleb(values.len() as u32);
    for v in values {
        out.extend_from_slice(&v.bytes());
    }
    out
}

/// The whole file, before assembly.
#[derive(Default, Clone, Debug)]
pub struct DexSpec {
    /// DEX version string, e.g. `"038"` / `"039"`.
    pub version: String,
    pub strings: Vec<String>,
    pub types: Vec<u32>,
    pub protos: Vec<ProtoSpec>,
    pub fields: Vec<FieldId>,
    pub methods: Vec<MethodId>,
    pub classes: Vec<ClassSpec>,
    pub handles: Vec<MethodHandle>,
    /// `call_site_ids` entries: each is one `encoded_array_item` body.
    pub call_sites: Vec<Vec<u8>>,
    /// Suppress the TYPE_CALL_SITE_ID_ITEM (0x0007) / TYPE_METHOD_HANDLE_ITEM
    /// (0x0008) map rows while still writing the pools — models a file
    /// whose pools exist but whose map hides them, which is exactly the
    /// shape a pre-O `invoke-custom` operand has to hit.
    pub hide_post_o_map_entries: bool,
}

impl DexSpec {
    /// DEX version used in the header (the gate's default is 039).
    pub fn version(&self) -> &str {
        if self.version.is_empty() {
            "039"
        } else {
            &self.version
        }
    }

    /// `type_ids` index of `descriptor`, appended when absent.
    pub fn ty(&mut self, descriptor: &str) -> u32 {
        let s = self.str(descriptor);
        if let Some(i) = self.types.iter().position(|&x| x == s) {
            return i as u32;
        }
        self.types.push(s);
        self.types.len() as u32 - 1
    }

    /// `string_ids` index of `s`, appended when absent. The pool is not
    /// re-sorted: the DEX spec requires sorted `string_ids`, but index
    /// stability is what a test wants to assert, and droidsaw only
    /// records ordering violations.
    pub fn str(&mut self, s: &str) -> u32 {
        if let Some(i) = self.strings.iter().position(|x| x == s) {
            return i as u32;
        }
        self.strings.push(s.to_string());
        self.strings.len() as u32 - 1
    }

    /// `proto_ids` index of `(shorty, ret, params)`, appended when absent.
    pub fn proto(&mut self, shorty: &str, ret: u32, params: &[u32]) -> u32 {
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

    /// Append a `field_ids` row, returning its index.
    pub fn field(&mut self, class_idx: u32, type_idx: u32, name: &str) -> u32 {
        let name_idx = self.str(name);
        self.fields.push(FieldId {
            class_idx: class_idx as u16,
            type_idx: type_idx as u16,
            name_idx,
        });
        self.fields.len() as u32 - 1
    }

    /// Append a `method_ids` row, returning its index.
    pub fn method(&mut self, class_idx: u32, proto_idx: u32, name: &str) -> u32 {
        let name_idx = self.str(name);
        self.methods.push(MethodId {
            class_idx: class_idx as u16,
            proto_idx: proto_idx as u16,
            name_idx,
        });
        self.methods.len() as u32 - 1
    }

    /// Assemble the DEX bytes. SHA-1 is written before adler32 because
    /// the signature bytes live inside the adler32 range.
    pub fn build(&self) -> Vec<u8> {
        let mut o = 0x70usize;
        let string_ids_off = o;
        o += 4 * self.strings.len();
        let type_ids_off = o;
        o += 4 * self.types.len();
        let proto_ids_off = o;
        o += 12 * self.protos.len();
        let field_ids_off = o;
        o += 8 * self.fields.len();
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
        // which is 4-aligned, so `align4(len)` == aligning the absolute
        // offset.
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

        // code_items first, then class_data: the class_data entry carries
        // the code offsets, so the code items must already be placed.
        // Section order inside `data` is free.
        let mut class_data_offs = Vec::with_capacity(self.classes.len());
        let mut code_offs: Vec<u32> = Vec::new();
        let mut static_value_offs: Vec<u32> = Vec::new();
        for c in &self.classes {
            let mut offs: Vec<u32> = Vec::new();
            for m in c.direct_methods.iter().chain(c.virtual_methods.iter()) {
                let off = match &m.code {
                    Some(code) => {
                        d.align();
                        let at = d.off();
                        code_offs.push(at);
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
            cd.extend(uleb(c.static_fields.len() as u32));
            cd.extend(uleb(c.instance_fields.len() as u32));
            cd.extend(uleb(c.direct_methods.len() as u32));
            cd.extend(uleb(c.virtual_methods.len() as u32));
            for fields in [&c.static_fields, &c.instance_fields] {
                let mut acc = 0u32;
                for f in fields {
                    cd.extend(uleb(f.idx - acc));
                    cd.extend(uleb(u32::from(f.flags)));
                    acc = f.idx;
                }
            }
            let mut next = 0usize;
            for (list, count) in [
                (&c.direct_methods, c.direct_methods.len()),
                (&c.virtual_methods, c.virtual_methods.len()),
            ] {
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
                let _ = count;
                next += list.len();
            }
            d.raw(&cd);
            static_value_offs.push(0);
        }

        // encoded_array items (call sites first, then class statics).
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
        // `d.buf` starts at absolute offset `data_off`.
        b[data_off..data_off + d.buf.len()].copy_from_slice(&d.buf);

        // header
        b[..8].copy_from_slice(format!("dex\n{}\0", self.version()).as_bytes());
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
        p32(&mut b, 0x50, self.fields.len() as u32);
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

        for (i, f) in self.fields.iter().enumerate() {
            let base = field_ids_off + i * 8;
            p16(&mut b, base, f.class_idx);
            p16(&mut b, base + 2, f.type_idx);
            p32(&mut b, base + 4, f.name_idx);
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
            p32(&mut b, base + 28, static_value_offs[i]);
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
    /// declared with size 0: droidsaw reads only the call-site and
    /// method-handle rows (both in the id sections), and re-deriving
    /// those offsets here would duplicate the layout walk `build` owns.
    fn map_entries(&self) -> Vec<(u16, u32, u32)> {
        let mut o = 0x70usize;
        let string_ids_off = o;
        o += 4 * self.strings.len();
        let type_ids_off = o;
        o += 4 * self.types.len();
        let proto_ids_off = o;
        o += 12 * self.protos.len();
        let field_ids_off = o;
        o += 8 * self.fields.len();
        let method_ids_off = o;
        o += 8 * self.methods.len();
        let class_defs_off = o;
        o += 32 * self.classes.len();
        let call_site_ids_off = o;
        o += 4 * self.call_sites.len();
        let method_handles_off = o;
        o += 8 * self.handles.len();
        let _ = o;

        // Extents are only used for the header/map sanity that droidsaw
        // does not verify; offsets below are recomputed by `build`,
        // which is the single source of truth. To avoid duplicating the
        // layout walk, map rows are emitted with size 0 for the
        // variable-extent data types (class_data / code / string_data /
        // encoded_array) — droidsaw reads only the call-site and
        // method-handle rows, both of which live in the id sections.
        let mut e: Vec<(u16, u32, u32)> = vec![
            (0x0000, 1, 0),
            (0x0001, self.strings.len() as u32, string_ids_off as u32),
            (0x0002, self.types.len() as u32, type_ids_off as u32),
            (0x0003, self.protos.len() as u32, proto_ids_off as u32),
            (0x0004, self.fields.len() as u32, field_ids_off as u32),
            (0x0005, self.methods.len() as u32, method_ids_off as u32),
            (0x0006, self.classes.len() as u32, class_defs_off as u32),
        ];
        if !self.call_sites.is_empty() && !self.hide_post_o_map_entries {
            e.push((
                0x0007,
                self.call_sites.len() as u32,
                call_site_ids_off as u32,
            ));
        }
        if !self.handles.is_empty() && !self.hide_post_o_map_entries {
            e.push((0x0008, self.handles.len() as u32, method_handles_off as u32));
        }
        if !self.call_sites.is_empty() && !self.hide_post_o_map_entries {
            // TYPE_ENCODED_ARRAY_ITEM; droidsaw ignores it, but a real
            // DEX declares it and the row keeps the map self-consistent.
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
    /// Pad to a 4-byte boundary and return the new length. `base` is
    /// 4-aligned by construction, so aligning the buffer length aligns
    /// the absolute offset.
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

/// MUTF-8 encoding (DEX §3.3): one/two/three-byte forms only, and
/// supplementary code points as a surrogate pair of three-byte forms.
fn mutf8(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for ch in s.chars() {
        let cp = ch as u32;
        if cp < 0x80 && cp != 0 {
            out.push(cp as u8);
        } else if cp < 0x800 {
            out.push(0xC0 | (cp >> 6) as u8);
            out.push(0x80 | (cp & 0x3F) as u8);
        } else if cp < 0x10000 {
            push3(&mut out, cp);
        } else {
            let v = cp - 0x10000;
            push3(&mut out, 0xD800 + (v >> 10));
            push3(&mut out, 0xDC00 + (v & 0x3FF));
        }
    }
    out
}

fn push3(out: &mut Vec<u8>, cp: u32) {
    out.push(0xE0 | ((cp >> 12) & 0x0F) as u8);
    out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
    out.push(0x80 | (cp & 0x3F) as u8);
}
