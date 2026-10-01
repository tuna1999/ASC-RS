//! Static XOR string deobfuscation (`--decode-xor`), P1 pattern:
//!
//! ```java
//! static String i(byte[] p) {            // decoder: xor every element
//!     for (int j = 0; j < p.length; j++) //   with a literal key, then
//!         p[j] = (byte)(p[j] ^ KEY);     //   `new String(p)`
//!     return new String(p);
//! }
//! ...
//! byte[] a = {8, 7, ...};                // caller: byte array built from
//! String s = i(a);                       //   constants, one decode call
//! ```
//!
//! [`find_xor_decoders`] recognizes decoders (static `([B)Ljava/lang/String;`
//! bodies on a strict opcode allow-list that must XOR with a provable key,
//! store back into the parameter and end in `new String(byte[])`).
//! [`XorResolver::calls`] decodes call sites with a per-method forward
//! dataflow whose meet keeps only values every predecessor path agrees
//! on; arrays come from `const`+`aput-byte` chains or `fill-array-data`,
//! and an array that escapes into another invoke loses provability,
//! so an unprovable site yields no call rather than a wrong string.
//!
//! The decoder mutates its argument in place, so a call site is only
//! [`XorCall::patchable`] when no register aliasing the array is touched
//! after the invoke (patching the call would then change what those reads
//! see). [`XorCall`] mirrors asc-paranoid's `Call` so asc-core can reuse
//! its findrefs/getclass plumbing.

use std::collections::HashMap;

use asc_dex::{CodeItem, DexView, MethodIdx, ProtoIdx};

use crate::dex::{
    Regs, decode_insns, is_payload, leaders, lossy, regs, str_bytes, string_protos, type_bytes,
    unit, unit32,
};

const ACC_STATIC: u32 = 0x0008;
const STRING: &[u8] = b"Ljava/lang/String;";
const BYTE_ARRAY: &[u8] = b"[B";
const VOID: &[u8] = b"V";
/// Largest byte array modeled at a call site (values are literal consts,
/// real obfuscators stay in the tens; cap is a bounded-memory guard).
const MAX_ELEMENTS: usize = 1024;

/// A recognized `xor-with-literal-key` decoder method.
#[derive(Debug, Clone)]
pub struct XorDecoder {
    /// Defining class descriptor (`L…;`).
    pub class: String,
    /// Method name.
    pub method: String,
    /// XOR key (low 8 bits — `aput-byte` stores one byte).
    pub key: u8,
}

/// One decoded `invoke-static <decoder>(byte[])` call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XorCall {
    /// Code-unit offset of the `invoke-static[/range]`.
    pub offset: u32,
    /// Destination register of the following `move-result-object`, if any.
    pub result: Option<u8>,
    /// Decoded string as UTF-16 code units (for [`asc_rebuild::StringPatch`]).
    pub value: Vec<u16>,
    /// False when an array alias is touched after the invoke — the decoder
    /// mutates in place, so replacing the call would change later reads.
    pub patchable: bool,
}

/// Opcodes a decoder body may use; anything else (fields, other calls,
/// monitors, array fills, …) disqualifies the method.
fn decoder_allowed(op: u8) -> bool {
    matches!(op,
        0x01..=0x0c            // moves (incl. move-result*)
        | 0x0e                 // return-void
        | 0x11                 // return-object
        | 0x12..=0x15          // const/4, const/16, const, const/high16
        | 0x21                 // array-length
        | 0x22                 // new-instance (must be String)
        | 0x28..=0x2a          // goto, goto/16, goto/32
        | 0x32..=0x3d          // if-eq … if-lez
        | 0x48                 // aget-byte
        | 0x4f                 // aput-byte
        | 0x70                 // invoke-direct (must be String.<init>([B)V)
        | 0x8d                 // int-to-byte
        | 0x90 | 0x97          // add-int, xor-int
        | 0xb0 | 0xb7          // add-int/2addr, xor-int/2addr
        | 0xd0 | 0xd7          // add-int/lit16, xor-int/lit16
        | 0xd8 | 0xdf) // add-int/lit8, xor-int/lit8
}

/// Every XOR decoder defined in `view`: a static `([B)Ljava/lang/String;`
/// whose allow-listed body XORs with one consistent literal key, stores
/// back into the parameter array and constructs exactly one
/// `new String(byte[])`. Malformed methods contribute nothing.
pub fn find_xor_decoders(view: &DexView<'_>) -> Vec<XorDecoder> {
    let mut out = Vec::new();
    let protos = string_protos(view, &[BYTE_ARRAY]);
    if protos.is_empty() {
        return out;
    }
    for i in 0..view.class_def_count() {
        let Ok(cd) = view.class_def(i) else { continue };
        let Ok(Some(data)) = view.class_data(cd.class_data_off) else {
            continue;
        };
        for em in &data.direct_methods {
            if em.access_flags & ACC_STATIC == 0 || em.code_off == 0 {
                continue;
            }
            let Ok(mi) = view.method(em.method_idx) else {
                continue;
            };
            if !protos.contains(&mi.proto.0) {
                continue;
            }
            let Ok(Some(code)) = view.code_item(em.code_off) else {
                continue;
            };
            let (Some(key), Some(name)) = (analyze_decoder(view, &code), str_bytes(view, mi.name))
            else {
                continue;
            };
            out.push(XorDecoder {
                class: lossy(type_bytes(view, cd.class).unwrap_or_default()),
                method: lossy(name),
                key,
            });
        }
    }
    out
}

/// Proves the decoder shape and extracts the key, or `None`.
fn analyze_decoder(view: &DexView<'_>, code: &CodeItem<'_>) -> Option<u8> {
    if code.ins_size == 0 || code.registers_size < code.ins_size {
        return None;
    }
    let p0 = code.registers_size - code.ins_size;
    let insns = code.insns_exact();
    let list = decode_insns(insns, code.insns_size)?;
    // Known register values: an int constant, or `p0.length` (only the
    // full-array `new String(p, 0, p.length)` form is accepted).
    let mut consts: HashMap<u16, DVal> = HashMap::new();
    let mut key: Option<i64> = None;
    let mut aput_on_param = false;
    let mut new_string = false;
    let note_key = |key: &mut Option<i64>, k: i64| -> bool {
        match *key {
            Some(k0) if k0 != k => false, // conflicting keys: not our shape
            _ => {
                *key = Some(k);
                true
            }
        }
    };
    for &(off, _) in &list {
        if is_payload(insns, off) {
            return None; // payloads have no place in a P1 decoder
        }
        let first = unit(insns, off, 0);
        let op = first as u8;
        let b1 = first >> 8;
        let (a4, b4) = (b1 & 0xF, b1 >> 4);
        if !decoder_allowed(op) {
            return None;
        }
        match op {
            0x12 => {
                consts.insert(a4, DVal::Const(((b1 as u8 as i8) >> 4) as i64));
            }
            0x13 => {
                consts.insert(b1, DVal::Const(unit(insns, off, 1) as i16 as i64));
            }
            0x14 => {
                consts.insert(b1, DVal::Const(unit32(insns, off, 1) as i32 as i64));
            }
            0x15 => {
                consts.insert(
                    b1,
                    DVal::Const(((unit(insns, off, 1) as i16 as i32) << 16) as i64),
                );
            }
            0x01 | 0x04 | 0x07 => {
                copy(&mut consts, a4, b4, op);
            }
            0x02 | 0x05 | 0x08 => {
                copy(&mut consts, b1, unit(insns, off, 1), op);
            }
            0x03 | 0x06 | 0x09 => {
                copy(&mut consts, b1, unit(insns, off, 1), op);
            }
            0x0a..=0x0c => {
                consts.remove(&b1); // move-result*: unknown here
            }
            0x21 => {
                // `array-length vA, vB`: p0.length is provable
                if b4 == p0 {
                    consts.insert(a4, DVal::ParamLen);
                } else {
                    consts.remove(&a4);
                }
            }
            0x48 => {
                consts.remove(&a4); // aget-byte: unknown
            }
            0x4f => {
                if unit(insns, off, 1) & 0xFF == p0 {
                    aput_on_param = true;
                }
            }
            0x8d => match consts.get(&b4) {
                Some(DVal::Const(v)) => {
                    consts.insert(a4, DVal::Const(*v as i8 as i64));
                }
                _ => {
                    consts.remove(&a4);
                }
            },
            0xdf => {
                // xor-int/lit8: AA|op, lit|BB
                let lit = (unit(insns, off, 1) >> 8) as u8 as i8 as i64;
                if !note_key(&mut key, lit) {
                    return None;
                }
                consts.remove(&b1);
            }
            0xd7 => {
                // xor-int/lit16: B|A|op, literal
                if !note_key(&mut key, unit(insns, off, 1) as i16 as i64) {
                    return None;
                }
                consts.remove(&a4);
            }
            0x97 => {
                // xor-int vAA, vBB, vCC — provable when exactly one source
                // (or both) is a known constant
                let u = unit(insns, off, 1);
                let v = |r| match consts.get(&r) {
                    Some(DVal::Const(v)) => Some(*v),
                    _ => None,
                };
                match (v(u & 0xFF), v(u >> 8)) {
                    (Some(x), Some(y)) => {
                        consts.insert(b1, DVal::Const(x ^ y));
                    }
                    (Some(k), None) | (None, Some(k)) => {
                        if !note_key(&mut key, k) {
                            return None;
                        }
                        consts.remove(&b1);
                    }
                    (None, None) => {
                        consts.remove(&b1);
                    }
                }
            }
            0xb7 => {
                // xor-int/2addr vA, vB
                let v = |r| match consts.get(&r) {
                    Some(DVal::Const(v)) => Some(*v),
                    _ => None,
                };
                match (v(a4), v(b4)) {
                    (Some(x), Some(y)) => {
                        consts.insert(a4, DVal::Const(x ^ y));
                    }
                    (Some(k), None) | (None, Some(k)) => {
                        if !note_key(&mut key, k) {
                            return None;
                        }
                        consts.remove(&a4);
                    }
                    (None, None) => {
                        consts.remove(&a4);
                    }
                }
            }
            0x22 => {
                if type_bytes(view, asc_dex::TypeIdx(unit(insns, off, 1) as u32)) != Some(STRING) {
                    return None;
                }
                consts.remove(&b1);
            }
            0x70 => {
                let m = view.method(MethodIdx(unit(insns, off, 1) as u32)).ok()?;
                let Ok(proto) = view.proto(ProtoIdx(m.proto.0)) else {
                    return None;
                };
                let is_string_ctor = type_bytes(view, m.class) == Some(STRING)
                    && str_bytes(view, m.name) == Some(b"<init>")
                    && type_bytes(view, proto.return_type) == Some(VOID);
                if !is_string_ctor {
                    return None;
                }
                // Accepted forms: `new String(p)` — ([B)V — and
                // `new String(p, 0, p.length)` — ([BII)V with a provable
                // zero offset and a `p0.length` length.
                let param = |i: usize| {
                    proto
                        .parameters
                        .get(i)
                        .and_then(|t| type_bytes(view, t).map(|b| b.to_vec()))
                };
                let ok = match proto.parameters.len() {
                    1 if param(0).as_deref() == Some(BYTE_ARRAY) => true,
                    3 if param(0).as_deref() == Some(BYTE_ARRAY)
                        && param(1).as_deref() == Some(b"I")
                        && param(2).as_deref() == Some(b"I") =>
                    {
                        match regs(insns, off) {
                            // args = {instance, array, offset, length}
                            Regs::List(r, 4) => {
                                matches!(consts.get(&r[2]), Some(DVal::Const(0)))
                                    && matches!(consts.get(&r[3]), Some(DVal::ParamLen))
                            }
                            _ => false,
                        }
                    }
                    _ => false,
                };
                if !ok {
                    return None;
                }
                new_string = true;
            }
            _ => {
                // goto / if / return: no register writes to model
            }
        }
    }
    (aput_on_param && new_string)
        .then(|| key.map(|k| (k & 0xFF) as u8))
        .flatten()
}

/// Decoder register value: int constant or `p0.length`.
#[derive(Clone, Copy)]
enum DVal {
    Const(i64),
    ParamLen,
}

/// Scalar move: `dst` takes `src`'s value; wide forms also clear `dst+1`.
fn copy(consts: &mut HashMap<u16, DVal>, dst: u16, src: u16, op: u8) {
    match consts.get(&src).copied() {
        Some(v) => {
            consts.insert(dst, v);
        }
        None => {
            consts.remove(&dst);
        }
    }
    if (0x04..=0x06).contains(&op) {
        consts.remove(&dst.wrapping_add(1));
    }
}

/// Per-DEX index of decoder method ids (the decoder may live in another
/// DEX of the same APK). Mirrors `asc_paranoid::Resolver`.
pub struct XorResolver<'d> {
    targets: HashMap<u32, &'d XorDecoder>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Val {
    Int(i64),
    /// Byte array identified by its `new-array` code-unit offset — a
    /// deterministic identity, so dataflow meets can compare contents.
    Arr(u32),
}

/// Per-block dataflow state: register values plus the contents of every
/// tracked byte array (keyed by creation offset).
#[derive(Clone, Default)]
struct Flow {
    regs: HashMap<u16, Val>,
    arrays: HashMap<u32, Vec<Option<u8>>>,
}

/// `a = a ∩ b` (keep only entries both states agree on, arrays included).
/// Returns whether `a` changed. Entries only ever disappear or lose
/// elements, so the worklist fixpoint terminates.
fn meet(a: &mut Flow, b: &Flow) -> bool {
    let mut changed = false;
    let regs: Vec<u16> = a.regs.keys().copied().collect();
    for k in regs {
        if a.regs.get(&k) != b.regs.get(&k) {
            a.regs.remove(&k);
            changed = true;
        }
    }
    let arrays: Vec<u32> = a.arrays.keys().copied().collect();
    for o in arrays {
        if a.arrays.get(&o) != b.arrays.get(&o) {
            a.arrays.remove(&o);
            changed = true;
        }
    }
    changed
}

impl<'d> XorResolver<'d> {
    /// Matches `view`'s method ids against `decoders` by class descriptor,
    /// name and `([B)Ljava/lang/String;` proto.
    pub fn new(view: &DexView<'_>, decoders: &'d [XorDecoder]) -> Self {
        let mut targets = HashMap::new();
        if !decoders.is_empty() {
            let protos = string_protos(view, &[BYTE_ARRAY]);
            for m in 0..view.method_count() {
                let Ok(mi) = view.method(MethodIdx(m)) else {
                    continue;
                };
                if !protos.contains(&mi.proto.0) {
                    continue;
                }
                let (Some(name), Some(class)) =
                    (str_bytes(view, mi.name), type_bytes(view, mi.class))
                else {
                    continue;
                };
                if let Some(d) = decoders
                    .iter()
                    .find(|d| d.method.as_bytes() == name && d.class.as_bytes() == class)
                {
                    targets.insert(m, d);
                }
            }
        }
        Self { targets }
    }

    /// `true` when `view` references no known decoder.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Decodes every decoder call in `code` whose byte array is provably
    /// constant on **every path** reaching the invoke: `new-array` of
    /// `[B` with a constant size and every element stored from a
    /// constant, tracked by a forward dataflow whose meet keeps only
    /// values all predecessor paths agree on. An array that escapes
    /// into any other invoke is dropped from the state.
    pub fn calls(&self, view: &DexView<'_>, code: &CodeItem<'_>) -> Vec<XorCall> {
        let mut out = Vec::new();
        if self.targets.is_empty() {
            return out;
        }
        let insns = code.insns_exact();
        let Some(list) = decode_insns(insns, code.insns_size) else {
            return out;
        };
        let leader_set = leaders(view, code, insns, &list);
        // Basic-block starts: leaders (branch targets, catch handlers),
        // the instruction *after* every conditional (its fallthrough
        // edge needs its own block so mid-block branches cannot smuggle
        // a post-branch state onto a pre-branch edge), and the entry.
        let mut starts: Vec<u32> = leader_set.iter().copied().chain([0]).collect();
        for &(off, w) in &list {
            if !is_payload(insns, off) && matches!(unit(insns, off, 0) as u8, 0x32..=0x3d) {
                starts.push(off + w);
            }
        }
        starts.sort_unstable();
        starts.dedup();
        let block_of = |off: u32| starts.partition_point(|&s| s <= off) - 1;

        // positions (indexes into `list`) of each block's instructions
        let blocks: Vec<Vec<usize>> = {
            let mut b = vec![Vec::new(); starts.len()];
            for (pos, &(off, _)) in list.iter().enumerate() {
                if !is_payload(insns, off) {
                    b[block_of(off)].push(pos);
                }
            }
            b
        };

        // ---- forward dataflow to fixpoint ----
        let mut in_state: Vec<Option<Flow>> = (0..starts.len()).map(|_| None).collect();
        in_state[0] = Some(Flow::default());
        let mut queue: std::collections::VecDeque<usize> = [0].into_iter().collect();
        while let Some(bi) = queue.pop_front() {
            let Some(mut st) = in_state[bi].clone() else {
                continue;
            };
            for &pos in &blocks[bi] {
                self.exec_insn(view, insns, &list, pos, &mut st);
                if is_unconditional(unit(insns, list[pos].0, 0) as u8) {
                    break; // dead code after a goto/return never runs here
                }
            }
            for succ in self.successors(insns, &list, &blocks[bi], &starts, block_of) {
                let changed = match &mut in_state[succ] {
                    None => {
                        in_state[succ] = Some(st.clone());
                        true
                    }
                    Some(s) => meet(s, &st),
                };
                if changed && !queue.contains(&succ) {
                    queue.push_back(succ);
                }
            }
        }

        // ---- final pass: report decode sites under their fixed states ----
        for bi in 0..starts.len() {
            let Some(mut st) = in_state[bi].clone() else {
                continue;
            };
            for &pos in &blocks[bi] {
                self.exec_insn_collect(view, insns, &list, pos, &mut st, &mut Some(&mut out));
                if is_unconditional(unit(insns, list[pos].0, 0) as u8) {
                    break;
                }
            }
        }
        out
    }

    /// Successor block indexes of the block whose instructions are
    /// `blk`. Every conditional inside the block contributes its target
    /// edge; a goto/return/throw ends the block (anything after it is
    /// dead); otherwise the next block is the fallthrough. `switch`
    /// blocks conservatively end the path (case targets are not chased,
    /// so such call sites simply never decode).
    fn successors(
        &self,
        insns: &[u8],
        list: &[(u32, u32)],
        blk: &[usize],
        starts: &[u32],
        block_of: impl Fn(u32) -> usize,
    ) -> Vec<usize> {
        let Some(&last) = blk.last() else {
            return vec![];
        };
        let mut succ: Vec<usize> = Vec::new();
        let push_target = |succ: &mut Vec<usize>, t: i32| {
            if let Some(u) = u32::try_from(t)
                .ok()
                .filter(|&u| (u as usize) < insns.len() / 2)
            {
                let b = block_of(u);
                if !succ.contains(&b) {
                    succ.push(b);
                }
            }
        };
        for &pos in blk {
            let (off, _) = list[pos];
            let first = unit(insns, off, 0);
            let op = first as u8;
            match op {
                0x28 => {
                    push_target(&mut succ, off as i32 + (first >> 8) as i8 as i32);
                    return succ;
                }
                0x29 => {
                    push_target(&mut succ, off as i32 + unit(insns, off, 1) as i16 as i32);
                    return succ;
                }
                0x2a | 0x2b | 0x2c | 0x0e..=0x11 | 0x27 => return succ,
                0x32..=0x3d => {
                    push_target(&mut succ, off as i32 + unit(insns, off, 1) as i16 as i32);
                }
                _ => {}
            }
        }
        if let Some(next) = starts.iter().find(|&&s| s > list[last].0) {
            let b = block_of(*next);
            if !succ.contains(&b) {
                succ.push(b);
            }
        }
        succ
    }

    /// One instruction of the interpreter over `st`. When `out` is
    /// given, decode sites also emit [`XorCall`]s (final pass only).
    fn exec_insn(
        &self,
        view: &DexView<'_>,
        insns: &[u8],
        list: &[(u32, u32)],
        pos: usize,
        st: &mut Flow,
    ) {
        self.exec_insn_collect(view, insns, list, pos, st, &mut None)
    }

    fn exec_insn_collect(
        &self,
        view: &DexView<'_>,
        insns: &[u8],
        list: &[(u32, u32)],
        pos: usize,
        st: &mut Flow,
        out: &mut Option<&mut Vec<XorCall>>,
    ) {
        let off = list[pos].0;
        let first = unit(insns, off, 0);
        let op = first as u8;
        let b1 = first >> 8;
        let (a4, b4) = (b1 & 0xF, b1 >> 4);
        let regs_v = &mut st.regs;
        let arrays = &mut st.arrays;
        match op {
            0x12 => {
                regs_v.insert(a4, Val::Int(((b1 as u8 as i8) >> 4) as i64));
            }
            0x13 => {
                regs_v.insert(b1, Val::Int(unit(insns, off, 1) as i16 as i64));
            }
            0x14 => {
                regs_v.insert(b1, Val::Int(unit32(insns, off, 1) as i32 as i64));
            }
            0x15 => {
                regs_v.insert(
                    b1,
                    Val::Int(((unit(insns, off, 1) as i16 as i32) << 16) as i64),
                );
            }
            0x01 | 0x04 | 0x07 => {
                move_val(regs_v, a4, b4, op);
            }
            0x02 | 0x05 | 0x08 | 0x03 | 0x06 | 0x09 => {
                move_val(regs_v, b1, unit(insns, off, 1), op);
            }
            0x23 => {
                // new-array vA, vB, [B with a constant size
                let is_byte_array = type_bytes(view, asc_dex::TypeIdx(unit(insns, off, 1) as u32))
                    == Some(BYTE_ARRAY);
                let size = match regs_v.get(&b4) {
                    Some(&Val::Int(n)) => usize::try_from(n).ok(),
                    _ => None,
                };
                match (is_byte_array, size) {
                    (true, Some(n)) if n <= MAX_ELEMENTS => {
                        arrays.insert(off, vec![None; n]);
                        regs_v.insert(a4, Val::Arr(off));
                    }
                    _ => {
                        regs_v.remove(&a4);
                    }
                }
            }
            0x4f => {
                // aput-byte vAA(value), vBB(array), vCC(index)
                let u = unit(insns, off, 1);
                let (val, arr, idx) = (b1, u & 0xFF, u >> 8);
                match (regs_v.get(&val).copied(), regs_v.get(&arr).copied()) {
                    (Some(Val::Int(v)), Some(Val::Arr(a))) => {
                        let slot = match regs_v.get(&idx) {
                            Some(&Val::Int(i)) => usize::try_from(i).ok(),
                            _ => None,
                        };
                        if let Some(elems) = arrays.get_mut(&a) {
                            match slot {
                                Some(i) if i < elems.len() => {
                                    elems[i] = Some(v as u8); // aput stores &0xFF
                                }
                                _ => elems.fill(None), // unknown index: nothing provable
                            }
                        }
                    }
                    (_, Some(Val::Arr(a))) => {
                        if let Some(elems) = arrays.get_mut(&a) {
                            elems.fill(None); // unknown value stored
                        }
                    }
                    _ => {} // untracked array: nothing to poison
                }
            }
            0x48 => {
                // aget-byte: element value back out, when provable
                let u = unit(insns, off, 1);
                let (dst, arr, idx) = (b1, u & 0xFF, u >> 8);
                let v = match (regs_v.get(&arr).copied(), regs_v.get(&idx).copied()) {
                    (Some(Val::Arr(a)), Some(Val::Int(i))) => match arrays.get(&a) {
                        Some(elems) => usize::try_from(i)
                            .ok()
                            .and_then(|i| elems.get(i).copied().flatten())
                            .map(|b| b as i64),
                        None => None,
                    },
                    _ => None,
                };
                match v {
                    Some(v) => {
                        regs_v.insert(dst, Val::Int(v));
                    }
                    None => {
                        regs_v.remove(&dst);
                    }
                }
            }
            0x21 => {
                // array-length of a tracked array is its known size
                match regs_v.get(&b4).copied() {
                    Some(Val::Arr(a)) => {
                        if let Some(elems) = arrays.get(&a) {
                            regs_v.insert(a4, Val::Int(elems.len() as i64));
                        } else {
                            regs_v.remove(&a4);
                        }
                    }
                    _ => {
                        regs_v.remove(&a4);
                    }
                }
            }
            0x26 => {
                // fill-array-data vAA, :payload — static bytes from the
                // embedded payload blob (ident 0x0300, uleb width, uleb
                // size, data). Only byte payloads are modeled.
                if let Some(&Val::Arr(a)) = regs_v.get(&b1) {
                    let payload = unit32(insns, off, 1) as i32;
                    let filled = fill_bytes(insns, off, payload);
                    if let Some(elems) = arrays.get_mut(&a) {
                        match filled {
                            Some(bytes) if bytes.len() <= elems.len() => {
                                for (i, b) in bytes.iter().enumerate() {
                                    elems[i] = Some(*b);
                                }
                            }
                            _ => elems.fill(None), // not provable: no decode
                        }
                    }
                }
            }
            0x71 if first >> 12 == 1 => {
                let arg = unit(insns, off, 2) & 0xF;
                let dec = self.targets.get(&(unit(insns, off, 1) as u32));
                if let Some(out) = out.as_deref_mut() {
                    self.decode_at(insns, list, pos, arg, dec, regs_v, arrays, out);
                }
                // the decoder (or an unknown callee) mutates/escapes the
                // array: provability ends at the first invoke on it
                if let Some(&Val::Arr(a)) = regs_v.get(&arg) {
                    arrays.remove(&a);
                }
                regs_v.remove(&arg);
            }
            0x77 if b1 == 1 => {
                let arg = unit(insns, off, 2);
                let dec = self.targets.get(&(unit(insns, off, 1) as u32));
                if let Some(out) = out.as_deref_mut() {
                    self.decode_at(insns, list, pos, arg, dec, regs_v, arrays, out);
                }
                if let Some(&Val::Arr(a)) = regs_v.get(&arg) {
                    arrays.remove(&a);
                }
                regs_v.remove(&arg);
            }
            0x6e..=0x78 => {
                // any other invoke: an argument array escapes (the callee
                // may mutate it) — drop its contents, then default-clear
                if let Regs::List(r, n) = regs(insns, off) {
                    for &r in &r[..n] {
                        if let Some(&Val::Arr(a)) = regs_v.get(&r) {
                            arrays.remove(&a);
                        }
                        regs_v.remove(&r);
                    }
                } else if let Regs::Range(s, n) = regs(insns, off) {
                    for k in 0..n {
                        let r = s.wrapping_add(k);
                        if let Some(&Val::Arr(a)) = regs_v.get(&r) {
                            arrays.remove(&a);
                        }
                        regs_v.remove(&r);
                    }
                }
            }
            _ => {
                for r in named_regs(insns, off) {
                    if let Some(&Val::Arr(a)) = regs_v.get(&r) {
                        arrays.remove(&a);
                    }
                    regs_v.remove(&r);
                }
            }
        }
    }

    /// Decodes the array in `arg` at the invoke `list[pos]` and records
    /// the call when every element is known and valid UTF-8.
    #[allow(clippy::too_many_arguments)] // interpreter plumbing
    fn decode_at(
        &self,
        insns: &[u8],
        list: &[(u32, u32)],
        pos: usize,
        arg: u16,
        dec: Option<&&'d XorDecoder>,
        regs_v: &HashMap<u16, Val>,
        arrays: &HashMap<u32, Vec<Option<u8>>>,
        out: &mut Vec<XorCall>,
    ) {
        let off = list[pos].0;
        let Some(&Val::Arr(a)) = regs_v.get(&arg) else {
            return;
        };
        let Some(elems) = arrays.get(&a) else {
            return;
        };
        let Some(dec) = dec else {
            return;
        };
        let Some(bytes) = elems
            .iter()
            .map(|e| e.map(|b| b ^ dec.key))
            .collect::<Option<Vec<_>>>()
        else {
            return;
        };
        let Some(value) = String::from_utf8(bytes).ok() else {
            return; // not valid UTF-8: never guess the charset
        };
        let result = list
            .get(pos + 1)
            .filter(|&&(o, _)| !is_payload(insns, o) && unit(insns, o, 0) as u8 == 0x0c)
            .map(|&(o, _)| (unit(insns, o, 0) >> 8) as u8);
        // patchable only while no live alias of the array is read later
        let aliases: Vec<u16> = regs_v
            .iter()
            .filter(|(_, v)| matches!(v, Val::Arr(x) if *x == a))
            .map(|(r, _)| *r)
            .collect();
        let touched = {
            // An alias read observes the decoder's in-place mutation; a
            // pure def of an alias register (javac reuses the array
            // register for the invoke result) kills that alias instead.
            let mut active = aliases.clone();
            let mut touched = false;
            for &(o, _) in &list[pos + 1..] {
                if is_payload(insns, o) {
                    continue;
                }
                let (reads, defs) = def_use(insns, o);
                if reads.iter().any(|r| active.contains(r)) {
                    touched = true;
                    break;
                }
                for d in defs {
                    active.retain(|&a| a != d);
                }
                if active.is_empty() {
                    break;
                }
            }
            touched
        };
        out.push(XorCall {
            offset: off,
            result,
            value: value.encode_utf16().collect(),
            patchable: !touched,
        });
    }
}

/// `(reads, defs)` of the instruction at `off`. Only the shapes that can
/// appear around a byte-array construction are precise; every other
/// opcode reports all named registers as reads (conservative — an
/// invoke, aput or aget naming the alias must count).
fn def_use(insns: &[u8], off: u32) -> (Vec<u16>, Vec<u16>) {
    let first = unit(insns, off, 0);
    let op = first as u8;
    let b1 = first >> 8;
    let (a4, b4) = (b1 & 0xF, b1 >> 4);
    match op {
        // move-result*, move-exception: pure def
        0x0a..=0x0d => (vec![], vec![b1]),
        // const/4: pure def of a nibble register
        0x12 => (vec![], vec![a4]),
        // const/16, const, const/high16: pure def
        0x13..=0x15 => (vec![], vec![b1]),
        // 12x moves and array-length: def a4, read b4 (wide: also a4+1)
        0x01 | 0x04 | 0x07 | 0x21 => {
            let mut defs = vec![a4];
            if op == 0x04 {
                defs.push(a4 + 1);
            }
            (vec![b4], defs)
        }
        // 22x / 32x moves: def b1, read unit1 (wide: also b1+1)
        0x02..=0x03 | 0x05..=0x06 | 0x08..=0x09 => {
            let mut defs = vec![b1];
            if matches!(op, 0x05 | 0x06) {
                defs.push(b1 + 1);
            }
            (vec![unit(insns, off, 1)], defs)
        }
        _ => match regs(insns, off) {
            Regs::List(r, n) => (r[..n].to_vec(), vec![]),
            Regs::Range(s, n) => ((0..n).map(|k| s + k).collect(), vec![]),
        },
    }
}

/// Whether the opcode unconditionally transfers control (ends the
/// straight-line execution of the current block).
fn is_unconditional(op: u8) -> bool {
    matches!(op, 0x28 | 0x29 | 0x2a | 0x0e..=0x11 | 0x27)
}

/// Byte contents of the `fill-array-data` payload targeted from `off`
/// (offset in code units, possibly negative), or `None` when the blob is
/// truncated, not a byte payload, or outside `insns`. Payload layout per
/// the DEX spec: `ident` u16, `element_width` u16, `size` u32, data.
fn fill_bytes(insns: &[u8], off: u32, payload_off: i32) -> Option<Vec<u8>> {
    let units = off as i64 + payload_off as i64;
    if units < 0 {
        return None;
    }
    let at = (units * 2) as usize;
    let u16at = |p: usize| {
        insns
            .get(p..p + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let u32at = |p: usize| {
        insns
            .get(p..p + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    if u16at(at)? != 0x0300 {
        return None;
    }
    let width = u16at(at + 2)? as u32;
    let size = u32at(at + 4)?;
    if width != 1 || size > MAX_ELEMENTS as u32 {
        return None;
    }
    let start = at.checked_add(8)?;
    let end = start.checked_add(size as usize)?;
    if end > insns.len() {
        return None;
    }
    Some(insns[start..end].to_vec())
}
/// Registers an instruction names (its format's operand list).
fn named_regs(insns: &[u8], off: u32) -> Vec<u16> {
    match regs(insns, off) {
        Regs::List(r, n) => r[..n].to_vec(),
        Regs::Range(s, n) => (0..n).map(|k| s.wrapping_add(k)).collect(),
    }
}

/// Val move: `dst` takes `src`'s value; wide forms also clear `dst+1`.
fn move_val(regs_v: &mut HashMap<u16, Val>, dst: u16, src: u16, op: u8) {
    match regs_v.get(&src).copied() {
        Some(v) => {
            regs_v.insert(dst, v);
        }
        None => {
            regs_v.remove(&dst);
        }
    }
    if (0x04..=0x06).contains(&op) {
        regs_v.remove(&dst.wrapping_add(1));
    }
}
