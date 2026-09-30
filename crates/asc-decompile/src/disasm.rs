//! Smali-syntax disassembly renderer (backend for `disassemble`).
//!
//! Body layout is ours; the *operand* rendering of every opcode is delegated
//! to `droidsaw_dex::smali::fmt_instruction`, which was audited
//! byte-for-byte against baksmali for all opcodes EXCEPT the eight the audit
//! flagged. Those eight are re-rendered here:
//!
//! | opcode | droidsaw output | baksmali (correct) |
//! |---|---|---|
//! | `invoke-custom{/range}` | `?->?(?)?` | `call_site_N("name", (P)R, extra…)@bootstrap` |
//! | `invoke-polymorphic{/range}` | proto operand dropped or misfiled | `method, (P)R` |
//! | `const-method-handle` | misfiled as a method ref | `<kind>@<member>` |
//! | `const-method-type` | misfiled as a method ref | `(P)R` |
//! | `const-string{/jumbo}` | non-ASCII left raw | `\uXXXX` per non-ASCII unit |
//! | `const-wide/high16` | never an `L` | `L` outside the `i32` range |
//! | `.array-data` elements | unsigned hex, `t` on all widths | signed hex, `t`/`s`/none/`L` |
//! | `.packed-switch` / `.sparse-switch` keys | unsigned hex | signed hex |
//!
//! The `L` suffix rule is dexlib2's, not a smali convention: baksmali routes
//! every `Format21lh`/`Format51l` operand through
//! `LongRenderer.writeSignedIntOrLongTo` (append `L` only outside the `i32`
//! range) but renders `const-wide` — also `Format51l` — through
//! `LongRenderer.writeTo`, which always appends `L`. The two wide opcodes
//! therefore differ exactly as the table says. The narrow `const/high16`
//! shares `Format21h` with `writeSignedIntOrLongTo` and keeps droidsaw's
//! (correct) spelling.
//!
//! One more droidsaw output defect is fixed by owning the body layout: the
//! trailing-label flush printed each label past the last instruction twice.
//!
//! Silent degradation is refused. Every case the F5 gate enumerates that a
//! `CodeItem` actually signals — code-item invariant violations (unknown
//! opcode byte, missing/mis-typed or unaligned payload, out-of-range or
//! mid-instruction branch target, zero-argument non-static invoke, invalid or
//! overlapping try range, inverted register counts), a branch target that is
//! not an instruction start, an unaligned try end, a `try` whose handler is
//! missing, an out-of-range pool reference, and an unresolvable operand
//! (droidsaw's `?`) — returns [`DecompileError::BackendError`] naming the
//! method and the code-unit offset instead of emitting a plausible-looking
//! instruction.
//!
//! Dialect divergences from baksmali, deliberate and documented: labels are
//! `:addr_<hex>` rather than baksmali's `pswitch_`/`try_start_`/… prefixes,
//! and registers are always `vN` (no `pN` parameter spelling). Every operand
//! and directive string is baksmali's.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use droidsaw_dex::annotation::{EncodedAnnotation, EncodedValue};
use droidsaw_dex::decode::{
    ClassData, CodeItem, EncodedMethod, Instruction, PayloadData, PoolIndex,
};
use droidsaw_dex::ids::{
    ClassDefItem, FieldIdx, MethodHandleIdx, MethodIdx, ProtoIdx, StringIdx, TypeIdx,
};
use droidsaw_dex::opcodes::Opcode;
use droidsaw_dex::parser::DexFile;
use droidsaw_dex::smali::fmt_instruction;

use crate::DecompileError;

/// First line of every listing. A documented omission, not a defect.
pub(crate) const HEADER_NOTE: &str =
    "# smali-syntax listing from asc-rs; annotations, static values and debug info are not emitted";

/// Opcodes the audit flagged; every other opcode goes through
/// `fmt_instruction` unchanged.
const OVERRIDDEN: [Opcode; 9] = [
    Opcode::InvokePolymorphic,
    Opcode::InvokePolymorphicRange,
    Opcode::InvokeCustom,
    Opcode::InvokeCustomRange,
    Opcode::ConstMethodHandle,
    Opcode::ConstMethodType,
    // droidsaw's `escape_smali_string` passes non-ASCII through raw;
    // baksmali hex-escapes every non-printable / non-ASCII UTF-16 unit.
    Opcode::ConstString,
    Opcode::ConstStringJumbo,
    // droidsaw folds `ConstHigh16 | ConstWideHigh16` into one arm that
    // never appends `L`; baksmali's `Format21lh` needs it.
    Opcode::ConstWideHigh16,
];

/// DEX `method_handle_type_code` -> baksmali `MethodHandleType` name. Values
/// outside 0..=8 are rejected (baksmali throws `InvalidMethodHandleType`).
const METHOD_HANDLE_KINDS: [&str; 9] = [
    "static-put",
    "static-get",
    "instance-put",
    "instance-get",
    "invoke-static",
    "invoke-instance",
    "invoke-constructor",
    "invoke-direct",
    "invoke-interface",
];

/// Kind `4` = `invoke-static`, the only legal bootstrap handle type.
const KIND_INVOKE_STATIC: u16 = 4;

/// Kinds 0..=3 reference the field pool, 4..=8 the method pool.
const KIND_MAX_FIELD: u16 = 3;

/// The two opcodes whose operand is a string literal, so a `?` inside it is
/// data, not a failed pool lookup.
const CONST_STRING: [Opcode; 2] = [Opcode::ConstString, Opcode::ConstStringJumbo];

/// `class_data_off == 0` (no fields, no methods) — a static borrow instead of
/// an `Option` dance at the single call site.
static EMPTY_CLASS_DATA: ClassData = ClassData {
    static_fields: Vec::new(),
    instance_fields: Vec::new(),
    direct_methods: Vec::new(),
    virtual_methods: Vec::new(),
};

/// Access-flag table per scope, in dexlib2 `AccessFlags` enum order (which is
/// the bit order baksmali prints in). `SYNCHRONIZED`/`VOLATILE`/`BRIDGE`/
/// `TRANSIENT`/`VARARGS` share bits across scopes, hence one table each.
const CLASS_FLAGS: &[(u32, &str)] = &[
    (0x0001, "public"),
    (0x0002, "private"),
    (0x0004, "protected"),
    (0x0008, "static"),
    (0x0010, "final"),
    (0x0200, "interface"),
    (0x0400, "abstract"),
    (0x1000, "synthetic"),
    (0x2000, "annotation"),
    (0x4000, "enum"),
];

const FIELD_FLAGS: &[(u32, &str)] = &[
    (0x0001, "public"),
    (0x0002, "private"),
    (0x0004, "protected"),
    (0x0008, "static"),
    (0x0010, "final"),
    (0x0040, "volatile"),
    (0x0080, "transient"),
    (0x1000, "synthetic"),
    (0x4000, "enum"),
];

const METHOD_FLAGS: &[(u32, &str)] = &[
    (0x0001, "public"),
    (0x0002, "private"),
    (0x0004, "protected"),
    (0x0008, "static"),
    (0x0010, "final"),
    (0x0020, "synchronized"),
    (0x0040, "bridge"),
    (0x0080, "varargs"),
    (0x0100, "native"),
    (0x0400, "abstract"),
    (0x0800, "strictfp"),
    (0x1000, "synthetic"),
    (0x10000, "constructor"),
    (0x20000, "declared-synchronized"),
];

/// Where an error happened, for the message prefix.
struct Ctx {
    who: String,
    code_off: u32,
    pc: Option<u32>,
}

fn ctx(who: &str, code_off: u32, pc: Option<u32>) -> Ctx {
    Ctx {
        who: who.to_owned(),
        code_off,
        pc,
    }
}

fn err(c: &Ctx, detail: impl std::fmt::Display) -> DecompileError {
    match c.pc {
        Some(pc) => DecompileError::BackendError(format!(
            "{}: code_item at {:#x} pc {pc}: {detail}",
            c.who, c.code_off
        )),
        None => DecompileError::BackendError(format!("{}: {detail}", c.who)),
    }
}

/// Disassemble one class to a smali-syntax listing.
///
/// `method` filters by exact method name (every overload matches). Every
/// failure is a [`DecompileError::BackendError`] carrying the method name and,
/// where the failure is positional, the code-unit offset.
pub(crate) fn render_class(
    dex: &DexFile,
    bytes: &[u8],
    descriptor: &str,
    class_def: &ClassDefItem,
    method: Option<&str>,
) -> Result<String, DecompileError> {
    let mut out = String::with_capacity(4096);
    let _ = writeln!(out, "{HEADER_NOTE}");
    let c = ctx(descriptor, 0, None);

    let _ = writeln!(
        out,
        ".class {}{}",
        flag_prefix(class_def.access_flags, CLASS_FLAGS),
        type_at(dex, class_def.class_idx, &c)?
    );
    if let Some(super_idx) = class_def.superclass_idx {
        let _ = writeln!(out, ".super {}", type_at(dex, super_idx, &c)?);
    }
    for iface in dex
        .type_lists
        .get(&class_def.interfaces_off)
        .into_iter()
        .flatten()
    {
        let _ = writeln!(out, ".implements {}", type_at(dex, *iface, &c)?);
    }

    let class_data = if class_def.class_data_off == 0 {
        &EMPTY_CLASS_DATA
    } else {
        dex.class_datas
            .get(&class_def.class_data_off)
            .ok_or_else(|| {
                DecompileError::BackendError(format!(
                    "class {descriptor}: class_data_off {:#x} missing from parse",
                    class_def.class_data_off
                ))
            })?
    };

    // A name filter means the caller wants that method only; the field
    // inventory would be noise, so it is dropped.
    if method.is_none() {
        for f in class_data
            .static_fields
            .iter()
            .chain(class_data.instance_fields.iter())
        {
            let field = dex
                .fields
                .get(f.field_idx.0 as usize)
                .ok_or_else(|| err(&c, format!("field id {} out of range", f.field_idx.0)))?;
            let _ = writeln!(
                out,
                ".field {}{}:{}",
                flag_prefix(f.access_flags, FIELD_FLAGS),
                string_at(dex, field.name_idx, &c)?,
                type_at(dex, field.type_idx, &c)?
            );
        }
    }

    for em in class_data
        .direct_methods
        .iter()
        .chain(class_data.virtual_methods.iter())
    {
        render_method(&mut out, dex, bytes, descriptor, em, method)?;
    }

    Ok(out)
}

/// One `.method … .end method` block, or nothing when `filter` is set and the
/// name does not match.
fn render_method(
    out: &mut String,
    dex: &DexFile,
    bytes: &[u8],
    descriptor: &str,
    em: &EncodedMethod,
    filter: Option<&str>,
) -> Result<(), DecompileError> {
    let bootstrap = ctx(descriptor, em.code_off, None);
    let method_id = dex.methods.get(em.method_idx.0 as usize).ok_or_else(|| {
        err(
            &bootstrap,
            format!("method id {} out of range", em.method_idx.0),
        )
    })?;
    let name = string_at(dex, method_id.name_idx, &bootstrap)?;
    if filter.is_some_and(|f| f != name) {
        return Ok(());
    }

    let who = format!("{descriptor}->{name}");
    let c = ctx(&who, em.code_off, None);
    let proto = dex
        .protos
        .get(method_id.proto_idx.0 as usize)
        .ok_or_else(|| {
            err(
                &c,
                format!("proto id {} out of range", method_id.proto_idx.0),
            )
        })?;

    let _ = writeln!(
        out,
        ".method {}{name}({}){}",
        flag_prefix(em.access_flags, METHOD_FLAGS),
        type_list_at(dex, proto.parameters_off, &c)?,
        type_at(dex, proto.return_type_idx, &c)?,
    );

    if em.code_off != 0 {
        let code = dex.code_items.get(&em.code_off).ok_or_else(|| {
            err(
                &c,
                format!("code_item at {:#x} missing from parse", em.code_off),
            )
        })?;
        let _ = writeln!(out, "    .registers {}", code.registers_size);
        let _ = writeln!(out);
        render_body(out, dex, bytes, &who, em.code_off, code)?;
    }
    out.push_str(".end method\n\n");
    Ok(())
}

/// Method body: labels, `.catch`/`.catchall`, instructions, then the payload
/// directives.
fn render_body(
    out: &mut String,
    dex: &DexFile,
    bytes: &[u8],
    who: &str,
    code_off: u32,
    code: &CodeItem,
) -> Result<(), DecompileError> {
    let c = ctx(who, code_off, None);
    if let Some(v) = code.invariant_violations.first() {
        return Err(err(
            &c,
            format!(
                "code_item has {} code-item invariant violation(s), first: {v:?}",
                code.invariant_violations.len()
            ),
        ));
    }

    let insn_starts: BTreeSet<u32> = code.instructions.iter().map(|i| i.addr).collect();
    let last_addr = code
        .instructions
        .last()
        .map_or(0, |i| i.addr + u32::from(i.size));

    let labels = collect_labels(code, &insn_starts, last_addr);
    let catches = collect_catches(dex, &c, code, &insn_starts, last_addr)?;
    // Payload addresses print their own `:label` line with the directive.
    let payload_addrs: BTreeSet<u32> = code.payloads.keys().copied().collect();

    for insn in &code.instructions {
        if payload_addrs.contains(&insn.addr) {
            continue;
        }
        if labels.contains(&insn.addr) {
            let _ = writeln!(out, "    :{}", label(insn.addr));
        }
        if let Some(dirs) = catches.get(&insn.addr) {
            for d in dirs {
                let _ = writeln!(out, "    {d}");
            }
        }
        let _ = writeln!(out, "    {}", fmt_one(dex, bytes, &c, code_off, insn)?);
    }

    // Labels past the last instruction (try ranges covering end-of-method)
    // are flushed here — once. droidsaw's flush printed them twice, and it
    // also re-printed a payload address sitting at or past the end of the
    // body, which the payload loop below already emits.
    for addr in labels
        .iter()
        .filter(|a| **a >= last_addr && !payload_addrs.contains(a))
    {
        let _ = writeln!(out, "    :{}", label(*addr));
        if let Some(dirs) = catches.get(addr) {
            for d in dirs {
                let _ = writeln!(out, "    {d}");
            }
        }
    }

    for (addr, payload) in &code.payloads {
        let _ = writeln!(out);
        let _ = writeln!(out, "    :{}", label(*addr));
        match payload {
            PayloadData::PackedSwitch { first_key, targets } => {
                let _ = writeln!(
                    out,
                    "    .packed-switch {}",
                    signed_hex(i64::from(*first_key))
                );
                for t in targets {
                    let _ = writeln!(out, "        :{}", label(*t));
                }
                let _ = writeln!(out, "    .end packed-switch");
            }
            PayloadData::SparseSwitch { keys, targets } => {
                let _ = writeln!(out, "    .sparse-switch");
                for (k, t) in keys.iter().zip(targets.iter()) {
                    let _ = writeln!(
                        out,
                        "        {} -> :{}",
                        signed_hex(i64::from(*k)),
                        label(*t)
                    );
                }
                let _ = writeln!(out, "    .end sparse-switch");
            }
            PayloadData::FillArrayData {
                element_width,
                data,
            } => {
                let width = usize::from(*element_width);
                if !matches!(width, 1 | 2 | 4 | 8) {
                    return Err(err(
                        &c,
                        format!("array-data element_width {width} is not in {{1, 2, 4, 8}}"),
                    ));
                }
                let _ = writeln!(out, "    .array-data {element_width}");
                for chunk in data.chunks(width) {
                    let _ = writeln!(out, "        {}", array_element(chunk, width));
                }
                let _ = writeln!(out, "    .end array-data");
            }
        }
    }
    Ok(())
}

/// Every address that needs a `:label`, in one namespace: branch targets,
/// payload addresses, switch payload targets, try start/end and handler
/// addresses. Addresses past the last instruction are the legitimate
/// `try_end` labels of a try range reaching end-of-method (baksmali's
/// `EndTryLabelMethodItem`); anything else in that range is a dangling
/// reference and is dropped, exactly as droidsaw drops it.
fn collect_labels(code: &CodeItem, insn_starts: &BTreeSet<u32>, last_addr: u32) -> BTreeSet<u32> {
    let mut labels = BTreeSet::new();
    for insn in &code.instructions {
        if let Some(t) = insn.target {
            labels.insert(t);
        }
    }
    labels.extend(code.payloads.keys().copied());
    for payload in code.payloads.values() {
        match payload {
            PayloadData::PackedSwitch { targets, .. }
            | PayloadData::SparseSwitch { targets, .. } => {
                labels.extend(targets.iter().copied());
            }
            PayloadData::FillArrayData { .. } => {}
        }
    }
    for t in &code.tries {
        labels.insert(t.start_addr);
        labels.insert(t.start_addr + u32::from(t.insn_count));
        if let Some(h) = code.catch_handlers.get(t.handler_idx) {
            labels.extend(h.catches.iter().map(|c| c.handler_addr));
            labels.extend(h.catch_all_addr);
        }
    }
    labels.retain(|a| *a >= last_addr || insn_starts.contains(a) || code.payloads.contains_key(a));
    labels
}

/// `.catch` / `.catchall` directives keyed by the address they attach to:
/// the exclusive end of the protected range, i.e. the `try_end` label.
fn collect_catches(
    dex: &DexFile,
    c: &Ctx,
    code: &CodeItem,
    insn_starts: &BTreeSet<u32>,
    last_addr: u32,
) -> Result<BTreeMap<u32, Vec<String>>, DecompileError> {
    let mut out: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for t in &code.tries {
        let end = t.start_addr + u32::from(t.insn_count);
        let Some(h) = code.catch_handlers.get(t.handler_idx) else {
            return Err(err(
                c,
                format!(
                    "try_item at {} references catch handler {} which is not in the handler list",
                    t.start_addr, t.handler_idx
                ),
            ));
        };
        if end < last_addr && !insn_starts.contains(&end) {
            return Err(err(
                c,
                format!(
                    "try range [{}..{end}) is not instruction-aligned",
                    t.start_addr
                ),
            ));
        }
        for cc in &h.catches {
            out.entry(end).or_default().push(format!(
                ".catch {} {{:{} .. :{}}} :{}",
                type_at(dex, cc.exception_type, c)?,
                label(t.start_addr),
                label(end),
                label(cc.handler_addr)
            ));
        }
        if let Some(all) = h.catch_all_addr {
            out.entry(end).or_default().push(format!(
                ".catchall {{:{} .. :{}}} :{}",
                label(t.start_addr),
                label(end),
                label(all)
            ));
        }
    }
    Ok(out)
}

/// One instruction line, without the leading indent.
fn fmt_one(
    dex: &DexFile,
    bytes: &[u8],
    c: &Ctx,
    code_off: u32,
    insn: &Instruction,
) -> Result<String, DecompileError> {
    if !OVERRIDDEN.contains(&insn.op) {
        let text = fmt_instruction(insn, dex);
        if unresolved(&text, insn) {
            return Err(err(c, format!("unresolved operand in `{text}`")));
        }
        return Ok(text);
    }
    let pc = ctx(&c.who, code_off, Some(insn.addr));
    // The mnemonic is always droidsaw's; only the operand text is ours.
    let mnemonic = insn.op.mnemonic();
    let operands = match insn.op {
        Opcode::InvokeCustom | Opcode::InvokeCustomRange => {
            let regs = if insn.op == Opcode::InvokeCustom {
                reg_list(insn)
            } else {
                reg_range(insn)
            };
            format!("{regs}, {}", call_site_ref(dex, &pc, insn)?)
        }
        Opcode::InvokePolymorphic | Opcode::InvokePolymorphicRange => {
            // droidsaw classifies the 45cc / 4rcc `4rcc` payload with its
            // generic classifier, so the proto can come back as a Method
            // ref; baksmali's `Format45cc`/`Format4rcc` case always reads
            // reference2 (code unit 3) as METHOD_PROTO.
            let m = match insn.pool_idx {
                Some(PoolIndex::Method(m)) | Some(PoolIndex::MethodAndProto(m, _)) => m,
                _ => return Err(err(&pc, "invoke-polymorphic without a method ref")),
            };
            let p = ProtoIdx(raw_unit(bytes, code_off, insn, 3, &pc)?);
            let regs = if insn.op == Opcode::InvokePolymorphic {
                reg_list(insn)
            } else {
                reg_range(insn)
            };
            format!(
                "{regs}, {}, {}",
                method_ref(dex, m, &pc)?,
                proto_ref(dex, p, &pc)?
            )
        }
        Opcode::ConstMethodHandle => {
            let idx = raw_unit(bytes, code_off, insn, 1, &pc)?;
            format!(
                "v{}, {}",
                insn.dst.unwrap_or(0),
                method_handle_ref(dex, MethodHandleIdx(idx), &pc)?
            )
        }
        Opcode::ConstMethodType => {
            let idx = raw_unit(bytes, code_off, insn, 1, &pc)?;
            format!(
                "v{}, {}",
                insn.dst.unwrap_or(0),
                proto_ref(dex, ProtoIdx(idx), &pc)?
            )
        }
        Opcode::ConstString | Opcode::ConstStringJumbo => {
            let Some(PoolIndex::String(s)) = insn.pool_idx else {
                return Err(err(&pc, "const-string without a string ref"));
            };
            let value = string_at(dex, s, &pc)?;
            format!(
                "v{}, \"{}\"",
                insn.dst.unwrap_or(0),
                escape_smali_string(&value)
            )
        }
        // baksmali `Format21lh` -> `writeLiteral` ->
        // `LongRenderer.writeSignedIntOrLongTo`: `L` exactly when the value
        // leaves the `i32` range. `const-wide` is the same instruction
        // format but goes through `LongRenderer.writeTo`, which always
        // appends `L` — droidsaw already spells that one that way.
        Opcode::ConstWideHigh16 => {
            format!("v{}, {}", insn.dst.unwrap_or(0), wide_literal(insn.literal))
        }
        _ => unreachable!("OVERRIDDEN lists exactly the opcodes handled above"),
    };
    Ok(format!("{mnemonic} {operands}"))
}

/// True when the rendered operand contains a `?` that is not part of a
/// string literal — droidsaw's marker for an unresolvable pool reference.
fn unresolved(text: &str, insn: &Instruction) -> bool {
    !CONST_STRING.contains(&insn.op) && text.contains('?')
}

/// `{vC, vD, …}` for the 35c/45cc register list.
fn reg_list(insn: &Instruction) -> String {
    let regs: Vec<String> = insn
        .src
        .as_slice()
        .iter()
        .map(|r| format!("v{r}"))
        .collect();
    format!("{{{}}}", regs.join(", "))
}

/// `{vC .. vN}` for the 3rc/4rcc range form; `{}` when the count is zero
/// (baksmali `writeInvokeRangeRegisters`).
fn reg_range(insn: &Instruction) -> String {
    let count = insn.literal;
    let first = insn.src.raw_at(0);
    if count <= 0 {
        return "{}".to_string();
    }
    let last = u32::from(first) + (count as u32) - 1;
    format!("{{v{first} .. v{last}}}")
}

/// Code unit `unit` of `insn`, re-read from the DEX bytes: `insns` starts at
/// `code_off + 16` and every unit is little-endian.
///
/// `const-method-handle` / `const-method-type` are 21c and
/// `invoke-polymorphic` / `invoke-polymorphic/range` are 45cc / 4rcc — for all
/// five droidsaw's pool classifier can file the second operand as a Method
/// ref, and baksmali reads it as METHOD_HANDLE / METHOD_PROTO instead. The
/// wire bytes are the authority.
fn raw_unit(
    bytes: &[u8],
    code_off: u32,
    insn: &Instruction,
    unit: u32,
    c: &Ctx,
) -> Result<u32, DecompileError> {
    let byte_off = insn
        .addr
        .checked_add(unit)
        .map(|u| u64::from(u) * 2)
        .and_then(|delta| (code_off as u64).checked_add(16)?.checked_add(delta));
    let Some(byte_off) = byte_off else {
        return Err(err(c, "instruction byte offset overflow"));
    };
    let Ok(byte_off) = usize::try_from(byte_off) else {
        return Err(err(c, "instruction byte offset does not fit usize"));
    };
    let lo = *bytes
        .get(byte_off)
        .ok_or_else(|| err(c, "instruction operand reads past the DEX file"))?;
    let hi = *bytes
        .get(byte_off + 1)
        .ok_or_else(|| err(c, "truncated instruction operand"))?;
    Ok(u32::from(lo) | u32::from(hi) << 8)
}

/// `call_site_N("name", (P)R, extra…)@bootstrap`.
fn call_site_ref(dex: &DexFile, c: &Ctx, insn: &Instruction) -> Result<String, DecompileError> {
    let Some(PoolIndex::CallSite(cs)) = insn.pool_idx else {
        return Err(err(c, "invoke-custom without a call_site ref"));
    };
    let n = cs.0;
    let off = *dex
        .call_site_ids
        .get(n as usize)
        .ok_or_else(|| err(c, format!("call_site index {n} out of range")))?;
    let values = dex
        .encoded_arrays
        .get(&off)
        .ok_or_else(|| err(c, format!("call_site {n} has no encoded_array at {off:#x}")))?;
    if values.len() < 3 {
        return Err(err(
            c,
            format!("call_site {n} has {} entries, need >= 3", values.len()),
        ));
    }
    let (
        Some(EncodedValue::MethodHandle(boot)),
        Some(EncodedValue::String(sam)),
        Some(EncodedValue::MethodType(mt)),
    ) = (values.first(), values.get(1), values.get(2))
    else {
        return Err(err(
            c,
            format!("call_site {n} header is not [method_handle, string, method_type]"),
        ));
    };
    let boot_handle = dex.method_handles.get(boot.0 as usize).ok_or_else(|| {
        err(
            c,
            format!("call_site {n} bootstrap method_handle {boot} out of range"),
        )
    })?;
    if boot_handle.kind != KIND_INVOKE_STATIC {
        return Err(err(
            c,
            format!(
                "call_site {n} bootstrap method_handle kind {} is not invoke-static",
                boot_handle.kind
            ),
        ));
    }
    let bootstrap = method_ref(dex, MethodIdx(u32::from(boot_handle.field_or_method_id)), c)?;

    let mut args = vec![
        format!("\"{}\"", escape_smali_string(&string_at(dex, *sam, c)?)),
        proto_ref(dex, *mt, c)?,
    ];
    for (slot, v) in values.iter().enumerate().skip(3) {
        args.push(call_site_arg(dex, v, c, n, slot)?);
    }
    Ok(format!("call_site_{n}({})@{bootstrap}", args.join(", ")))
}

/// One `invoke-custom` extra argument, baksmali's
/// `DexFormattedWriter.writeEncodedValue`: `Boolean.toString`,
/// `String.format("0x%x", …)` for every integral width, `Float.toString`,
/// `Double.toString`, `null`, the reference forms, and `writeAnnotation` /
/// `writeArray` recursions.
fn call_site_arg(
    dex: &DexFile,
    v: &EncodedValue,
    c: &Ctx,
    n: u32,
    slot: usize,
) -> Result<String, DecompileError> {
    let at = |detail: String| err(c, format!("call_site {n} slot {slot}: {detail}"));
    match v {
        EncodedValue::Boolean(b) => Ok(b.to_string()),
        // `String.format("0x%x", …)`: the i32/i64 sign-extends to u32/u64, so a
        // negative value prints as its unsigned 32/64-bit pattern.
        EncodedValue::Byte(b) => Ok(format!("0x{:x}", *b as u32)),
        EncodedValue::Char(ch) => Ok(format!("0x{:x}", *ch as u32)),
        EncodedValue::Short(s) => Ok(format!("0x{:x}", *s as u32)),
        EncodedValue::Int(i) => Ok(format!("0x{:x}", *i as u32)),
        EncodedValue::Long(l) => Ok(format!("0x{:x}", *l as u64)),
        EncodedValue::Float(f) => Ok(f.to_string()),
        EncodedValue::Double(d) => Ok(d.to_string()),
        EncodedValue::Null => Ok("null".to_string()),
        EncodedValue::String(s) => Ok(format!(
            "\"{}\"",
            escape_smali_string(&string_at(dex, *s, c).map_err(|e| at(e.to_string()))?)
        )),
        EncodedValue::Type(t) => type_at(dex, *t, c).map_err(|e| at(e.to_string())),
        EncodedValue::Field(f) => field_ref(dex, *f, c).map_err(|e| at(e.to_string())),
        // An enum value renders exactly like a field reference.
        EncodedValue::Enum(f) => field_ref(dex, *f, c).map_err(|e| at(e.to_string())),
        EncodedValue::Method(m) => method_ref(dex, *m, c).map_err(|e| at(e.to_string())),
        EncodedValue::MethodType(p) => proto_ref(dex, *p, c).map_err(|e| at(e.to_string())),
        EncodedValue::MethodHandle(h) => {
            method_handle_ref(dex, *h, c).map_err(|e| at(e.to_string()))
        }
        EncodedValue::Array(items) => {
            let parts = items
                .iter()
                .map(|i| call_site_arg(dex, i, c, n, slot))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| at(e.to_string()))?;
            Ok(format!("{{{}}}", parts.join(", ")))
        }
        EncodedValue::Annotation(a) => {
            annotation_literal(dex, a, c, n, slot).map_err(|e| at(e.to_string()))
        }
    }
}

/// baksmali `writeAnnotation`: `Ltype;{k=v, …}` with the same value grammar.
fn annotation_literal(
    dex: &DexFile,
    a: &EncodedAnnotation,
    c: &Ctx,
    n: u32,
    slot: usize,
) -> Result<String, DecompileError> {
    let type_desc = type_at(dex, a.type_idx, c)?;
    let mut parts = Vec::with_capacity(a.elements.len());
    for (name, value) in &a.elements {
        let key = string_at(dex, *name, c)?;
        parts.push(format!("{key}={}", call_site_arg(dex, value, c, n, slot)?));
    }
    Ok(format!("{type_desc}{{{}}}", parts.join(", ")))
}

/// `<kind>@<member>` — baksmali `DexFormattedWriter.writeMethodHandle`, e.g.
/// `invoke-constructor@Lfoo;-><init>()V`. Shared by `const-method-handle` and
/// by `invoke-custom` call-site arguments.
fn method_handle_ref(dex: &DexFile, h: MethodHandleIdx, c: &Ctx) -> Result<String, DecompileError> {
    let handle = dex
        .method_handles
        .get(h.0 as usize)
        .ok_or_else(|| err(c, format!("method_handle index {h} out of range")))?;
    let kind = METHOD_HANDLE_KINDS
        .get(handle.kind as usize)
        .ok_or_else(|| {
            err(
                c,
                format!("unknown method_handle_type_code {:#x}", handle.kind),
            )
        })?;
    let member = if handle.kind <= KIND_MAX_FIELD {
        field_ref(dex, FieldIdx(u32::from(handle.field_or_method_id)), c)?
    } else {
        method_ref(dex, MethodIdx(u32::from(handle.field_or_method_id)), c)?
    };
    Ok(format!("{kind}@{member}"))
}

fn field_ref(dex: &DexFile, f: FieldIdx, c: &Ctx) -> Result<String, DecompileError> {
    let field = dex
        .fields
        .get(f.0 as usize)
        .ok_or_else(|| err(c, format!("field id {f} out of range")))?;
    Ok(format!(
        "{}->{}:{}",
        type_at(dex, field.class_idx, c)?,
        string_at(dex, field.name_idx, c)?,
        type_at(dex, field.type_idx, c)?
    ))
}

fn method_ref(dex: &DexFile, m: MethodIdx, c: &Ctx) -> Result<String, DecompileError> {
    let method = dex
        .methods
        .get(m.0 as usize)
        .ok_or_else(|| err(c, format!("method id {m} out of range")))?;
    Ok(format!(
        "{}->{}{}",
        type_at(dex, method.class_idx, c)?,
        string_at(dex, method.name_idx, c)?,
        proto_ref(dex, method.proto_idx, c)?
    ))
}

/// `(params)return` — a method proto *with* parentheses, which is what the
/// `method_ref`, `invoke-polymorphic` and `const-method-type` operands need.
fn proto_ref(dex: &DexFile, p: ProtoIdx, c: &Ctx) -> Result<String, DecompileError> {
    let proto = dex
        .protos
        .get(p.0 as usize)
        .ok_or_else(|| err(c, format!("proto id {p} out of range")))?;
    Ok(format!(
        "({}){}",
        type_list_at(dex, proto.parameters_off, c)?,
        type_at(dex, proto.return_type_idx, c)?
    ))
}

fn type_list_at(dex: &DexFile, off: u32, c: &Ctx) -> Result<String, DecompileError> {
    if off == 0 {
        return Ok(String::new());
    }
    let list = dex
        .type_lists
        .get(&off)
        .ok_or_else(|| err(c, format!("type_list at {off:#x} missing")))?;
    list.iter()
        .map(|t| type_at(dex, *t, c))
        .collect::<Result<Vec<_>, _>>()
        .map(|v| v.concat())
}

fn type_at(dex: &DexFile, t: TypeIdx, c: &Ctx) -> Result<String, DecompileError> {
    dex.get_type_descriptor(t)
        .map(|s| s.to_owned())
        .map_err(|_| err(c, format!("type id {t} out of range")))
}

fn string_at(dex: &DexFile, s: StringIdx, c: &Ctx) -> Result<String, DecompileError> {
    dex.get_string(s)
        .map(|v| v.to_owned())
        .map_err(|_| err(c, format!("string id {s} out of range")))
}

/// Space-joined flag words; empty when no bit is set.
fn access_flags(flags: u32, table: &[(u32, &str)]) -> String {
    table
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join(" ")
}

/// [`access_flags`] plus a separating space, or nothing when no bit is set
/// (avoids `.method  name` with a doubled space).
fn flag_prefix(flags: u32, table: &[(u32, &str)]) -> String {
    let f = access_flags(flags, table);
    if f.is_empty() { f } else { f + " " }
}

/// Address-based label. baksmali uses `pswitch_`/`try_start_`/… prefixes; one
/// namespace keeps payload, try and branch targets unambiguous.
fn label(addr: u32) -> String {
    format!("addr_{addr:x}")
}

/// baksmali `StringUtils.escapeString`: printable ASCII passes through
/// (with `"` `'` `\` backslash-escaped), `\n` `\r` `\t` are named, and
/// everything else — control characters *and* all non-ASCII — becomes
/// `\uXXXX` per UTF-16 code unit.
fn escape_smali_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for unit in value.encode_utf16() {
        match unit {
            0x20..=0x7e => {
                if unit == u16::from(b'"') || unit == u16::from(b'\'') || unit == u16::from(b'\\') {
                    out.push('\\');
                }
                out.push(char::from(u8::try_from(unit).unwrap_or(b'?')));
            }
            0x0a => out.push_str("\\n"),
            0x0d => out.push_str("\\r"),
            0x09 => out.push_str("\\t"),
            _ => {
                let _ = write!(out, "\\u{unit:04x}");
            }
        }
    }
    out
}

/// One `.array-data` element — baksmali `ArrayDataMethodItem` fed by
/// `LongRenderer.writeSignedIntOrLongTo`:
///
/// * little-endian decode, signed, of width 1/2/4/8 (the caller rejects any
///   other width before reaching here);
/// * the literal itself from [`wide_literal`], which owns the signed-hex
///   spelling and the `i32`-range `L` rule;
/// * then the width suffix: `t` for 1, `s` for 2, nothing for 4 and 8.
fn array_element(chunk: &[u8], width: usize) -> String {
    let value: i64 = match width {
        1 => i64::from(chunk.first().copied().unwrap_or(0) as i8),
        2 => {
            let mut bytes = [0u8; 2];
            for (dst, src) in bytes.iter_mut().zip(chunk) {
                *dst = *src;
            }
            i64::from(i16::from_le_bytes(bytes))
        }
        4 => {
            let mut bytes = [0u8; 4];
            for (dst, src) in bytes.iter_mut().zip(chunk) {
                *dst = *src;
            }
            i64::from(i32::from_le_bytes(bytes))
        }
        8 => {
            let mut bytes = [0u8; 8];
            for (dst, src) in bytes.iter_mut().zip(chunk) {
                *dst = *src;
            }
            i64::from_le_bytes(bytes)
        }
        _ => 0,
    };
    let mut out = wide_literal(value);
    match width {
        1 => out.push('t'),
        2 => out.push('s'),
        _ => {}
    }
    out
}

/// Signed hex as baksmali renders literals and switch keys: `0x0`, `0x7f`,
/// `-0x1`. droidsaw printed switch keys with `{:#x}`, so `-1` came out as
/// `0xffffffff`.
fn signed_hex(value: i64) -> String {
    if value < 0 {
        format!("-0x{:x}", value.unsigned_abs())
    } else {
        format!("0x{value:x}")
    }
}

/// dexlib2 `LongRenderer.writeSignedIntOrLongTo`, which baksmali's
/// `Format21lh` (`const-wide/high16`) and `.array-data` elements use:
/// signed hex, then `L` only when the value leaves the `i32` range.
/// `const-wide` is the same instruction format but renders through
/// `LongRenderer.writeTo`, which always appends `L`.
fn wide_literal(value: i64) -> String {
    let mut out = signed_hex(value);
    if value > i64::from(i32::MAX) || value < i64::from(i32::MIN) {
        out.push('L');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_matches_baksmali_for_ascii() {
        assert_eq!(escape_smali_string("abc/xyz-1.2"), "abc/xyz-1.2");
        assert_eq!(escape_smali_string("say \"hi\""), "say \\\"hi\\\"");
        assert_eq!(escape_smali_string("it's"), "it\\'s");
        assert_eq!(escape_smali_string("a\\b"), "a\\\\b");
        let text = escape_smali_string("l1\nl2\r\tx");
        assert_eq!(text, String::from("l1\\nl2\\r") + "\\tx");
    }

    #[test]
    fn escape_hexes_every_non_ascii_and_control_unit() {
        // baksmali escapes all non-ASCII, not just control characters.
        assert_eq!(escape_smali_string("h\u{e9}llo"), "h\\u00e9llo");
        assert_eq!(escape_smali_string("\0"), "\\u0000");
        assert_eq!(escape_smali_string("\u{7f}"), "\\u007f");
        // Non-BMP becomes one escape per UTF-16 unit (surrogate pair).
        assert_eq!(escape_smali_string("\u{1f600}"), "\\ud83d\\ude00");
    }

    #[test]
    fn signed_hex_is_signed_and_unpadded() {
        assert_eq!(signed_hex(0), "0x0");
        assert_eq!(signed_hex(127), "0x7f");
        assert_eq!(signed_hex(-1), "-0x1");
        assert_eq!(signed_hex(-2), "-0x2");
        assert_eq!(signed_hex(i64::from(i32::MIN)), "-0x80000000");
        assert_eq!(signed_hex(i64::MIN), "-0x8000000000000000");
    }

    #[test]
    fn array_elements_are_signed_little_endian_with_baksmali_suffixes() {
        // width 1: signed byte + `t`
        assert_eq!(array_element(&[0x01], 1), "0x1t");
        assert_eq!(array_element(&[0x7f], 1), "0x7ft");
        assert_eq!(array_element(&[0x80], 1), "-0x80t");
        // width 2: signed short + `s`
        assert_eq!(array_element(&[0xff, 0x7f], 2), "0x7fffs");
        assert_eq!(array_element(&[0x00, 0x80], 2), "-0x8000s");
        // width 4: signed int, no suffix
        assert_eq!(array_element(&[0xff, 0xff, 0xff, 0xff], 4), "-0x1");
        assert_eq!(array_element(&[0x78, 0x56, 0x34, 0x12], 4), "0x12345678");
        // width 8: `L` only when the value does not fit in i32 (baksmali's
        // `writeSignedIntOrLongTo` test is `val > Integer.MAX_VALUE`, so a
        // width-8 element inside the i32 range prints exactly like width 4).
        assert_eq!(array_element(&[0x01, 0, 0, 0, 0, 0, 0, 0], 8), "0x1");
        assert_eq!(
            array_element(&[0x00, 0x00, 0x00, 0x80, 0, 0, 0, 0], 8),
            "0x80000000L"
        );
        assert_eq!(
            array_element(&[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0], 8),
            "0xffffffffL"
        );
        assert_eq!(
            array_element(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 8),
            "-0x1"
        );
    }

    #[test]
    fn wide_literals_get_l_only_outside_the_i32_range() {
        // dexlib2 LongRenderer.writeSignedIntOrLongTo, the writer baksmali
        // routes const-wide/high16 (Format21lh) and .array-data elements
        // through. `const-wide` is the same instruction format but uses
        // LongRenderer.writeTo, which always appends `L`.
        assert_eq!(wide_literal(0), "0x0");
        assert_eq!(wide_literal(i64::from(i32::MAX)), "0x7fffffff");
        assert_eq!(wide_literal(i64::from(i32::MIN)), "-0x80000000");
        assert_eq!(wide_literal(0x0001_0000_0000_0000), "0x1000000000000L");
        assert_eq!(wide_literal(0x0002_0000_0000_0000), "0x2000000000000L");
        assert_eq!(wide_literal(i64::from(i32::MAX) + 1), "0x80000000L");
        assert_eq!(wide_literal(i64::from(i32::MIN) - 1), "-0x80000001L");
    }

    #[test]
    fn label_set_keeps_one_entry_per_address() {
        let mut labels: BTreeSet<u32> = BTreeSet::new();
        labels.insert(0);
        labels.insert(0);
        labels.insert(0x1f);
        let rendered: Vec<String> = labels.iter().map(|a| label(*a)).collect();
        assert_eq!(rendered, vec!["addr_0".to_string(), "addr_1f".to_string()]);
    }

    #[test]
    fn access_flags_follow_baksmali_scope_order() {
        assert_eq!(access_flags(0x0001 | 0x0010, CLASS_FLAGS), "public final");
        assert_eq!(access_flags(0x0001 | 0x0009, METHOD_FLAGS), "public static");
        assert_eq!(access_flags(0x10001, METHOD_FLAGS), "public constructor");
        assert_eq!(access_flags(0x001a, FIELD_FLAGS), "private static final");
        // 0x0040 is `volatile` on a field and `bridge` on a method.
        assert_eq!(access_flags(0x0041, FIELD_FLAGS), "public volatile");
        assert_eq!(access_flags(0x0041, METHOD_FLAGS), "public bridge");
        assert_eq!(access_flags(0, CLASS_FLAGS), "");
    }
}
