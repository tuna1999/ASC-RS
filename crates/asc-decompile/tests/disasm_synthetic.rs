//! Operand-level gate for `ClassDecompiler::disassemble` (Smali syntax).
//!
//! Every expectation is written from the baksmali source
//! (`platform/external/smali` in AOSP) and the Dalvik bytecode spec,
//! never from the tool's output. The failure classes the gate exists for:
//!
//! * **wrong operands** — invoke-custom, invoke-polymorphic,
//!   const-method-handle and const-method-type are the paths the pinned
//!   droidsaw `smali.rs` gets wrong (`?->?(?)?`, a dropped proto, a
//!   method id read where a method_handle / proto id lives);
//! * **silent degradation** — an unknown opcode byte, a missing
//!   payload, a clamped try range or an unresolvable pool reference
//!   must be an `Err` naming the method and code-unit offset, never a
//!   shorter but still-successful listing;
//! * **lossy literals** — `.array-data` elements and switch keys are
//!   *signed*; droidsaw prints `{:#x}` of the raw `i32`.
//!
//! Label spelling, payload-block indentation and `v`-only registers are
//! documented dialect divergences (baksmali uses `:pswitch_0` /
//! `:try_start_0` names and nests payload targets one level deeper), so
//! the gate asserts operand text, structure and line ordering instead.
//!
//! The DEX files come from `tests/common/mod.rs`, whose own correctness
//! is pinned separately by `tests/disasm_builder.rs`.

mod common;

use asc_decompile::{ClassDecompiler, DecompileError, droidsaw::DroidsawBackend};
use common::*;

const GATE: &str = "Lgate/C;";

/// Header comment the contract requires as the first line.
const BANNER: &str =
    "# smali-syntax listing from asc-rs; annotations, static values and debug info are not emitted";

fn disasm(dex: &[u8]) -> Result<String, DecompileError> {
    DroidsawBackend::new().disassemble(dex, GATE, None)
}

fn disasm_one(dex: &[u8], method: &str) -> Result<String, DecompileError> {
    DroidsawBackend::new().disassemble(dex, GATE, Some(method))
}

fn ok(dex: &[u8]) -> String {
    disasm(dex).unwrap_or_else(|e| panic!("disassemble failed: {e}"))
}

fn lines_eq(out: &str, line: &str) -> usize {
    out.lines().filter(|l| *l == line).count()
}

fn contains(out: &str, line: &str) -> bool {
    out.lines().any(|l| l == line)
}

/// Like [`lines_eq`] but ignoring indentation: baksmali indents payload
/// directive targets one level deeper than the renderer does, so the
/// operand gate must not pin the leading whitespace of a body line.
fn trimmed_eq(out: &str, line: &str) -> usize {
    out.lines().filter(|l| l.trim() == line).count()
}

/// Write a 32-bit branch offset into the 31t instruction at code-unit
/// `at` (the two low bytes are `at + 1`, the high bytes `at + 2`).
fn patch_branch32(units: &mut [u16], at: u16, rel: i32) {
    let bits = rel as u32;
    units[at as usize + 1] = (bits & 0xFFFF) as u16;
    units[at as usize + 2] = (bits >> 16) as u16;
}

// ── fixtures ─────────────────────────────────────────────────────────

/// A DEX whose single class `Lgate/C;` is `public`, extends
/// `Ljava/lang/Object;` and declares no members. Pool order:
/// 0 `Lgate/C;`, 1 `Ljava/lang/Object;`, 2 `V`.
fn empty_class() -> DexSpec {
    let mut s = DexSpec::default();
    let cls = s.ty(GATE);
    let object = s.ty("Ljava/lang/Object;");
    let void = s.ty("V");
    s.proto("V", void, &[]);
    s.classes.push(ClassSpec {
        flags: 0x0001,
        class_idx: cls,
        superclass: Some(object),
        interfaces: vec![],
        static_fields: vec![],
        instance_fields: vec![],
        direct_methods: vec![],
        virtual_methods: vec![],
    });
    s
}

/// `empty_class()` plus one `public static g()V` method whose code the
/// caller installs with [`set_code`].
fn with_g() -> DexSpec {
    let mut s = empty_class();
    let g = s.method(0, 0, "g");
    s.classes[0].direct_methods.push(Method {
        name: g,
        flags: 0x0008,
        code: None,
    });
    s
}

fn set_code(s: &mut DexSpec, units: Vec<u16>, registers: u16) {
    s.classes[0].direct_methods[0].code = Some(Code {
        registers,
        ins: 0,
        outs: 0,
        units,
        tries: vec![],
        handlers: vec![],
    });
}

/// Every `invoke-custom` fixture shape, spelled out so the expected text
/// is derivable: bootstrap `LambdaMetafactory.metafactory`, SAM name
/// `run`, instantiated proto `()V`, implementation handle
/// `invoke-constructor C-><init>()V`, extra args `7` and `"captured"`.
struct Lambda {
    spec: DexSpec,
    cs_index: u16,
}

fn lambda() -> Lambda {
    let mut s = empty_class();
    let cls = s.classes[0].class_idx;
    let lmf = s.ty("Ljava/lang/invoke/LambdaMetafactory;");
    let ctor = s.method(cls, 0, "<init>");
    let bootstrap = s.method(lmf, 0, "metafactory");
    s.handles.push(MethodHandle {
        kind: 6, // invoke-constructor
        member: ctor as u16,
    });
    s.handles.push(MethodHandle {
        kind: 4, // invoke-static
        member: bootstrap as u16,
    });
    let name = s.str("run");
    let captured = s.str("captured");
    let runnable = s.ty("Ljava/lang/Runnable;");
    s.proto("Ljava/lang/Runnable;", runnable, &[]); // proto 1 = ()Ljava/lang/Runnable;
    let int_ty = s.ty("I");
    s.proto("I", int_ty, &[]); // proto 2 = ()I (instantiated method type)
    s.call_sites.push(encoded_array(&[
        Ev::MethodHandle(1),
        Ev::Str(name),
        Ev::MethodType(1),
        Ev::MethodHandle(0),
        Ev::MethodType(2),
        Ev::Str(captured),
    ]));
    let g = s.method(0, 0, "g");
    s.classes[0].direct_methods.push(Method {
        name: g,
        flags: 0x0008,
        code: None,
    });
    Lambda {
        spec: s,
        cs_index: 0,
    }
}

// ── class shape ──────────────────────────────────────────────────────

#[test]
fn class_without_members_renders_only_directives() {
    let out = ok(&empty_class().build());
    assert_eq!(
        out,
        format!("{BANNER}\n.class public Lgate/C;\n.super Ljava/lang/Object;\n")
    );
}

#[test]
fn class_header_fields_and_methods_render_in_class_data_order() {
    let mut s = empty_class();
    let cls = s.classes[0].class_idx;
    let iface = s.ty("Lgate/I;");
    let string_ty = s.ty("Ljava/lang/String;");
    let fld = s.field(cls, string_ty, "S");
    // method_ids order: virt(0), dir(1). class_data order: dir then virt.
    let virt = s.method(cls, 0, "virt");
    let dir = s.method(cls, 0, "dir");
    s.classes[0].flags = 0x0011; // public final
    s.classes[0].interfaces = vec![iface];
    s.classes[0].static_fields = vec![FieldSpec {
        idx: fld,
        flags: 0x0009, // public static
    }];
    let code = |registers| {
        Some(Code {
            registers,
            ins: 0,
            outs: 0,
            units: vec![0x000E],
            tries: vec![],
            handlers: vec![],
        })
    };
    s.classes[0].direct_methods = vec![Method {
        name: dir,
        flags: 0x0008,
        code: code(1),
    }];
    s.classes[0].virtual_methods = vec![Method {
        name: virt,
        flags: 0x0001,
        code: code(2),
    }];
    let out = ok(&s.build());
    // Header directives, in the contract's order, with exactly one
    // line each. Blank separator lines are a dialect detail (baksmali
    // puts blank lines between directives; the renderer does not), so
    // they are ignored here.
    let non_empty: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(non_empty[0], BANNER, "banner is the first line:\n{out}");
    assert_eq!(non_empty[1], ".class public final Lgate/C;");
    assert_eq!(non_empty[2], ".super Ljava/lang/Object;");
    assert_eq!(non_empty[3], ".implements Lgate/I;");
    assert_eq!(
        non_empty[4], ".field public static S:Ljava/lang/String;",
        "got:\n{out}"
    );
    // class_data order: direct method first, then virtual.
    let dir_at = non_empty
        .iter()
        .position(|l| l.contains(" dir()V"))
        .expect("direct method");
    let virt_at = non_empty
        .iter()
        .position(|l| l.contains(" virt()V"))
        .expect("virtual method");
    assert!(dir_at < virt_at, "class_data order, got:\n{out}");
    assert_eq!(non_empty[dir_at + 1].trim(), ".registers 1");
    assert_eq!(non_empty[dir_at + 2].trim(), "return-void");
    assert_eq!(non_empty[dir_at + 3], ".end method");
    assert_eq!(non_empty[virt_at + 1].trim(), ".registers 2");
    assert_eq!(out.matches(".end method").count(), 2, "got:\n{out}");
    // Every method with a code item declares .registers once and carries
    // one body instruction; a renderer that dropped or duplicated either
    // would still satisfy the checks above.
    assert_eq!(out.matches(".registers ").count(), 2, "got:\n{out}");
    assert_eq!(out.matches("return-void").count(), 2, "got:\n{out}");
    assert!(out.ends_with('\n'), "trailing newline required");
}

#[test]
fn class_without_superclass_omits_the_super_directive() {
    let mut s = empty_class();
    s.classes[0].superclass = None;
    let out = ok(&s.build());
    assert!(contains(&out, ".class public Lgate/C;"));
    assert!(
        !out.lines().any(|l| l.starts_with(".super")),
        "no superclass -> no .super line, got:\n{out}"
    );
}

#[test]
fn abstract_and_native_methods_have_no_registers_or_body() {
    let mut s = empty_class();
    let cls = s.classes[0].class_idx;
    let abs = s.method(cls, 0, "abs");
    let nat = s.method(cls, 0, "nat");
    let real = s.method(cls, 0, "real");
    s.classes[0].flags = 0x0401; // public abstract
    s.classes[0].virtual_methods = vec![
        Method {
            name: abs,
            flags: 0x0401, // public abstract
            code: None,
        },
        Method {
            name: nat,
            flags: 0x0101, // public native
            code: None,
        },
        Method {
            name: real,
            flags: 0x0001,
            code: Some(Code {
                registers: 1,
                ins: 1,
                outs: 0,
                units: vec![0x000E],
                tries: vec![],
                handlers: vec![],
            }),
        },
    ];
    let out = ok(&s.build());
    assert!(contains(&out, ".class public abstract Lgate/C;"));
    assert!(contains(&out, ".method public abstract abs()V"));
    assert!(contains(&out, ".method public native nat()V"));
    assert!(contains(&out, ".method public real()V"));
    assert_eq!(
        lines_eq(&out, "    .registers 1"),
        1,
        "only the method with code declares .registers, got:\n{out}"
    );
    let abs_block = out
        .split(".method public abstract abs()V")
        .nth(1)
        .expect("abstract method present");
    let abs_block = &abs_block[..abs_block.find(".end method").expect("end")];
    assert!(
        !abs_block.contains(".registers") && !abs_block.contains("return-void"),
        "abstract method must have neither .registers nor a body, got:\n{abs_block}"
    );
    let nat_block = out
        .split(".method public native nat()V")
        .nth(1)
        .expect("native method present");
    let nat_block = &nat_block[..nat_block.find(".end method").expect("end")];
    assert!(
        !nat_block.contains(".registers") && !nat_block.contains("return-void"),
        "native method must have neither .registers nor a body, got:\n{nat_block}"
    );
    assert!(out.ends_with('\n'), "trailing newline required");
}

// ── invoke-custom ────────────────────────────────────────────────────

#[test]
fn invoke_custom_renders_the_full_call_site_grammar() {
    let mut l = lambda();
    let mut units = insn_35c(0xFC, 1, l.cs_index, [0, 0, 0, 0, 0]);
    units.push(0x000E);
    l.spec.classes[0].direct_methods[0].code = Some(Code {
        registers: 1,
        ins: 0,
        outs: 1,
        units,
        tries: vec![],
        handlers: vec![],
    });
    let out = ok(&l.spec.build());
    // ReferenceFormatter.writeCallSiteReference:
    //   call_site_<i>( "name", (params)ret, extra... )@<bootstrap method>
    assert_eq!(
        lines_eq(
            &out,
            "    invoke-custom {v0}, call_site_0(\"run\", ()Ljava/lang/Runnable;, invoke-constructor@Lgate/C;-><init>()V, ()I, \"captured\")@Ljava/lang/invoke/LambdaMetafactory;->metafactory()V"
        ),
        1,
        "call site grammar, got:\n{out}"
    );
    assert!(
        !out.contains("?->?(?)?"),
        "an unresolvable reference is a gate failure, got:\n{out}"
    );
}

#[test]
fn invoke_custom_range_renders_the_same_call_site() {
    let mut l = lambda();
    let mut units = insn_3rc(0xFD, 3, l.cs_index, 0); // {v0 .. v2}
    units.push(0x000E);
    l.spec.classes[0].direct_methods[0].code = Some(Code {
        registers: 3,
        ins: 0,
        outs: 1,
        units,
        tries: vec![],
        handlers: vec![],
    });
    let out = ok(&l.spec.build());
    assert_eq!(
        lines_eq(
            &out,
            "    invoke-custom/range {v0 .. v2}, call_site_0(\"run\", ()Ljava/lang/Runnable;, invoke-constructor@Lgate/C;-><init>()V, ()I, \"captured\")@Ljava/lang/invoke/LambdaMetafactory;->metafactory()V"
        ),
        1,
        "range form, got:\n{out}"
    );
}

#[test]
fn invoke_custom_without_call_site_section_is_an_error() {
    let mut l = lambda();
    // 035 file: no TYPE_CALL_SITE_ID_ITEM / TYPE_METHOD_HANDLE_ITEM rows,
    // so the decoded CallSiteIdx resolves to nothing.
    l.spec.version = "035".into();
    l.spec.hide_post_o_map_entries = true;
    let mut units = insn_35c(0xFC, 1, l.cs_index, [0, 0, 0, 0, 0]);
    units.push(0x000E);
    l.spec.classes[0].direct_methods[0].code = Some(Code {
        registers: 1,
        ins: 0,
        outs: 1,
        units,
        tries: vec![],
        handlers: vec![],
    });
    let err = disasm(&l.spec.build()).expect_err("missing call_site must be an Err");
    let msg = format!("{err:?}");
    assert!(
        msg.contains('g') && msg.to_lowercase().contains("call"),
        "error must name the method and the call site, got: {msg}"
    );
}

#[test]
fn out_of_range_call_site_index_is_an_error() {
    let mut l = lambda();
    let mut units = insn_35c(0xFC, 1, 5, [0, 0, 0, 0, 0]);
    units.push(0x000E);
    l.spec.classes[0].direct_methods[0].code = Some(Code {
        registers: 1,
        ins: 0,
        outs: 1,
        units,
        tries: vec![],
        handlers: vec![],
    });
    let err = disasm(&l.spec.build()).expect_err("OOB call_site index must be an Err");
    let msg = format!("{err:?}");
    assert!(msg.contains('g'), "must name the method, got: {msg}");
    assert!(
        msg.to_lowercase().contains("call"),
        "must mention the call site, got: {msg}"
    );
}

// ── invoke-polymorphic ───────────────────────────────────────────────

#[test]
fn invoke_polymorphic_renders_method_ref_and_proto() {
    let mut s = empty_class();
    let handle_ty = s.ty("Ljava/lang/invoke/MethodHandle;");
    let string_ty = s.ty("Ljava/lang/String;");
    let obj_ty = s.ty("Ljava/lang/Object;");
    let obj_arr_ty = s.ty("[Ljava/lang/Object;");
    // proto 1 is the method's own prototype; proto 2 is the per-call-site
    // prototype (the F45cc unit 3 operand).
    let method_proto = s.proto("[Ljava/lang/Object;", obj_ty, &[obj_arr_ty]);
    let call_site_proto = s.proto("Ljava/lang/String;", string_ty, &[]);
    let invoke_exact = s.method(handle_ty, method_proto, "invokeExact");
    let g = s.method(0, 0, "g");
    s.classes[0].direct_methods.push(Method {
        name: g,
        flags: 0x0008,
        code: None,
    });
    // 45cc: unit 0 = A|G|op (A = arg count, G = 5th register),
    // unit 2 = F|E|D|C. Two args therefore live in C and D.
    let mut units = insn_45cc(
        0xFA,
        2,
        invoke_exact as u16,
        call_site_proto as u16,
        [1, 2, 0, 0, 0],
    );
    units.push(0x000E);
    s.classes[0].direct_methods[0].code = Some(Code {
        registers: 3,
        ins: 0,
        outs: 2,
        units,
        tries: vec![],
        handlers: vec![],
    });
    let out = ok(&s.build());
    assert_eq!(
        trimmed_eq(
            &out,
            "invoke-polymorphic {v1, v2}, Ljava/lang/invoke/MethodHandle;->invokeExact([Ljava/lang/Object;)Ljava/lang/Object;, ()Ljava/lang/String;"
        ),
        1,
        "method ref AND per-call-site proto, got:\n{out}"
    );
}

#[test]
fn invoke_polymorphic_range_renders_method_ref_and_proto() {
    let mut s = empty_class();
    let handle_ty = s.ty("Ljava/lang/invoke/MethodHandle;");
    let string_ty = s.ty("Ljava/lang/String;");
    // The method reference and the per-call-site prototype must be two
    // different rows, or the test cannot tell a correct renderer from one
    // that fell back to `invokeExact`'s own prototype. `DexSpec::proto`
    // dedupes on (shorty, return, params), so the two triples differ.
    let method_proto = s.proto("V", 2, &[]); // proto 1 = ()V
    let call_site_proto = s.proto("Ljava/lang/String;", string_ty, &[]); // proto 2 = ()String
    let invoke_exact = s.method(handle_ty, method_proto, "invokeExact");
    let g = s.method(0, 0, "g");
    s.classes[0].direct_methods.push(Method {
        name: g,
        flags: 0x0008,
        code: None,
    });
    let mut units = insn_4rcc(0xFB, 3, invoke_exact as u16, call_site_proto as u16, 1); // {v1 .. v3}
    units.push(0x000E);
    s.classes[0].direct_methods[0].code = Some(Code {
        registers: 4,
        ins: 0,
        outs: 3,
        units,
        tries: vec![],
        handlers: vec![],
    });
    let out = ok(&s.build());
    assert_eq!(
        trimmed_eq(
            &out,
            "invoke-polymorphic/range {v1 .. v3}, Ljava/lang/invoke/MethodHandle;->invokeExact()V, ()Ljava/lang/String;"
        ),
        1,
        "method ref AND per-call-site proto, got:\n{out}"
    );
}

// ── const-method-handle / const-method-type ──────────────────────────

fn handle_spec() -> DexSpec {
    let mut s = empty_class();
    let cls = s.classes[0].class_idx;
    let int_ty = s.ty("I");
    let string_ty = s.ty("Ljava/lang/String;");
    let fld = s.field(cls, int_ty, "count");
    let obj_to_string = s.method(1, 0, "toString"); // Ljava/lang/Object;->toString -> method 0
    // kinds 0..=3 are field kinds, 4..=8 method kinds
    // (DEX method_handle_type_codes).
    s.handles.push(MethodHandle {
        kind: 0,
        member: fld as u16,
    });
    s.handles.push(MethodHandle {
        kind: 1,
        member: fld as u16,
    });
    s.handles.push(MethodHandle {
        kind: 2,
        member: fld as u16,
    });
    s.handles.push(MethodHandle {
        kind: 3,
        member: fld as u16,
    });
    s.handles.push(MethodHandle {
        kind: 4,
        member: obj_to_string as u16,
    });
    s.handles.push(MethodHandle {
        kind: 5,
        member: obj_to_string as u16,
    });
    s.handles.push(MethodHandle {
        kind: 6,
        member: obj_to_string as u16,
    });
    s.handles.push(MethodHandle {
        kind: 7,
        member: obj_to_string as u16,
    });
    s.handles.push(MethodHandle {
        kind: 8,
        member: obj_to_string as u16,
    });
    s.proto("I", int_ty, &[]); // proto 1 = ()I
    let void_ty = 2u32;
    s.proto("Ljava/lang/String;", void_ty, &[int_ty, string_ty]); // proto 2 = (I Ljava/lang/String;)V
    s
}

#[test]
fn const_method_handle_renders_every_kind() {
    let mut s = handle_spec();
    let mut units = Vec::new();
    for i in 0u16..9 {
        units.extend(insn_21c(0xFE, i, i));
    }
    units.push(0x000E);
    s.classes[0].direct_methods.push(Method {
        name: 0,
        flags: 0x0008,
        code: Some(Code {
            registers: 9,
            ins: 0,
            outs: 0,
            units,
            tries: vec![],
            handlers: vec![],
        }),
    });
    let out = ok(&s.build());
    // dexlib2 MethodHandleType: 0 static-put, 1 static-get,
    // 2 instance-put, 3 instance-get, 4 invoke-static,
    // 5 invoke-instance, 6 invoke-constructor, 7 invoke-direct,
    // 8 invoke-interface.
    for (i, kind, member) in [
        (0, "static-put", "Lgate/C;->count:I"),
        (1, "static-get", "Lgate/C;->count:I"),
        (2, "instance-put", "Lgate/C;->count:I"),
        (3, "instance-get", "Lgate/C;->count:I"),
        (4, "invoke-static", "Ljava/lang/Object;->toString()V"),
        (5, "invoke-instance", "Ljava/lang/Object;->toString()V"),
        (6, "invoke-constructor", "Ljava/lang/Object;->toString()V"),
        (7, "invoke-direct", "Ljava/lang/Object;->toString()V"),
        (8, "invoke-interface", "Ljava/lang/Object;->toString()V"),
    ] {
        assert_eq!(
            trimmed_eq(&out, &format!("const-method-handle v{i}, {kind}@{member}")),
            1,
            "handle kind {kind}, got:\n{out}"
        );
    }
    assert_eq!(
        lines_eq(
            &out,
            "    const-method-handle v8, invoke-interface@Ljava/lang/Object;->toString()V"
        ),
        1,
        "invoke-interface, got:\n{out}"
    );
    assert_eq!(
        lines_eq(
            &out,
            "    const-method-handle v0, static-put@Lgate/C;->count:I"
        ),
        1,
        "field kinds render a field descriptor, got:\n{out}"
    );
    assert_eq!(
        lines_eq(
            &out,
            "    const-method-handle v3, instance-get@Lgate/C;->count:I"
        ),
        1,
        "got:\n{out}"
    );
}

#[test]
fn const_method_handle_with_unknown_kind_is_an_error() {
    let mut s = handle_spec();
    s.handles[4].kind = 9; // not a defined method_handle_type_code
    let mut units = insn_21c(0xFE, 0, 4);
    units.push(0x000E);
    s.classes[0].direct_methods.push(Method {
        name: 0,
        flags: 0x0008,
        code: Some(Code {
            registers: 1,
            ins: 0,
            outs: 0,
            units,
            tries: vec![],
            handlers: vec![],
        }),
    });
    let err = disasm(&s.build()).expect_err("unknown handle kind must be an Err");
    let msg = format!("{err:?}");
    assert!(msg.contains('g'), "must name the method, got: {msg}");
    assert!(
        msg.contains('9') || msg.to_lowercase().contains("kind"),
        "must report the offending kind, got: {msg}"
    );
}

#[test]
fn const_method_handle_with_out_of_range_handle_is_an_error() {
    let mut s = handle_spec();
    let mut units = insn_21c(0xFE, 0, 99);
    units.push(0x000E);
    s.classes[0].direct_methods.push(Method {
        name: 0,
        flags: 0x0008,
        code: Some(Code {
            registers: 1,
            ins: 0,
            outs: 0,
            units,
            tries: vec![],
            handlers: vec![],
        }),
    });
    let err = disasm(&s.build()).expect_err("OOB handle index must be an Err");
    let msg = format!("{err:?}");
    assert!(msg.contains('g'), "must name the method, got: {msg}");
    assert!(
        msg.contains("99"),
        "must report the offending index, got: {msg}"
    );
}

#[test]
fn const_method_type_renders_the_proto() {
    let mut s = handle_spec();
    let mut units = insn_21c(0xFF, 0, 1); // ()I
    units.extend(insn_21c(0xFF, 1, 2)); // (ILjava/lang/String;)V
    units.push(0x000E);
    s.classes[0].direct_methods.push(Method {
        name: 0,
        flags: 0x0008,
        code: Some(Code {
            registers: 2,
            ins: 0,
            outs: 0,
            units,
            tries: vec![],
            handlers: vec![],
        }),
    });
    let out = ok(&s.build());
    assert_eq!(
        lines_eq(&out, "    const-method-type v0, ()I"),
        1,
        "proto 1, got:\n{out}"
    );
    assert_eq!(
        lines_eq(&out, "    const-method-type v1, (ILjava/lang/String;)V"),
        1,
        "proto 2, got:\n{out}"
    );
}

#[test]
fn const_method_type_with_out_of_range_proto_is_an_error() {
    let mut s = handle_spec();
    let mut units = insn_21c(0xFF, 0, 77);
    units.push(0x000E);
    s.classes[0].direct_methods.push(Method {
        name: 0,
        flags: 0x0008,
        code: Some(Code {
            registers: 1,
            ins: 0,
            outs: 0,
            units,
            tries: vec![],
            handlers: vec![],
        }),
    });
    let err = disasm(&s.build()).expect_err("OOB proto index must be an Err");
    let msg = format!("{err:?}");
    assert!(msg.contains('g'), "must name the method, got: {msg}");
    assert!(
        msg.contains("77"),
        "must report the offending index, got: {msg}"
    );
}

// ── 3rc register ranges ──────────────────────────────────────────────

#[test]
fn range_invoke_renders_start_and_last_register() {
    let mut s = empty_class();
    let many = s.method(0, 0, "many"); // method 0
    let g = s.method(0, 0, "g");
    s.classes[0].direct_methods.push(Method {
        name: g,
        flags: 0x0008,
        code: Some(Code {
            registers: 11,
            ins: 0,
            outs: 0,
            // 6 args cannot be a 35c (max 5) -> must render a range.
            units: {
                let mut u = insn_3rc(0x77, 6, many as u16, 5); // {v5 .. v10}
                u.push(0x000E);
                u
            },
            tries: vec![],
            handlers: vec![],
        }),
    });
    let out = ok(&s.build());
    assert_eq!(
        lines_eq(
            &out,
            "    invoke-static/range {v5 .. v10}, Lgate/C;->many()V"
        ),
        1,
        "6-arg range invoke, got:\n{out}"
    );
}

#[test]
fn range_invoke_with_zero_arg_count_renders_empty_registers() {
    let mut s = empty_class();
    let g = s.method(0, 0, "g");
    s.classes[0].direct_methods.push(Method {
        name: g,
        flags: 0x0008,
        code: Some(Code {
            registers: 4,
            ins: 0,
            outs: 0,
            // AA == 0: baksmali prints `{}` because the register count
            // is zero (the CCCC field is then spec-irrelevant).
            units: {
                let mut u = insn_3rc(0x77, 0, 0, 3);
                u.push(0x000E);
                u
            },
            tries: vec![],
            handlers: vec![],
        }),
    });
    let out = ok(&s.build());
    assert_eq!(
        lines_eq(&out, "    invoke-static/range {}, Lgate/C;->g()V"),
        1,
        "zero-arg range renders {{}}, got:\n{out}"
    );
}

// ── literals ─────────────────────────────────────────────────────────

#[test]
fn high16_and_wide_literals_use_baksmali_signed_hex() {
    let mut s = with_g();
    let mut units = Vec::new();
    units.extend(insn_21h(0x15, 0, 0x0001)); // const/high16 v0
    units.extend(insn_21h(0x19, 1, 0x0002)); // const-wide/high16 v1
    units.extend(insn_21h(0x19, 3, 0x0000)); // const-wide/high16 v3, value 0
    units.extend(insn_51l(0x18, 5, 0x1234_5678)); // const-wide v5
    units.push(0x000E);
    set_code(&mut s, units, 7);
    let out = ok(&s.build());
    // const/high16 widens the 16-bit field by 16 (0x0001 -> 0x10000);
    // baksmali's Format21h renders it through
    // LongRenderer.writeSignedIntOrLongTo, which stays inside the i32 range
    // and so adds no `L`. const-wide/high16 widens by 48 instead, so 0x0002
    // is 0x2000000000000 and leaves the i32 range: the same writer (baksmali
    // Format21lh -> writeLiteral) adds the `L`. `const-wide` is Format51l
    // but goes through LongRenderer.writeTo, which always adds it — droidsaw
    // already spells that one that way.
    assert_eq!(
        lines_eq(&out, "    const/high16 v0, 0x10000"),
        1,
        "const/high16, got:\n{out}"
    );
    assert_eq!(
        lines_eq(&out, "    const-wide/high16 v1, 0x2000000000000L"),
        1,
        "const-wide/high16, got:\n{out}"
    );
    assert_eq!(
        lines_eq(&out, "    const-wide/high16 v3, 0x0"),
        1,
        "a wide literal inside the i32 range takes no `L`, got:\n{out}"
    );
    assert_eq!(
        lines_eq(&out, "    const-wide v5, 0x12345678L"),
        1,
        "const-wide, got:\n{out}"
    );
}

#[test]
fn const_string_escapes_like_baksmali() {
    let mut s = with_g();
    // quote, backslash, newline, tab and U+00E9. (A supplementary
    // character would need CESU-8, which droidsaw's MUTF-8 decoder
    // rejects — see `mutf8.rs` — so the surrogate-pair case is not
    // reachable through the string pool.)
    let raw = "q\"uote \\ back \n\ttab caf\u{e9}";
    let idx = s.str(raw) as u16;
    let mut units = insn_21c(0x1A, 0, idx);
    units.push(0x000E);
    set_code(&mut s, units, 1);
    let out = ok(&s.build());
    // StringUtils.writeEscapedString: printable ASCII passes through
    // (with a backslash before \ " '), \n \r \t get short forms, and
    // every other code unit becomes \uXXXX per UTF-16 unit.
    assert_eq!(
        lines_eq(
            &out,
            "    const-string v0, \"q\\\"uote \\\\ back \\n\\ttab caf\\u00e9\""
        ),
        1,
        "baksmali escaping, got:\n{out}"
    );
}

// ── switch / array payloads ──────────────────────────────────────────

#[test]
fn packed_switch_prints_a_signed_first_key_once() {
    let mut s = with_g();
    let mut units: Vec<u16> = Vec::new();
    units.push(0x0000); // 0 nop, so the switch lands on an odd address
    // 1..3  packed-switch v0; the payload follows immediately at 4.
    // droidsaw reads the payload ident before it skips the
    // pseudo-instruction, and rejects an odd payload_pc, so the payload
    // must be both adjacent and even -> the switch must start odd.
    units.extend(insn_31t(0x2B, 0, 0));
    let payload_at = units.len() as u16; // 4
    // first_key -2; both targets back to addr 0.
    units.extend(packed_switch_payload(-2, &[0, 0]));
    patch_branch32(&mut units, 1, i32::from(payload_at) - 1);
    set_code(&mut s, units, 2);
    let out = ok(&s.build());
    assert_eq!(
        lines_eq(&out, "    .packed-switch -0x2"),
        1,
        "first_key is signed hex, got:\n{out}"
    );
    assert!(
        !out.contains("0xfffffffe"),
        "an unsigned first_key is a gate failure, got:\n{out}"
    );
    assert_eq!(
        lines_eq(&out, &format!("    :addr_{payload_at:x}")),
        1,
        "the payload label is printed exactly once, got:\n{out}"
    );
    assert_eq!(lines_eq(&out, "    .end packed-switch"), 1, "got:\n{out}");
    // A packed-switch target may legitimately coincide with a branch or
    // payload label (both cases above point back at addr 0), so uniqueness
    // is checked over label *definitions* in
    // `every_label_line_is_printed_exactly_once`; here the operand that
    // matters is the switch's own reference to its payload.
    assert_eq!(
        lines_eq(&out, &format!("    packed-switch v0, :addr_{payload_at:x}")),
        1,
        "the switch operand names the payload address, got:\n{out}"
    );
}

#[test]
fn sparse_switch_prints_signed_keys() {
    let mut s = with_g();
    let mut units: Vec<u16> = Vec::new();
    units.push(0x0000); // 0 nop -> the switch lands on an odd address
    units.extend(insn_31t(0x2C, 0, 0)); // 1..3  sparse-switch v0
    let payload_at = units.len() as u16; // 4
    // keys -1 and 0x7fffffff; both targets back to addr 1 (the switch).
    units.extend(sparse_switch_payload(&[-1, 0x7fff_ffff], &[0, 0]));
    patch_branch32(&mut units, 1, i32::from(payload_at) - 1);
    set_code(&mut s, units, 2);
    let out = ok(&s.build());
    assert_eq!(
        out.lines()
            .filter(|l| l.trim() == "-0x1 -> :addr_1")
            .count(),
        1,
        "negative key is signed hex, got:\n{out}"
    );
    assert_eq!(
        out.lines()
            .filter(|l| l.trim() == "0x7fffffff -> :addr_1")
            .count(),
        1,
        "large key, got:\n{out}"
    );
    assert!(
        !out.contains("0xffffffff"),
        "an unsigned key is a gate failure, got:\n{out}"
    );
    assert_eq!(
        lines_eq(&out, &format!("    :addr_{payload_at:x}")),
        1,
        "got:\n{out}"
    );
    assert_eq!(lines_eq(&out, "    .end sparse-switch"), 1, "got:\n{out}");
    assert_eq!(
        lines_eq(&out, &format!("    sparse-switch v0, :addr_{payload_at:x}")),
        1,
        "the switch operand names the payload address, got:\n{out}"
    );
}

#[test]
fn fill_array_data_prints_signed_elements_with_width_suffixes() {
    // One `fill-array-data` + payload per element width, each pair
    // 4-byte aligned (droidsaw reports `UnalignedTableDexPc` for an odd
    // payload_pc). Offsets are patched from the recorded addresses.
    let mut s = with_g();
    let mut units: Vec<u16> = Vec::new();
    let mut switches: Vec<u16> = Vec::new();
    let mut payloads: Vec<u16> = Vec::new();
    for (i, (width, data)) in [
        (1u16, vec![0x80u8, 0x7F]),
        (2, vec![0x00, 0x80, 0xFF, 0xFF]),
        (4, vec![0x00, 0x00, 0x00, 0x80, 0xFF, 0xFF, 0xFF, 0xFF]),
        (
            8,
            vec![
                0, 0, 0, 0, 0, 0, 0, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
            ],
        ),
    ]
    .into_iter()
    .enumerate()
    {
        if units.len().is_multiple_of(2) {
            // pad to an odd switch address so the payload starts even
            units.push(0x0000);
        }
        let sw = units.len() as u16;
        units.extend(insn_31t(0x26, i as u16, 0));
        let pay = units.len() as u16;
        units.extend(array_payload(width, &data));
        switches.push(sw);
        payloads.push(pay);
    }
    for (sw, pay) in switches.iter().zip(&payloads) {
        patch_branch32(&mut units, *sw, i32::from(*pay) - i32::from(*sw));
    }
    units.push(0x000E);
    set_code(&mut s, units, 2);
    let out = ok(&s.build());
    // ArrayDataMethodItem: LongRenderer.writeSignedIntOrLongTo per
    // element (little-endian, signed), then a `t` suffix for width 1, a
    // `s` suffix for width 2 and nothing for width 4; width 8 gets `L`
    // only when the magnitude exceeds the int range.
    for (w, elements) in [
        (1u16, vec!["-0x80t", "0x7ft"]),
        (2, vec!["-0x8000s", "-0x1s"]),
        (4, vec!["-0x80000000", "-0x1"]),
        (8, vec!["-0x8000000000000000L", "0x7fffffffffffffffL"]),
    ] {
        assert_eq!(
            trimmed_eq(&out, &format!(".array-data {w}")),
            1,
            "one .array-data {w} block, got:\n{out}"
        );
        for e in elements {
            assert!(
                out.lines().any(|l| l.trim() == e.trim()),
                "missing element {e:?}, got:\n{out}"
            );
        }
        assert_eq!(trimmed_eq(&out, ".end array-data"), 4, "got:\n{out}");
    }
    // Each `fill-array-data` operand names its payload address; that
    // address must carry exactly one label line in the payload block.
    for (i, pay) in payloads.iter().enumerate() {
        assert!(
            out.lines()
                .any(|l| l.trim() == format!("fill-array-data v{i}, :addr_{pay:x}")),
            "fill-array-data v{i} must point at :addr_{pay:x}, got:\n{out}"
        );
        assert_eq!(
            trimmed_eq(&out, &format!(":addr_{pay:x}")),
            1,
            "payload label :addr_{pay:x} must appear exactly once, got:\n{out}"
        );
    }
}

#[test]
fn every_label_line_is_printed_exactly_once() {
    // Guards the droidsaw bug where the trailing-label flush prints a
    // payload address a second time (smali.rs:254-261 vs the payload
    // loop). Payload addresses are always below the last instruction, so
    // only the payload loop may print them.
    let mut s = with_g();
    let mut units: Vec<u16> = Vec::new();
    units.push(0x0000); // 0 nop -> the switch lands on an odd address
    units.extend(insn_31t(0x2B, 0, 0)); // 1..3  packed-switch v0
    let payload_at = units.len() as u16; // 4
    units.extend(packed_switch_payload(0, &[-1, 0]));
    patch_branch32(&mut units, 1, i32::from(payload_at) - 1);
    set_code(&mut s, units, 2);
    let out = ok(&s.build());
    // Payload blocks indent their targets one level deeper than the
    // body (baksmali's convention), so a definition is identified by
    // its indentation, not by the text after the colon.
    let definitions: Vec<&str> = out
        .lines()
        .filter(|l| l.starts_with("    :"))
        .map(|l| l.trim())
        .collect();
    let mut seen: Vec<&str> = Vec::new();
    for t in &definitions {
        assert!(!seen.contains(t), "label {t} printed twice:\n{out}");
        seen.push(t);
    }
    assert!(
        seen.contains(&format!(":addr_{payload_at:x}").as_str()),
        "payload label :addr_{payload_at:x} present, got:\n{out} (defs: {seen:?})"
    );
}

#[test]
fn switch_without_payload_is_an_error() {
    let mut s = with_g();
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn_11n(0x12, 0, 0));
    units.extend(insn_31t(0x2B, 0, 2_000)); // far past the end
    units.push(0x000E);
    set_code(&mut s, units, 2);
    let err = disasm(&s.build()).expect_err("a dangling switch payload must be an Err");
    let msg = format!("{err:?}");
    assert!(msg.contains('g'), "must name the method, got: {msg}");
    assert!(
        msg.contains("BranchTargetOutOfRange"),
        "must report the out-of-range switch target, got: {msg}"
    );
}

// ── try / catch ──────────────────────────────────────────────────────

#[test]
fn try_catch_and_catchall_use_exclusive_end_labels() {
    let mut s = with_g();
    let throwable = s.ty("Ljava/lang/Throwable;");
    let units: Vec<u16> = vec![0x000E; 6];
    // try covers [0, 1) -> the end label is addr 1; typed handler 5,
    // catch-all 6 (past the last instruction at addr 5).
    s.classes[0].direct_methods[0].code = Some(Code {
        registers: 1,
        ins: 0,
        outs: 0,
        units,
        tries: vec![TrySpec {
            start_addr: 0,
            insn_count: 1,
            handler_off: 1,
        }],
        handlers: vec![HandlerSpec {
            catches: vec![(throwable as u16, 5)],
            catch_all: Some(6),
        }],
    });
    let out = ok(&s.build());
    assert_eq!(
        lines_eq(
            &out,
            "    .catch Ljava/lang/Throwable; {:addr_0 .. :addr_1} :addr_5"
        ),
        1,
        "typed catch range is [start, end), got:\n{out}"
    );
    assert_eq!(
        lines_eq(&out, "    .catchall {:addr_0 .. :addr_1} :addr_6"),
        1,
        "catchall range, got:\n{out}"
    );
    assert_eq!(lines_eq(&out, "    :addr_1"), 1, "got:\n{out}");
    let end = out
        .find("    :addr_1\n")
        .unwrap_or_else(|| panic!("end label missing:\n{out}"));
    let catch = out
        .find("    .catch Ljava/lang/Throwable;")
        .unwrap_or_else(|| panic!("catch missing:\n{out}"));
    assert!(end < catch, ".catch follows the end label, got:\n{out}");
    let catchall = out
        .find("    .catchall")
        .unwrap_or_else(|| panic!("catchall missing:\n{out}"));
    assert!(
        catch < catchall,
        "typed catch precedes catch-all, got:\n{out}"
    );
}

#[test]
fn try_with_clamped_range_is_an_error() {
    // start_addr + insn_count > insns_size: droidsaw clamps the count and
    // records TryItemRangeInvalid, so a listing would silently cover a
    // range the file never declared.
    let mut s = with_g();
    let throwable = s.ty("Ljava/lang/Throwable;");
    s.classes[0].direct_methods[0].code = Some(Code {
        registers: 1,
        ins: 0,
        outs: 0,
        units: vec![0x000E, 0x000E],
        tries: vec![TrySpec {
            start_addr: 0,
            insn_count: 50,
            handler_off: 1,
        }],
        handlers: vec![HandlerSpec {
            catches: vec![(throwable as u16, 1)],
            catch_all: None,
        }],
    });
    let err = disasm(&s.build()).expect_err("a clamped try range must be an Err");
    let msg = format!("{err:?}");
    assert!(msg.contains('g'), "must name the method, got: {msg}");
    assert!(
        msg.contains("50"),
        "must report the observed count, got: {msg}"
    );
}

// ── error paths ──────────────────────────────────────────────────────

#[test]
fn unknown_opcode_byte_is_an_error_naming_method_and_offset() {
    let mut s = with_g();
    let mut units = insn_11n(0x12, 0, 1);
    units.push(0x003F); // code-unit offset 1: undefined opcode
    units.push(0x000E);
    set_code(&mut s, units, 2);
    let err = disasm(&s.build()).expect_err("an unknown opcode must be an Err");
    let msg = format!("{err:?}");
    assert!(msg.contains('g'), "must name the method, got: {msg}");
    assert!(
        msg.contains("0x3f") || msg.contains("63") || msg.contains(" 1"),
        "must carry the offending offset or opcode, got: {msg}"
    );
}

#[test]
fn missing_class_returns_class_not_found() {
    let dex = empty_class().build();
    let err = DroidsawBackend::new()
        .disassemble(&dex, "Lgate/Missing;", None)
        .expect_err("an absent class must be an Err");
    assert!(
        matches!(&err, DecompileError::ClassNotFound(c) if c.contains("Missing")),
        "got {err:?}"
    );
}

#[test]
fn method_filter_selects_every_overload_and_omits_fields() {
    let mut s = empty_class();
    let cls = s.classes[0].class_idx;
    let int_ty = s.ty("I");
    let string_ty = s.ty("Ljava/lang/String;");
    let fld = s.field(cls, string_ty, "fld");
    s.proto("I", 2, &[int_ty]); // proto 1 = (I)V
    let m_void = s.method(cls, 0, "run");
    let m_int = s.method(cls, 1, "run");
    let other = s.method(cls, 0, "other");
    s.classes[0].static_fields = vec![FieldSpec {
        idx: fld,
        flags: 0x0009,
    }];
    let code = || {
        Some(Code {
            registers: 1,
            ins: 0,
            outs: 0,
            units: vec![0x000E],
            tries: vec![],
            handlers: vec![],
        })
    };
    s.classes[0].direct_methods = vec![
        Method {
            name: m_void,
            flags: 0x0008,
            code: code(),
        },
        Method {
            name: m_int,
            flags: 0x0008,
            code: code(),
        },
        Method {
            name: other,
            flags: 0x0008,
            code: code(),
        },
    ];
    let bytes = s.build();
    let out = disasm_one(&bytes, "run").expect("the filter matches two overloads");
    assert!(out.contains("run()V"), "got:\n{out}");
    assert!(
        out.contains("run(I)V"),
        "both overloads are listed, got:\n{out}"
    );
    assert_eq!(
        out.matches(".method").count(),
        2,
        "exactly two methods, got:\n{out}"
    );
    assert!(!out.contains("other"), "non-matching method, got:\n{out}");
    assert!(
        !out.contains(".field"),
        "fields are omitted with a method filter, got:\n{out}"
    );
    let full = ok(&bytes);
    assert!(
        full.contains(".field public static fld:Ljava/lang/String;"),
        "the unfiltered listing carries fields, got:\n{full}"
    );
}

#[test]
fn method_filter_with_no_match_returns_method_not_found() {
    let mut s = with_g();
    set_code(&mut s, vec![0x000E], 1);
    let err = disasm_one(&s.build(), "nope").expect_err("no match must be an Err");
    assert!(
        matches!(&err, DecompileError::MethodNotFound(m) if m.contains("nope")),
        "got {err:?}"
    );
}

#[test]
fn both_dex_versions_038_and_039_disassemble() {
    for version in ["038", "039"] {
        let mut s = with_g();
        s.version = version.to_string();
        set_code(&mut s, vec![0x000E], 1);
        let out =
            disasm(&s.build()).unwrap_or_else(|e| panic!("dex {version} must disassemble: {e}"));
        assert!(contains(&out, "    return-void"), "dex {version}:\n{out}");
    }
}
