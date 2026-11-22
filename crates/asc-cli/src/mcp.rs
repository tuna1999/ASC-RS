//! `asc-rs mcp`: a Model Context Protocol server over stdio.
//!
//! Newline-delimited JSON-RPC 2.0 on stdin/stdout, synchronous, one
//! request at a time (no async runtime, per the workspace rules). Every
//! tool re-runs this same binary as a child process with an argv built
//! from [`TOOLS`], so a tool call behaves exactly like the CLI command
//! (same output, same exit codes) and a crash in one call cannot take
//! the server down. The argv never passes through a shell; flag values
//! are sent as `--flag=value` and free-text positionals after `--`, so a
//! value that starts with `-` is data, never an option.

use std::io::{BufRead as _, Read, Write as _};
use std::process::{Command, ExitCode, Stdio};

use serde_json::{Value, json};

/// Protocol revisions this server speaks; the newest is offered when the
/// client asks for one we do not know.
const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

// ponytail: fixed cap on tool text, add paging if agents need >4 MiB.
const MAX_TEXT: usize = 4 << 20;

#[derive(Clone, Copy)]
enum Arg {
    /// Positional before `--` (paths, the findrefs kind); must not start with `-`.
    Head,
    /// Positional after `--` (class names, needles): any text is literal.
    Tail,
    /// `--flag=value`.
    Flag(&'static str),
    /// `--flag` when true.
    Switch(&'static str),
}

#[derive(Clone, Copy)]
enum Ty {
    Str,
    /// Non-negative integer up to this bound (the clap type's range).
    Int(u64),
    Bool,
    Enum(&'static [&'static str]),
}

struct Param {
    name: &'static str,
    arg: Arg,
    ty: Ty,
    required: bool,
    desc: &'static str,
}

struct Tool {
    name: &'static str,
    desc: &'static str,
    params: &'static [Param],
}

const fn p(name: &'static str, arg: Arg, ty: Ty, required: bool, desc: &'static str) -> Param {
    Param {
        name,
        arg,
        ty,
        required,
        desc,
    }
}

const APK: Param = p(
    "apk",
    Arg::Head,
    Ty::Str,
    true,
    "Path to the APK (or bare .dex).",
);
const CLASS: Param = p(
    "class",
    Arg::Tail,
    Ty::Str,
    true,
    "Class descriptor (`Lcom/x/Foo;`) or dotted name.",
);
const FORMAT: Param = p(
    "format",
    Arg::Flag("--format"),
    Ty::Enum(&["text", "json"]),
    false,
    "Output format (default text).",
);
const MAPPING: Param = p(
    "mapping",
    Arg::Flag("--mapping"),
    Ty::Str,
    false,
    "R8/ProGuard mapping.txt: class arguments may use original names; output is annotated.",
);
const LIMIT: Param = p(
    "limit",
    Arg::Flag("--limit"),
    Ty::Int(u32::MAX as u64),
    false,
    "Maximum rows.",
);

/// One entry per CLI subcommand exposed to agents (`extract` is left out:
/// it writes files). `format`/`mapping` are appended to every tool.
const TOOLS: &[Tool] = &[
    Tool {
        name: "getclass",
        desc: "Decompile one class to Java (minimal rebuilt DEX).",
        params: &[
            APK,
            CLASS,
            p(
                "paranoid",
                Arg::Switch("--paranoid"),
                Ty::Bool,
                false,
                "Decode Paranoid/LSParanoid strings.",
            ),
            p(
                "decode_xor",
                Arg::Switch("--decode-xor"),
                Ty::Bool,
                false,
                "Decode XOR-obfuscated string literals.",
            ),
        ],
    },
    Tool {
        name: "disasm",
        desc: "Smali listing of one class (or one method), or its bytecode / CFG view.",
        params: &[
            APK,
            CLASS,
            p(
                "method",
                Arg::Flag("--method"),
                Ty::Str,
                false,
                "Only this method name.",
            ),
            p(
                "view",
                Arg::Flag("--view"),
                Ty::Enum(&["smali", "bytecode", "cfg"]),
                false,
                "Listing view (default smali).",
            ),
        ],
    },
    Tool {
        name: "calls",
        desc: "Outgoing call tree of one method (callees, breadth-first).",
        params: &[
            APK,
            CLASS,
            p(
                "method",
                Arg::Flag("--method"),
                Ty::Str,
                true,
                "Method name.",
            ),
            p(
                "depth",
                Arg::Flag("--depth"),
                Ty::Int(u8::MAX as u64),
                false,
                "Tree depth (default 1).",
            ),
            p(
                "max_nodes",
                Arg::Flag("--max-nodes"),
                Ty::Int(u32::MAX as u64),
                false,
                "Node cap (default 200).",
            ),
        ],
    },
    Tool {
        name: "member",
        desc: "Signature and access flags of every overload of one method.",
        params: &[
            APK,
            CLASS,
            p(
                "method",
                Arg::Flag("--method"),
                Ty::Str,
                true,
                "Method name.",
            ),
        ],
    },
    Tool {
        name: "mapping",
        desc: "Look up a class/member name in an R8/ProGuard mapping.txt (either direction).",
        params: &[
            p(
                "mapping_file",
                Arg::Head,
                Ty::Str,
                true,
                "Path to mapping.txt.",
            ),
            p(
                "needle",
                Arg::Tail,
                Ty::Str,
                true,
                "Obfuscated or original name.",
            ),
        ],
    },
    Tool {
        name: "findrefs",
        desc: "Find code referencing a string/type/method/field, or classes that extend/implement a class.",
        params: &[
            APK,
            p(
                "kind",
                Arg::Head,
                Ty::Enum(&["string", "type", "method", "field", "extends", "impl"]),
                true,
                "What to search for.",
            ),
            p(
                "value",
                Arg::Tail,
                Ty::Str,
                false,
                "Substring (string/type), member name (method/field, optional with class), or the class (extends/impl).",
            ),
            p(
                "class",
                Arg::Flag("--class"),
                Ty::Str,
                false,
                "method/field: restrict to this class.",
            ),
            p(
                "fuzzy_class",
                Arg::Switch("--fuzzy-class"),
                Ty::Bool,
                false,
                "method/field: treat class as a substring.",
            ),
            p(
                "transitive",
                Arg::Switch("--transitive"),
                Ty::Bool,
                false,
                "extends/impl: follow subclasses.",
            ),
            p(
                "decode_xor",
                Arg::Switch("--decode-xor"),
                Ty::Bool,
                false,
                "string: also match XOR-decoded literals.",
            ),
            p(
                "paranoid",
                Arg::Switch("--paranoid"),
                Ty::Bool,
                false,
                "string: also match Paranoid-decoded strings.",
            ),
        ],
    },
    Tool {
        name: "listmethod",
        desc: "List methods defined in the APK, optionally for one class and/or a name substring.",
        params: &[
            APK,
            p(
                "class",
                Arg::Flag("--class"),
                Ty::Str,
                false,
                "Exact class.",
            ),
            p(
                "name",
                Arg::Flag("--name"),
                Ty::Str,
                false,
                "Method-name substring.",
            ),
            LIMIT,
        ],
    },
    Tool {
        name: "listclass",
        desc: "List every class defined in the APK.",
        params: &[
            APK,
            p(
                "prefix",
                Arg::Flag("--prefix"),
                Ty::Str,
                false,
                "Descriptor/dotted prefix filter.",
            ),
            p(
                "with_dex",
                Arg::Switch("--with-dex"),
                Ty::Bool,
                false,
                "Show the defining DEX.",
            ),
        ],
    },
    Tool {
        name: "manifest",
        desc: "AndroidManifest.xml: package, SDKs, permissions, components, intent filters.",
        params: &[
            APK,
            p(
                "match_uri",
                Arg::Flag("--match-uri"),
                Ty::Str,
                false,
                "Evaluate which intent filters match this URI.",
            ),
        ],
    },
    Tool {
        name: "inspect",
        desc: "Inventory an APK/DEX and report packer signals and anomalies.",
        params: &[APK],
    },
    Tool {
        name: "native",
        desc: "Native libraries and DEX native methods, joined by JNI export name.",
        params: &[APK],
    },
    Tool {
        name: "cert",
        desc: "Signing certificates (v1/v2/v3) with signature verification.",
        params: &[APK],
    },
    Tool {
        name: "resources",
        desc: "resources.arsc: inventory, lookup by ID, key/value search.",
        params: &[
            APK,
            p(
                "id",
                Arg::Flag("--id"),
                Ty::Str,
                false,
                "Resource ID (0x7f...).",
            ),
            p(
                "strings",
                Arg::Flag("--strings"),
                Ty::Str,
                false,
                "Key/value substring search.",
            ),
            LIMIT,
        ],
    },
    Tool {
        name: "strings",
        desc: "DEX string-pool dump (every entry, not only referenced ones).",
        params: &[
            APK,
            p(
                "substring",
                Arg::Flag("--substring"),
                Ty::Str,
                false,
                "Substring filter.",
            ),
            p(
                "class",
                Arg::Flag("--class"),
                Ty::Str,
                false,
                "Only strings used by this class.",
            ),
            LIMIT,
        ],
    },
    Tool {
        name: "axml",
        desc: "Decode a compiled binary-XML entry (e.g. res/xml/network_security_config.xml).",
        params: &[
            APK,
            p("entry", Arg::Tail, Ty::Str, true, "Archive entry name."),
        ],
    },
    Tool {
        name: "hermes",
        desc: "Hermes bytecode bundle string tables.",
        params: &[
            APK,
            p(
                "pattern",
                Arg::Flag("--pattern"),
                Ty::Str,
                false,
                "Substring filter.",
            ),
            LIMIT,
        ],
    },
    Tool {
        name: "xapk",
        desc: "Inventory an XAPK (ZIP of APKs) per member.",
        params: &[APK],
    },
];

fn params(tool: &Tool) -> impl Iterator<Item = &Param> {
    let common: &[Param] = if tool.name == "mapping" {
        &[FORMAT]
    } else {
        &[FORMAT, MAPPING]
    };
    tool.params.iter().chain(common)
}

fn tool_schema(tool: &Tool) -> Value {
    let mut props = serde_json::Map::new();
    let mut required = Vec::new();
    for prm in params(tool) {
        let mut s = match prm.ty {
            Ty::Str => json!({"type": "string"}),
            Ty::Int(max) => json!({"type": "integer", "minimum": 0, "maximum": max}),
            Ty::Bool => json!({"type": "boolean"}),
            Ty::Enum(v) => json!({"type": "string", "enum": v}),
        };
        s["description"] = prm.desc.into();
        props.insert(prm.name.into(), s);
        if prm.required {
            required.push(prm.name);
        }
    }
    json!({
        "name": tool.name,
        "description": tool.desc,
        "inputSchema": {"type": "object", "properties": props, "required": required, "additionalProperties": false},
    })
}

/// Build the child argv; `Err` = invalid arguments (reported as `isError`).
fn build_argv(tool: &Tool, args: &serde_json::Map<String, Value>) -> Result<Vec<String>, String> {
    for k in args.keys() {
        if !params(tool).any(|p| p.name == k) {
            return Err(format!("unknown argument `{k}`"));
        }
    }
    let (mut head, mut flags, mut tail) = (vec![tool.name.to_string()], vec![], vec![]);
    for prm in params(tool) {
        let Some(v) = args.get(prm.name).filter(|v| !v.is_null()) else {
            if prm.required {
                return Err(format!("missing required argument `{}`", prm.name));
            }
            continue;
        };
        let text = match (prm.ty, v) {
            (Ty::Str, Value::String(s)) => s.clone(),
            (Ty::Enum(ok), Value::String(s)) if ok.contains(&s.as_str()) => s.clone(),
            (Ty::Int(max), Value::Number(n)) if n.as_u64().is_some_and(|v| v <= max) => {
                n.to_string()
            }
            (Ty::Bool, Value::Bool(b)) => b.to_string(),
            _ => {
                return Err(format!(
                    "argument `{}` has the wrong type or value",
                    prm.name
                ));
            }
        };
        match prm.arg {
            Arg::Head if text.starts_with('-') => {
                return Err(format!(
                    "`{}` must not start with `-` (use ./{text})",
                    prm.name
                ));
            }
            Arg::Head => head.push(text),
            Arg::Tail => tail.push(text),
            Arg::Flag(f) => flags.push(format!("{f}={text}")),
            Arg::Switch(f) if v == &Value::Bool(true) => flags.push(f.to_string()),
            Arg::Switch(_) => {}
        }
    }
    head.extend(flags);
    head.push("--".into());
    head.extend(tail);
    Ok(head)
}

// ponytail: no per-call timeout and one call at a time; a hung child
// blocks the server. Add a kill-after-deadline wait loop if that bites.
fn run_tool(argv: &[String]) -> Value {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => return tool_error(format!("cannot locate asc-rs: {e}")),
    };
    let mut child = match Command::new(exe)
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return tool_error(format!("cannot run asc-rs: {e}")),
    };
    // Keep at most MAX_TEXT + 1 bytes of each stream (the +1 lets `capped`
    // see the overflow) and drain the rest, so a huge listing never sits
    // in memory whole and the child never blocks on a full pipe.
    // `Command::output()` buffered everything before the cap applied.
    let stderr_pipe = child.stderr.take();
    let stderr_reader =
        std::thread::spawn(move || stderr_pipe.map(read_capped).unwrap_or_default());
    let stdout = child.stdout.take().map(read_capped).unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();
    let code = match child.wait() {
        Ok(st) => st.code().unwrap_or(-1),
        Err(e) => return tool_error(format!("asc-rs did not finish: {e}")),
    };
    let mut content = vec![text_item(capped(
        String::from_utf8_lossy(&stdout).into_owned(),
    ))];
    let stderr = String::from_utf8_lossy(&stderr);
    // Diagnostics go in their own item so a `format: json` result stays
    // parseable; exit 2 can still carry partial results above it.
    if code != 0 || !stderr.trim().is_empty() {
        content.push(text_item(capped(format!("[exit {code}] {stderr}"))));
    }
    json!({"content": content, "isError": code != 0})
}

/// First `MAX_TEXT + 1` bytes of `r`; the remainder is read and discarded.
fn read_capped(mut r: impl Read) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = r.by_ref().take(MAX_TEXT as u64 + 1).read_to_end(&mut buf);
    let _ = std::io::copy(&mut r, &mut std::io::sink());
    buf
}

fn tool_error(message: String) -> Value {
    json!({"content": [text_item(message)], "isError": true})
}

fn text_item(text: String) -> Value {
    json!({"type": "text", "text": text})
}

fn capped(mut text: String) -> String {
    if text.len() > MAX_TEXT {
        let mut cut = MAX_TEXT;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push_str("\n... truncated at 4 MiB; narrow the query (limit/prefix/class/method).");
    }
    text
}

/// Handle one parsed message; `None` for notifications (no reply).
fn handle(msg: &Value) -> Option<Value> {
    let Some(obj) = msg.as_object() else {
        // Batches (dropped from the spec in 2025-06-18) and scalars.
        return Some(json!({"jsonrpc": "2.0", "id": null,
            "error": {"code": -32600, "message": "invalid request: expected one JSON object"}}));
    };
    // No id = notification; no method = a response to us: never answered.
    let id = obj.get("id")?.clone();
    let method = obj.get("method")?.as_str().unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "initialize" => {
            let asked = params["protocolVersion"].as_str().unwrap_or("");
            let version = PROTOCOL_VERSIONS
                .iter()
                .find(|v| **v == asked)
                .unwrap_or(&PROTOCOL_VERSIONS[0]);
            Ok(json!({
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "asc-rs", "version": env!("CARGO_PKG_VERSION")},
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": TOOLS.iter().map(tool_schema).collect::<Vec<_>>()})),
        "tools/call" => {
            let name = params["name"].as_str().unwrap_or("");
            let empty = serde_json::Map::new();
            let args = params["arguments"].as_object().unwrap_or(&empty);
            match TOOLS.iter().find(|t| t.name == name) {
                None => Err((-32602, format!("unknown tool `{name}`"))),
                // Bad arguments are a tool error the model can read and retry.
                Some(tool) => Ok(build_argv(tool, args).map_or_else(
                    |e| tool_error(format!("invalid arguments: {e}")),
                    |argv| run_tool(&argv),
                )),
            }
        }
        _ => Err((-32601, format!("method not found: {method}"))),
    };
    Some(match result {
        Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
        Err((code, message)) => {
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
        }
    })
}

/// Serve until stdin closes.
pub fn serve() -> ExitCode {
    let mut stdin = std::io::stdin().lock();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match stdin.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        // Invalid UTF-8 becomes U+FFFD and then a -32700, never a silent exit.
        let line = String::from_utf8_lossy(&buf);
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => handle(&msg),
            Err(e) => Some(json!({
                "jsonrpc": "2.0", "id": null,
                "error": {"code": -32700, "message": format!("parse error: {e}")},
            })),
        };
        if let Some(r) = reply {
            let mut out = std::io::stdout().lock();
            if writeln!(out, "{r}").and_then(|()| out.flush()).is_err() {
                break; // client went away
            }
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str) -> &'static Tool {
        TOOLS.iter().find(|t| t.name == name).unwrap()
    }

    fn argv(name: &str, args: Value) -> Result<Vec<String>, String> {
        build_argv(tool(name), args.as_object().unwrap())
    }

    #[test]
    fn argv_keeps_values_out_of_option_position() {
        assert_eq!(
            argv(
                "getclass",
                json!({"apk": "a.apk", "class": "-o/evil", "format": "json"})
            )
            .unwrap(),
            ["getclass", "a.apk", "--format=json", "--", "-o/evil"]
        );
        assert_eq!(
            argv("findrefs", json!({"apk": "a.apk", "kind": "method", "value": "run", "class": "LX;", "fuzzy_class": true})).unwrap(),
            ["findrefs", "a.apk", "method", "--class=LX;", "--fuzzy-class", "--", "run"]
        );
        assert!(argv("getclass", json!({"apk": "-o", "class": "LX;"})).is_err());
        assert!(argv("getclass", json!({"apk": "a.apk"})).is_err());
        assert!(
            argv(
                "getclass",
                json!({"apk": "a.apk", "class": "LX;", "output": "x"})
            )
            .is_err()
        );
        assert!(argv("findrefs", json!({"apk": "a", "kind": "bogus"})).is_err());
        assert!(argv("listmethod", json!({"apk": "a", "limit": -1})).is_err());
        assert!(
            argv(
                "calls",
                json!({"apk": "a", "class": "X", "method": "m", "depth": 256})
            )
            .is_err()
        );
        assert!(
            argv(
                "calls",
                json!({"apk": "a", "class": "X", "method": "m", "depth": 255})
            )
            .is_ok()
        );
    }

    /// Every schema property must reach the CLI under a name clap accepts.
    #[test]
    fn every_tool_maps_to_a_real_subcommand() {
        use clap::CommandFactory as _;
        let cli = crate::Cli::command();
        for t in TOOLS {
            let sub = cli
                .find_subcommand(t.name)
                .unwrap_or_else(|| panic!("{}", t.name));
            for prm in params(t) {
                let flag = match prm.arg {
                    Arg::Flag(f) | Arg::Switch(f) => f.trim_start_matches("--"),
                    _ => continue,
                };
                let known =
                    |c: &clap::Command| c.get_arguments().any(|a| a.get_long() == Some(flag));
                let ok = known(sub) || known(&cli) || sub.get_subcommands().any(known);
                assert!(ok, "{} --{flag}", t.name);
            }
        }
    }

    /// Only `MAX_TEXT + 1` bytes are kept however much the child writes;
    /// the rest is consumed (so the child is never blocked) and dropped.
    #[test]
    fn read_capped_keeps_cap_plus_one_and_drains() {
        let mut src = std::io::Cursor::new(vec![b'x'; MAX_TEXT * 3]);
        let got = read_capped(&mut src);
        assert_eq!(got.len(), MAX_TEXT + 1);
        assert_eq!(src.position() as usize, MAX_TEXT * 3, "remainder drained");
        assert!(capped(String::from_utf8(got).unwrap()).ends_with("(limit/prefix/class/method)."));
        assert_eq!(read_capped(&b"short"[..]), b"short");
    }
}
