//! Semantic resolution of a lexical selection to a symbol identity
//! (audit F2).
//!
//! The click machinery keeps two distinct concepts apart:
//!
//! - **Document identity** — which document a selection was captured in,
//!   used only to reject stale selections that no longer belong to the
//!   source on screen (anti-stale, [`crate::app::SymbolSelection`]).
//! - **Resolved symbol** — what the clicked identifier *means*: a class,
//!   a method, a field, or nothing member-like. This lives in
//!   [`ResolvedSymbol`] and carries its *declaring class* when the view
//!   actually proves it. It is never derived from the document owner.
//!
//! Two parsers back it:
//!
//! - **Smali** ([`smali_resolve`]) — a structured listing, so `.method`
//!   / `.end method` blocks and `invoke-*` / `iget`/`sget` / `.field`
//!   targets resolve exactly (method name + prototype + declaring class).
//!   A cross-class call (`invoke-virtual {...}, Lb/B;->helper(...)`) thus
//!   resolves to `Lb/B;`, never to the document's own class.
//! - **Java** ([`java_resolve`]) — decompiled (droidsaw) source, which
//!   has no reliable declaration table, so it is conservative: a method
//!   *declaration* or unqualified call resolves to the current class, a
//!   qualified call/field access resolves with `owner = None` (unknown
//!   declaring class) and never masquerades, and any other identifier
//!   (a local, a register-like token) is **not** a member.
//!
//! Every parser fails **closed**: malformed or unexpected input yields
//! `Unknown` / `None`, never a panic and never a fabricated owner.

/// What kind of symbol a selection resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SymbolKind {
    /// A class reference (`L…;`).
    Class,
    /// A method (declaration, call or smali `invoke-*` target).
    Method,
    /// A field (smali `.field` / `iget`/`sget`, or a Java field access).
    Field,
}

/// The resolved identity of a clicked identifier.
///
/// `owner` is the **declaring** class descriptor (`L…;`) when the view
/// proved it — the anti-stale document key is a separate concept in
/// [`crate::app::SymbolSelection::descriptor`] and is *never* used as a
/// declaration owner here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedSymbol {
    pub(crate) kind: SymbolKind,
    pub(crate) owner: Option<String>,
    pub(crate) name: String,
    /// Method prototype string (`(…)...`) when the parser saw it.
    pub(crate) proto: Option<String>,
}

impl ResolvedSymbol {
    pub(crate) fn method(owner: Option<String>, name: String, proto: Option<String>) -> Self {
        Self {
            kind: SymbolKind::Method,
            owner,
            name,
            proto,
        }
    }

    fn field(owner: Option<String>, name: String) -> Self {
        Self {
            kind: SymbolKind::Field,
            owner,
            name,
            proto: None,
        }
    }

    fn class(name: String) -> Self {
        Self {
            kind: SymbolKind::Class,
            owner: None,
            name,
            proto: None,
        }
    }
}

fn is_class_descriptor(token: &str) -> bool {
    token.starts_with('L') && token.ends_with(';')
}

/// Byte offsets `[start, end)` of every line (newline excluded).
fn line_offsets(source: &str) -> Vec<(usize, usize)> {
    let b = source.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    for (i, &c) in b.iter().enumerate() {
        if c == b'\n' {
            out.push((start, i));
            start = i + 1;
        }
    }
    if start < b.len() {
        out.push((start, b.len()));
    }
    out
}

/// Line index whose byte range contains `s`, else `None`.
fn line_at(lines: &[(usize, usize)], s: usize) -> Option<usize> {
    lines.iter().position(|&(st, en)| st <= s && s < en)
}

/// Byte range of the `.method` … `.end method` block enclosing line `li`,
/// or `None` when `li` is outside any method block.
///
/// Methods cannot nest in smali, so a forward scan tracking the currently
/// open block is exact.
fn enclosing_method_block(
    source: &str,
    lines: &[(usize, usize)],
    li: usize,
) -> Option<(usize, usize)> {
    // Find the `.method` line that is still open at `li` (walk `0..=li`).
    let mut block_start: Option<(usize, usize)> = None;
    for &(ls, le) in lines.iter().take(li + 1) {
        let t = source[ls..le].trim_start();
        if t.starts_with(".method ") {
            block_start = Some((ls, le));
        } else if t.starts_with(".end method") {
            block_start = None;
        }
    }
    let (bs, _) = block_start?;
    // Find the matching `.end method` at or after `li`.
    for &(es, ee) in lines.iter().skip(li) {
        if source[es..ee].trim_start().starts_with(".end method") {
            return Some((bs, ee));
        }
    }
    // No terminating `.end method` (truncated listing): still a block up to EOF.
    Some((bs, source.len()))
}

/// Classify `token` on smali line `lt` (trimmed) within owning class.
/// Whitespace-separated `(absolute_start, token)` tuples of a line.
fn sig_tokens(lt_abs: usize, lt: &str) -> Vec<(usize, &str)> {
    let b = lt.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() {
            i += 1;
        }
        if start < i {
            out.push((lt_abs + start, &lt[start..i]));
        }
    }
    out
}

/// If `s` lies on the method name of a `.method` signature, resolve it.
fn method_name_at(lt_abs: usize, lt: &str, s: usize, owning: &str) -> Option<ResolvedSymbol> {
    for (abs, tok) in sig_tokens(lt_abs, lt) {
        if let Some(open) = tok.find('(') {
            if open > 0 && s >= abs && s < abs + open {
                let name = tok[..open].to_string();
                let proto = tok[open..]
                    .find(')')
                    .map(|c| tok[open..=open + c].to_string());
                return Some(ResolvedSymbol::method(
                    Some(owning.to_string()),
                    name,
                    proto,
                ));
            }
            return None;
        }
    }
    None
}

/// If `s` lies on the field name of a `.field` signature, resolve it.
fn field_name_at(lt_abs: usize, lt: &str, s: usize, owning: &str) -> Option<ResolvedSymbol> {
    for (abs, tok) in sig_tokens(lt_abs, lt) {
        if let Some(colon) = tok.find(':') {
            let name = &tok[..colon];
            if !name.is_empty() && !name.contains(';') && s >= abs && s < abs + colon {
                return Some(ResolvedSymbol::field(
                    Some(owning.to_string()),
                    name.to_string(),
                ));
            }
            return None;
        }
    }
    None
}

/// If `s` lies on the target method name of an `invoke-*` line, resolve it
/// to its *declared* class + prototype (cross-class A→B).
fn invoke_target_at(lt_abs: usize, lt: &str, s: usize) -> Option<ResolvedSymbol> {
    let arrow = lt.rfind(";->")?;
    let member_start = arrow + 3;
    let member = &lt[member_start..];
    let open = member.find('(')?;
    let name = &member[..open];
    if name.is_empty() || name.contains(';') {
        return None;
    }
    let name_abs = lt_abs + member_start;
    if !(s >= name_abs && s < name_abs + open) {
        return None;
    }
    let proto = member[open..]
        .find(')')
        .map(|c| member[open..=open + c].to_string());
    // The descriptor ends at the `;` of `;->`, so include it.
    let owner = class_descriptor_before(&lt[..arrow + 1])?;
    Some(ResolvedSymbol::method(Some(owner), name.to_string(), proto))
}

/// If `s` lies on the field name of a `iget`/`sget`/`iput`/`sput` target.
fn member_field_at(lt_abs: usize, lt: &str, s: usize) -> Option<ResolvedSymbol> {
    let arrow = lt.rfind(";->")?;
    let member_start = arrow + 3;
    let member = &lt[member_start..];
    let colon = member.find(':')?;
    let name = &member[..colon];
    if name.is_empty() || name.contains('(') {
        return None;
    }
    let name_abs = lt_abs + member_start;
    if !(s >= name_abs && s < name_abs + colon) {
        return None;
    }
    let owner = class_descriptor_before(&lt[..arrow + 1])?;
    Some(ResolvedSymbol::field(Some(owner), name.to_string()))
}

/// Extract the class descriptor immediately before a `;->` — the trailing
/// `L…;` of `…, Lcom/foo/Bar;`.
fn class_descriptor_before(prefix: &str) -> Option<String> {
    let prefix = prefix.trim_end();
    let b = prefix.as_bytes();
    // Walk *back* from the trailing `;` over the descriptor alphabet, then
    // require the `L` that starts it — `rfind('L')` would collapse
    // `Ljava/util/List;` to `List;`.
    if b.last() != Some(&b';') {
        return None;
    }
    let mut start = b.len() - 1;
    while start > 0
        && (b[start - 1].is_ascii_alphanumeric() || matches!(b[start - 1], b'/' | b'$' | b'_'))
    {
        start -= 1;
    }
    if start >= b.len() || b[start] != b'L' {
        return None;
    }
    Some(prefix[start..].to_string())
}

/// The `L…;` descriptor whose byte span contains `s`, if any.
fn class_descriptor_range(source: &str, s: usize) -> Option<(usize, usize)> {
    let b = source.as_bytes();
    // Walk back to the identifier-ish run the click belongs to.
    let mut start = s;
    while start > 0
        && (b[start - 1].is_ascii_alphanumeric() || matches!(b[start - 1], b'/' | b'$' | b'_'))
    {
        start -= 1;
    }
    if start >= b.len() || b[start] != b'L' {
        return None;
    }
    let mut end = start;
    while end < b.len() {
        let c = b[end];
        if c == b';' {
            return Some((start, end + 1));
        }
        if !(c.is_ascii_alphanumeric() || matches!(c, b'/' | b'$' | b'_' | b'[')) {
            return None;
        }
        end += 1;
    }
    None
}

/// Classify the click at absolute offset `s` on smali line `lt` (absolute
/// start `lt_abs`) within owning class `owning`.
fn classify_smali_at(
    lt_abs: usize,
    lt: &str,
    s: usize,
    owning: &str,
    source: &str,
) -> Option<ResolvedSymbol> {
    if lt.starts_with(".method ") {
        return method_name_at(lt_abs, lt, s, owning);
    }
    if lt.starts_with(".field ") {
        return field_name_at(lt_abs, lt, s, owning);
    }
    // Body line: a member target (`invoke-*` method, or `iget`/`sget`/… field),
    // then a bare class-descriptor token, then nothing member-like.
    if let Some(m) = invoke_target_at(lt_abs, lt, s).or_else(|| member_field_at(lt_abs, lt, s)) {
        return Some(m);
    }
    if let Some(range) = class_descriptor_range(source, s) {
        return Some(ResolvedSymbol::class(source[range.0..range.1].to_string()));
    }
    None
}

/// `(enclosing method block, occurrences, resolved symbol)`.
type SmaliResolved = (
    Option<(usize, usize)>,
    Vec<(usize, usize)>,
    Option<ResolvedSymbol>,
);

/// Resolve a selection inside a `#smali`/`#smali#method` view.
///
/// The method block is the byte range of the enclosing `.method … .end
/// method` (used as the rename scope), or `None` when the click is
/// outside any method.
pub(crate) fn smali_resolve(view_key: &str, source: &str, s: usize) -> SmaliResolved {
    let Some((owning, _)) = crate::state::tabs::smali_view_of(view_key) else {
        return (None, Vec::new(), None);
    };
    let lines = line_offsets(source);
    let Some(li) = line_at(&lines, s) else {
        return (None, Vec::new(), None);
    };
    let (ls, le) = lines[li];
    let line_text = &source[ls..le];
    let lead = line_text.len() - line_text.trim_start().len();
    let lt_abs = ls + lead;
    let lt = &line_text.trim_start();

    let block = enclosing_method_block(source, &lines, li);
    let occ_token = lexical_token_at(source, s);
    let occurrences = match (block, occ_token.as_deref()) {
        (Some((bs, be)), Some(tok)) => {
            crate::source_edit::occurrences_in_range(source, bs, be, tok)
        }
        _ => Vec::new(),
    };

    let symbol = classify_smali_at(lt_abs, lt, s, owning, source);
    (block, occurrences, symbol)
}

/// The lexical identifier token (`token_at`) at `s`, for occurrence
/// highlighting. Pure view state — never semantic.
pub(crate) fn lexical_token_at(source: &str, s: usize) -> Option<String> {
    let (a, b) = crate::source_edit::token_at(source, s)?;
    Some(source[a..b].to_string())
}

/// Resolve a selection inside a decompiled-Java class document.
pub(crate) fn java_resolve(
    descriptor: &str,
    source: &str,
    s: usize,
    e: usize,
    token: &str,
) -> Option<ResolvedSymbol> {
    if is_class_descriptor(token) {
        return Some(ResolvedSymbol::class(token.to_string()));
    }
    let after = source.get(e.min(source.len())..)?;
    let after_ws = after.trim_start();
    if after_ws.starts_with('(') {
        // A call or a declaration. A '.' immediately before the name is a
        // qualified (cross-class/object) call — the declaring class is not
        // knowable from decompiled source, so owner stays None.
        let before = &source[..s];
        let prev = before.trim_end().chars().next_back();
        let owner = if prev == Some('.') {
            receiver_descriptor(source, before.trim_end().len() - 1, descriptor)
        } else {
            Some(descriptor.to_string())
        };
        return Some(ResolvedSymbol::method(owner, token.to_string(), None));
    }
    let before = &source[..s];
    let prev = before.trim_end().chars().next_back();
    if prev == Some('.') {
        // A qualified field access: the owner is the *declared* type of the
        // receiver, provable only when the file declares that receiver.
        let owner = receiver_descriptor(source, before.trim_end().len() - 1, descriptor);
        return Some(ResolvedSymbol::field(owner, token.to_string()));
    }
    // A bare identifier with no call/field context is not provably a member
    // (local, keyword, …) — do not guess.
    None
}

/// Descriptor of the declared type of the receiver whose final identifier
/// ends right before byte `s` (the `.` of the qualified access), or `None`
/// when the file does not declare it.
///
/// This is the minimal declaration resolver: `this`/`super` are known from
/// the class itself, any other receiver must have a visible declaration whose
/// type the file spells out (or an import that spells it out). An undeclared
/// or unknown-typed receiver keeps `owner = None`, never a guess.
fn receiver_descriptor(source: &str, s: usize, descriptor: &str) -> Option<String> {
    let recv: String = source[..s]
        .trim_end()
        .chars()
        .rev()
        .take_while(|c| c.is_alphanumeric() || matches!(c, '_' | '$'))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if recv.is_empty() {
        return None;
    }
    if recv == "this" {
        return Some(descriptor.to_string());
    }
    if recv == "super" {
        return Some(super_descriptor(source));
    }
    if let Some(ty) = declared_type(source, &recv, s) {
        return type_descriptor(source, &ty);
    }
    // No declaration: a capitalised receiver is a static class reference.
    if recv.starts_with(|c: char| c.is_uppercase()) {
        return type_descriptor(source, &recv);
    }
    None
}

/// The declared type spelling of `name` at or before byte `at` (nearest
/// preceding declaration wins, which is what shadowing does), or `None`.
fn declared_type(source: &str, name: &str, at: usize) -> Option<String> {
    let before = &source[..at.min(source.len())];
    for line in before.lines().rev() {
        let t = line.trim();
        if t.starts_with("//") || t.starts_with('*') {
            continue;
        }
        let mut pos = 0;
        while let Some(found) = t[pos..].find(name) {
            let abs = pos + found;
            pos = abs + name.len();
            let starts_token = !t[..abs]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || matches!(c, '_' | '$' | '.'));
            // A declaration is followed by one of these; the receiver of the
            // very access being resolved is not (it sits at the line end).
            let after = t[abs + name.len()..].trim_start();
            if !starts_token
                || !(after.starts_with('=')
                    || after.starts_with(';')
                    || after.starts_with(',')
                    || after.starts_with(')'))
            {
                continue;
            }
            let head = t[..abs].trim_end();
            let ty: String = head
                .chars()
                .rev()
                .take_while(|c| {
                    c.is_alphanumeric() || matches!(c, '_' | '$' | '.' | '<' | '>' | '[' | ']')
                })
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            // A bare lowercase word is not a type (`int x`, `new obj`), so
            // fail closed instead of fabricating `Lpkg/v7;`.
            let plausible = ty.contains('.')
                || ty.contains('$')
                || ty.starts_with(|c: char| c.is_ascii_uppercase());
            if ty.is_empty()
                || !plausible
                || TYPE_STOPWORDS.contains(&ty.as_str())
                // `this.mContext = v0;` would otherwise report `this` as v0's type.
                || ty == "this"
                || ty == "super"
            {
                continue;
            }
            return Some(ty);
        }
    }
    None
}

/// Java/FQN type spelling -> class descriptor (`a.b.C` -> `La/b/C;`). A bare
/// simple name resolves through the file's imports, else the own package;
/// unprovable spellings yield `None`.
fn type_descriptor(source: &str, ty: &str) -> Option<String> {
    if ty.contains('.') || ty.contains('$') {
        return Some(format!("L{};", ty.replace('.', "/")));
    }
    for line in source.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("import ") {
            let path = rest.trim_end_matches(';').trim();
            if path.rsplit('.').next() == Some(ty) {
                return Some(format!("L{};", path.replace('.', "/")));
            }
        }
    }
    match source
        .lines()
        .find_map(|l| l.trim().strip_prefix("package "))
    {
        Some(pkg) => {
            let pkg = pkg.trim_end_matches(';').trim();
            Some(format!("L{}/{};", pkg.replace('.', "/"), ty))
        }
        None => Some(format!("L{ty};")),
    }
}

/// Descriptor of the class this file extends (Object when nothing is named).
fn super_descriptor(source: &str) -> String {
    for line in source.lines() {
        let Some(pos) = line.find(" extends ") else {
            continue;
        };
        let rest = line[pos + 9..].trim_start();
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || matches!(c, '_' | '$' | '.'))
            .collect();
        if let Some(d) = type_descriptor(source, &name) {
            return d;
        }
    }
    "Ljava/lang/Object;".to_string()
}

/// Tokens that precede a name without being its type.
const TYPE_STOPWORDS: &[&str] = &[
    "return",
    "new",
    "throws",
    "instanceof",
    "case",
    "else",
    "throw",
    "yield",
    "this",
    "super",
    "null",
    "true",
    "false",
    "final",
    "public",
    "private",
    "protected",
    "static",
    "volatile",
    "transient",
    "synchronized",
    "native",
    "abstract",
];

/// 0-indexed line inside `source` that declares member `name` of `kind`, or
/// `None` when no declaration is visible in this document.
///
/// Smali is exact (`.method … name(` / `.field … name:`); decompiled Java
/// relies on shape alone, so the first plausible declarator wins.
pub(crate) fn declaration_line(source: &str, name: &str, kind: SymbolKind) -> Option<usize> {
    source.lines().position(|line| {
        let t = line.trim_start();
        if t.starts_with("//") || t.starts_with('*') {
            return false;
        }
        match kind {
            SymbolKind::Method => {
                (t.starts_with(".method ") && t.contains(&format!(" {name}(")))
                    || is_java_declaration(t, name, '(')
            }
            SymbolKind::Field => {
                (t.starts_with(".field ") && t.contains(&format!(" {name}:")))
                    // A Java field ends with `;` (or `= value;`) — uninitialised
                    // fields have no `:` at all.
                    || is_java_declaration(t, name, ';')
                    || is_java_declaration(t, name, '=')
            }
            SymbolKind::Class => false,
        }
    })
}

/// Offset of `name` in `line` that is a whole identifier (`find` alone would
/// match `find` inside `find_all`).
fn identifier_occurrence(line: &str, name: &str) -> Option<usize> {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$';
    line.match_indices(name).map(|(pos, _)| pos).find(|&pos| {
        let prev = line[..pos].chars().next_back();
        let next = line[pos + name.len()..].chars().next();
        prev.is_none_or(|c| !is_ident(c)) && next.is_none_or(|c| !is_ident(c))
    })
}

/// `Type name(` / `Type name;` (or `=`) with no call/field qualifier.
fn is_java_declaration(line: &str, name: &str, terminator: char) -> bool {
    let Some(pos) = identifier_occurrence(line, name) else {
        return false;
    };
    let before = &line[..pos];
    if before.ends_with('.') {
        return false;
    }
    let after = line[pos + name.len()..].trim_start();
    if !after.starts_with(terminator) {
        return false;
    }
    let ty = before.trim_end();
    if ty.is_empty() || ty.ends_with(|c: char| c.is_ascii_punctuation() && c != '>' && c != ']') {
        return false;
    }
    ty.split_whitespace()
        .next_back()
        .is_some_and(|t| !TYPE_STOPWORDS.contains(&t))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALI: &str = "\
.class public Lcom/example/A;
.super Ljava/lang/Object;
.field private static final COUNT:I
.method public <init>()V
    .registers 1

    return-void
.end method
.method public foo(I)I
    .registers 3

    invoke-static {v0}, Lcom/example/Util;->helper(I)I
    move-result v0
    return v0
.end method
.method public bar()V
    .registers 1

    const/4 v0, 0x1
    invoke-virtual {p0}, Lcom/example/A;->foo(I)I
    return-void
.end method
";

    fn byte_at(src: &str, needle: &str) -> usize {
        src.find(needle).expect("needle present")
    }

    /// A `.method` signature click resolves to the owning class + name + proto.
    #[test]
    fn smali_method_signature_resolves_owning_class() {
        let s = byte_at(SMALI, "init>()V");
        let (block, occ, sym) = smali_resolve("Lcom/example/A;#smali", SMALI, s);
        let sym = sym.expect("resolved");
        assert_eq!(sym.kind, SymbolKind::Method);
        assert_eq!(sym.owner.as_deref(), Some("Lcom/example/A;"));
        assert_eq!(sym.name, "<init>");
        assert_eq!(sym.proto.as_deref(), Some("()"));
        assert!(
            block.is_some(),
            "a signature click has an enclosing method block"
        );
        assert_eq!(occ.len(), 1, "one `init` occurrence in its block");
    }

    /// An `invoke-*` target click resolves to the *declared* class, not the
    /// document's own class (cross-class A→Util). The lexical token differs
    /// from the resolved name, so clicking inside `helper` must still resolve.
    #[test]
    fn smali_invoke_target_resolves_declared_class() {
        let s = byte_at(SMALI, "helper(I)I");
        let sym = smali_resolve("Lcom/example/A;#smali", SMALI, s)
            .2
            .expect("resolved");
        assert_eq!(sym.kind, SymbolKind::Method);
        assert_eq!(sym.owner.as_deref(), Some("Lcom/example/Util;"));
        assert_eq!(sym.proto.as_deref(), Some("(I)"));
    }

    /// The descriptor walk must survive a capital `L` inside the simple
    /// name (`rfind('L')` would yield `List;`).
    #[test]
    fn smali_invoke_target_keeps_the_package_of_a_capital_l_class() {
        let src = SMALI.replace(
            "invoke-static {v0}, Lcom/example/Util;->helper(I)I",
            "invoke-static {v0}, Ljava/util/List;->size()I",
        );
        let s = byte_at(&src, "size()I");
        let sym = smali_resolve("Lcom/example/A;#smali", &src, s)
            .2
            .expect("resolved");
        assert_eq!(sym.owner.as_deref(), Some("Ljava/util/List;"));
    }

    /// Same walk on the field path (`iget` owner).
    #[test]
    fn smali_field_target_keeps_the_package_of_a_capital_l_class() {
        let src = SMALI.replace(
            "invoke-static {v0}, Lcom/example/Util;->helper(I)I",
            "iget v0, p0, Landroid/widget/LinearLayout;->mBaselineAlignedChildIndex:I",
        );
        let s = byte_at(&src, "mBaselineAlignedChildIndex");
        let sym = smali_resolve("Lcom/example/A;#smali", &src, s)
            .2
            .expect("resolved");
        assert_eq!(sym.kind, SymbolKind::Field);
        assert_eq!(sym.owner.as_deref(), Some("Landroid/widget/LinearLayout;"));
    }

    /// A self-method invoke in another method still resolves its true class.
    #[test]
    fn smali_invoke_self_resolves_owning_class() {
        // Point at the method name `foo` inside `…Lcom/example/A;->foo(I)I`.
        let s = byte_at(SMALI, "->foo(I)I") + 2;
        let sym = smali_resolve("Lcom/example/A;#smali", SMALI, s)
            .2
            .expect("resolved");
        assert_eq!(sym.owner.as_deref(), Some("Lcom/example/A;"));
    }

    /// A `.field` signature click resolves as a field of the owning class.
    #[test]
    fn smali_field_line_resolves_owning_class() {
        let s = byte_at(SMALI, "COUNT:I");
        let sym = smali_resolve("Lcom/example/A;#smali", SMALI, s)
            .2
            .expect("resolved");
        assert_eq!(sym.kind, SymbolKind::Field);
        assert_eq!(sym.owner.as_deref(), Some("Lcom/example/A;"));
    }

    /// A register / instruction operand click is not a member.
    #[test]
    fn smali_register_is_not_a_member() {
        let s = byte_at(SMALI, "{v0}");
        let sym = smali_resolve("Lcom/example/A;#smali", SMALI, s).2;
        assert!(sym.is_none(), "a register is never a member");
    }

    /// A class descriptor token is a Class, wherever it appears.
    #[test]
    fn smali_class_descriptor_token_is_class() {
        let s = byte_at(SMALI, "Lcom/example/Util;");
        let sym = smali_resolve("Lcom/example/A;#smali", SMALI, s)
            .2
            .expect("resolved");
        assert_eq!(sym.kind, SymbolKind::Class);
    }

    /// Malformed smali fails closed (no panic, no fabricated owner).
    #[test]
    fn smali_malformed_fails_closed() {
        let (_b, _o, sym) = smali_resolve("Lcom/example/A;#smali", ".method bogus no parens", 0);
        assert!(sym.is_none());
    }

    #[test]
    fn java_method_declaration_resolves_owning_class() {
        let src = "class A {\n  void foo() {}\n}";
        let s = src.find("foo").unwrap();
        let sym = java_resolve("LA;", src, s, s + 3, "foo").expect("resolved");
        assert_eq!(sym.kind, SymbolKind::Method);
        assert_eq!(sym.owner.as_deref(), Some("LA;"));
    }

    #[test]
    fn java_unqualified_call_resolves_owning_class() {
        let src = "class A {\n  void m() { foo(); }\n}";
        let s = src.find("foo").unwrap();
        let sym = java_resolve("LA;", src, s, s + 3, "foo").expect("resolved");
        assert_eq!(sym.owner.as_deref(), Some("LA;"));
    }

    #[test]
    fn java_static_call_owner_is_the_receiver_class() {
        let src = "class A {\n  void m() { B.foo(); }\n}";
        let s = src.find("foo").unwrap();
        let sym = java_resolve("LA;", src, s, s + 3, "foo").expect("resolved");
        assert_eq!(sym.kind, SymbolKind::Method);
        assert_eq!(sym.owner.as_deref(), Some("LB;"));
    }

    #[test]
    fn java_qualified_call_uses_the_declared_receiver_type() {
        let src = "class A {\n  void m() { com.x.B b = null; b.foo(); }\n}";
        let s = src.find("foo").unwrap();
        let sym = java_resolve("LA;", src, s, s + 3, "foo").expect("resolved");
        assert_eq!(sym.owner.as_deref(), Some("Lcom/x/B;"));
    }

    #[test]
    fn java_simple_receiver_type_resolves_through_imports() {
        let src = "import com.x.Bar;\nclass A {\n  void m(Bar b) { b.foo(); }\n}";
        let s = src.find("foo").unwrap();
        let sym = java_resolve("LA;", src, s, s + 3, "foo").expect("resolved");
        assert_eq!(sym.owner.as_deref(), Some("Lcom/x/Bar;"));
    }

    #[test]
    fn java_receiver_type_ignores_a_this_assignment_above() {
        // `this.mContext = v0;` must not make `this` look like v0's type.
        let src = "class A {\n  void m() {\n    this.mContext = v0;\n    v0.foo();\n  }\n}";
        let s = src.find("foo").unwrap();
        let sym = java_resolve("LA;", src, s, s + 3, "foo").expect("resolved");
        assert_eq!(sym.owner, None);
    }

    #[test]
    fn java_primitive_local_is_not_a_type() {
        let src = "class A {\n  void m() {\n    int v0 = 0;\n    v0.foo();\n  }\n}";
        let s = src.find("foo").unwrap();
        let sym = java_resolve("LA;", src, s, s + 3, "foo").expect("resolved");
        assert_eq!(sym.owner, None);
    }

    #[test]
    fn java_undeclared_lowercase_receiver_stays_unknown() {
        let src = "class A {\n  void m() { obj.foo(); }\n}";
        let s = src.find("foo").unwrap();
        let sym = java_resolve("LA;", src, s, s + 3, "foo").expect("resolved");
        assert_eq!(sym.owner, None);
    }

    #[test]
    fn java_super_call_resolves_the_parent() {
        let src = "class A extends com.y.P {\n  void m() { super.foo(); }\n}";
        let s = src.find("foo").unwrap();
        let sym = java_resolve("LA;", src, s, s + 3, "foo").expect("resolved");
        assert_eq!(sym.owner.as_deref(), Some("Lcom/y/P;"));
    }

    #[test]
    fn java_qualified_field_uses_the_declared_receiver_type() {
        let src = "class A {\n  void m(com.x.B b) { b.count = 1; }\n}";
        let s = src.find("count").unwrap();
        let sym = java_resolve("LA;", src, s, s + 5, "count").expect("resolved");
        assert_eq!(sym.kind, SymbolKind::Field);
        assert_eq!(sym.owner.as_deref(), Some("Lcom/x/B;"));
    }

    #[test]
    fn declaration_line_finds_smali_member_lines() {
        let src = SMALI;
        assert_eq!(declaration_line(src, "COUNT", SymbolKind::Field), Some(2));
        // `foo` is declared on line 8; line 20 also calls it.
        assert_eq!(declaration_line(src, "foo", SymbolKind::Method), Some(8));
        assert_eq!(declaration_line(src, "nope", SymbolKind::Method), None);
    }

    #[test]
    fn declaration_line_takes_an_uninitialised_java_field() {
        let src =
            "class A {\n  private final String mName;\n  void m() {\n    mName.length();\n  }\n}\n";
        assert_eq!(declaration_line(src, "mName", SymbolKind::Field), Some(1));
    }

    #[test]
    fn identifier_occurrence_skips_substring_and_qualified_hits() {
        assert_eq!(identifier_occurrence("a.find_all(x)", "find"), None);
        assert_eq!(
            identifier_occurrence("  List find(int k) {", "find"),
            Some(7)
        );
        assert_eq!(identifier_occurrence("x.helper(1)", "helper"), Some(2));
    }

    #[test]
    fn declaration_line_finds_java_member_lines() {
        let src = "class A {\n  int count = 0;\n  void foo() {}\n  void bar() { a.foo(); }\n}";
        assert_eq!(declaration_line(src, "count", SymbolKind::Field), Some(1));
        assert_eq!(declaration_line(src, "foo", SymbolKind::Method), Some(2));
        assert_eq!(declaration_line(src, "nope", SymbolKind::Method), None);
    }

    #[test]
    fn java_local_is_not_a_member() {
        let src = "class A {\n  void m() { int foo = 0; }\n}";
        let s = src.find("foo").unwrap();
        assert!(java_resolve("LA;", src, s, s + 3, "foo").is_none());
    }

    #[test]
    fn java_field_this_resolves_owning_class() {
        let src = "class A {\n  void m() { this.field = 1; }\n}";
        let s = src.find("field").unwrap();
        let sym = java_resolve("LA;", src, s, s + 5, "field").expect("resolved");
        assert_eq!(sym.kind, SymbolKind::Field);
        assert_eq!(sym.owner.as_deref(), Some("LA;"));
    }
}
