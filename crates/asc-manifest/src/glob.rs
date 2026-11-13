//! Ports of the two glob evaluators in `android.os.PatternMatcher`.
//!
//! An `<data>` filter stores `android:pathPattern` as `PATTERN_SIMPLE_GLOB`
//! and `android:pathAdvancedPattern` as `PATTERN_ADVANCED_GLOB`; the platform
//! evaluates both in `PatternMatcher.match`, so the verdict for a path that
//! carries them is deterministic and never "unknown" (oracle rows
//! T16/T17/T18/T22). Both are hand-written, backtracking-free walkers, not
//! regular expressions — the port keeps the original control flow rather
//! than describing it.
//!
//! Semantics that look like bugs are AOSP's: the simple glob terminates a
//! pattern on a trailing `.*` alone, `.` matches one character, `X*` repeats
//! `X`, and `\` escapes the next character. The advanced glob is a linear
//! greedy matcher over a parsed token list; an invalid pattern throws at
//! construction, which surfaces here as `Err`.

/// `PatternMatcher.PATTERN_SIMPLE_GLOB`.
pub(crate) fn glob_match(pattern: &str, matched: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = matched.chars().collect();
    let np = pat.len();
    if np == 0 {
        return text.is_empty();
    }
    let nm = text.len();
    let (mut ip, mut im) = (0usize, 0usize);
    let mut next = pat[0];
    while ip < np && im < nm {
        let mut c = next;
        ip += 1;
        next = pat.get(ip).copied().unwrap_or('\0');
        let escaped = c == '\\';
        if escaped {
            c = next;
            ip += 1;
            next = pat.get(ip).copied().unwrap_or('\0');
        }
        if next == '*' {
            if !escaped && c == '.' {
                // `.*`: everything up to the next pattern character matches.
                if ip >= np - 1 {
                    return true;
                }
                ip += 1;
                next = pat[ip];
                if next == '\\' {
                    ip += 1;
                    next = pat.get(ip).copied().unwrap_or('\0');
                }
                loop {
                    if text[im] == next {
                        break;
                    }
                    im += 1;
                    if im >= nm {
                        break;
                    }
                }
                if im == nm {
                    return false;
                }
                ip += 1;
                next = pat.get(ip).copied().unwrap_or('\0');
                im += 1;
            } else {
                // `X*`: only the run of `X` matches.
                loop {
                    if text[im] != c {
                        break;
                    }
                    im += 1;
                    if im >= nm {
                        break;
                    }
                }
                ip += 1;
                next = pat.get(ip).copied().unwrap_or('\0');
            }
        } else {
            if c != '.' && text[im] != c {
                return false;
            }
            im += 1;
        }
    }
    if ip >= np && im >= nm {
        return true;
    }
    // The match may be exhausted with a trailing `.*` still to consume.
    np >= 2 && ip == np - 2 && pat[ip] == '.' && pat[ip + 1] == '*'
}

/// `PatternMatcher.PATTERN_ADVANCED_GLOB`.
pub(crate) fn advanced_match(pattern: &str, matched: &str) -> Result<bool, String> {
    let tokens = parse_advanced(pattern)?;
    Ok(match_tokens(&tokens, matched))
}

/// Parsed advanced-glob token: a literal (as `char`), a set pair, or one of
/// the structural markers the matcher walks over.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tok {
    Lit(char),
    /// A repetition bound; only ever appears inside a `{min,max}` range.
    Num(i64),
    Any,
    SetStart,
    InvSetStart,
    SetStop,
    RangeStart,
    RangeStop,
    ZeroMore,
    OneMore,
}

/// `PatternMatcher.parseAndVerifyAdvancedPattern`.
fn parse_advanced(pattern: &str) -> Result<Vec<Tok>, String> {
    /// `MAX_PATTERN_STORAGE`.
    const MAX: usize = 2048;
    let p: Vec<char> = pattern.chars().collect();
    let lp = p.len();
    let mut out: Vec<Tok> = Vec::new();
    let (mut ip, mut in_set, mut in_range, mut in_char_class) = (0usize, false, false, false);
    while ip < lp {
        if out.len() > MAX - 3 {
            return Err("pattern is too large".into());
        }
        let mut c = p[ip];
        let mut add_literal = false;
        match c {
            '[' if !in_set => {
                if p.get(ip + 1) == Some(&'^') {
                    out.push(Tok::InvSetStart);
                    ip += 1;
                } else {
                    out.push(Tok::SetStart);
                }
                in_set = true;
                ip += 1;
                continue;
            }
            ']' if in_set => {
                if let Some(Tok::SetStart | Tok::InvSetStart) = out.last() {
                    return Err("you must define characters in a set".into());
                }
                out.push(Tok::SetStop);
                in_set = false;
                in_char_class = false;
            }
            '{' if !in_set => {
                match out.last() {
                    None
                    | Some(Tok::ZeroMore | Tok::OneMore | Tok::RangeStart | Tok::RangeStop) => {
                        return Err("modifier must follow a token".into());
                    }
                    _ => {}
                }
                out.push(Tok::RangeStart);
                in_range = true;
                ip += 1;
                continue;
            }
            '}' if in_range => {
                // `a{}` pushes no bound pair; AOSP then reads past the
                // token array, so reject it here instead.
                if !matches!(out.last(), Some(Tok::Num(_))) {
                    return Err("range without bounds".into());
                }
                out.push(Tok::RangeStop);
                in_range = false;
            }
            '*' if !in_set => {
                match out.last() {
                    None
                    | Some(Tok::ZeroMore | Tok::OneMore | Tok::RangeStart | Tok::RangeStop) => {
                        return Err("modifier must follow a token".into());
                    }
                    _ => {}
                }
                out.push(Tok::ZeroMore);
            }
            '+' if !in_set => {
                match out.last() {
                    None
                    | Some(Tok::ZeroMore | Tok::OneMore | Tok::RangeStart | Tok::RangeStop) => {
                        return Err("modifier must follow a token".into());
                    }
                    _ => {}
                }
                out.push(Tok::OneMore);
            }
            '.' if !in_set => out.push(Tok::Any),
            '\\' => {
                if ip + 1 >= lp {
                    return Err("escape found at end of pattern".into());
                }
                ip += 1;
                c = p[ip];
                add_literal = true;
            }
            _ => add_literal = true,
        }
        if in_set {
            if in_char_class {
                out.push(Tok::Lit(c));
                in_char_class = false;
            } else if ip + 2 < lp && p[ip + 1] == '-' && p[ip + 2] != ']' {
                // Start of a `a-z` class: the upper end is the next char.
                in_char_class = true;
                out.push(Tok::Lit(c));
                ip += 1;
            } else {
                // A lone char is a degenerate range of itself.
                out.push(Tok::Lit(c));
                out.push(Tok::Lit(c));
            }
        } else if in_range {
            let Some(rel) = p[ip..].iter().position(|&x| x == '}') else {
                return Err("range not ended with '}'".into());
            };
            let body: String = p[ip..ip + rel].iter().collect();
            let parse = |s: &str| {
                s.parse::<i64>()
                    .map_err(|_| "range number format incorrect".to_string())
            };
            let (min, max) = match body.split_once(',') {
                None => {
                    let n = parse(&body)?;
                    (n, n)
                }
                Some((min, max)) => (
                    parse(min)?,
                    if max.is_empty() {
                        i64::MAX
                    } else {
                        parse(max)?
                    },
                ),
            };
            if min > max {
                return Err("range quantifier minimum is greater than maximum".into());
            }
            out.push(Tok::Num(min));
            out.push(Tok::Num(max));
            ip += rel;
            continue; // `}` is consumed by the range parse.
        } else if add_literal {
            out.push(Tok::Lit(c));
        }
        ip += 1;
    }
    if in_set {
        return Err("set was not terminated".into());
    }
    if in_range {
        return Err("range not ended with '}'".into());
    }
    Ok(out)
}

fn bound(tok: Tok) -> i64 {
    match tok {
        Tok::Lit(c) => i64::from(u32::from(c)),
        Tok::Num(n) => n,
        _ => 0,
    }
}

/// The verb of a parsed token, resolved before its modifier is read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Any,
    Set,
    InvSet,
    Literal,
}

/// `PatternMatcher.matchAdvancedPattern` + `matchChars` + `matchChar`.
fn match_tokens(tokens: &[Tok], matched: &str) -> bool {
    let text: Vec<char> = matched.chars().collect();
    let lp = tokens.len();
    let lm = text.len();
    let (mut ip, mut im) = (0usize, 0usize);
    while ip < lp {
        let mut set_start = 0usize;
        let mut set_end = 0usize;
        let kind = match tokens[ip] {
            Tok::Any => {
                ip += 1;
                Kind::Any
            }
            Tok::SetStart | Tok::InvSetStart => {
                let inverse = tokens[ip] == Tok::InvSetStart;
                set_start = ip + 1;
                ip += 1;
                while ip < lp && tokens[ip] != Tok::SetStop {
                    ip += 1;
                }
                // `set_end` stays exclusive: the stop token index.
                set_end = ip;
                ip += 1;
                if inverse { Kind::InvSet } else { Kind::Set }
            }
            _ => {
                set_start = ip;
                ip += 1;
                Kind::Literal
            }
        };
        let (min_rep, max_rep) = if ip >= lp {
            (1, 1)
        } else {
            match tokens[ip] {
                Tok::ZeroMore => {
                    ip += 1;
                    (0, i64::MAX)
                }
                Tok::OneMore => {
                    ip += 1;
                    (1, i64::MAX)
                }
                Tok::RangeStart => {
                    ip += 1;
                    let min = bound(tokens[ip]);
                    ip += 1;
                    let max = bound(tokens[ip]);
                    ip += 2; // skips the range stop
                    (min, max)
                }
                _ => (1, 1),
            }
        };
        if min_rep > max_rep {
            return false;
        }
        let mut matched_len = 0i64;
        while matched_len < max_rep
            && match_char(
                &text,
                im + matched_len as usize,
                kind,
                tokens,
                set_start,
                set_end,
            )
        {
            matched_len += 1;
        }
        if matched_len < min_rep {
            return false;
        }
        im += matched_len as usize;
    }
    ip >= lp && im >= lm
}

/// `PatternMatcher.matchChar` — one character against one token.
fn match_char(
    text: &[char],
    im: usize,
    kind: Kind,
    tokens: &[Tok],
    set_start: usize,
    set_end: usize,
) -> bool {
    if im >= text.len() {
        return false;
    }
    let c = u32::from(text[im]);
    let in_set = || {
        tokens[set_start..set_end]
            .as_chunks::<2>()
            .0
            .iter()
            .any(|r| (bound(r[0]) as u32) <= c && c <= (bound(r[1]) as u32))
    };
    match kind {
        Kind::Any => true,
        Kind::Set => in_set(),
        Kind::InvSet => !in_set(),
        Kind::Literal => {
            text[im] == char::from_u32(bound(tokens[set_start]) as u32).unwrap_or('\u{fffd}')
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{advanced_match, glob_match};

    #[test]
    fn simple_glob_literal_and_any() {
        assert!(glob_match("abc", "abc"));
        assert!(!glob_match("abc", "abd"));
        assert!(glob_match("a.c", "abc"));
        assert!(!glob_match("a.c", "ac"));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "a"));
    }

    #[test]
    fn simple_glob_star_repeats_the_previous_character() {
        // A `*` repeats the character *before* it, so a leading `*` has
        // nothing to repeat and matches the empty remainder only.
        assert!(!glob_match("*", "anything"));
        assert!(!glob_match("*", ""));
        assert!(glob_match("ab*", "ab"));
        assert!(glob_match("ab*", "abbbb"));
        assert!(!glob_match("ab*", "abc"));
    }

    #[test]
    fn simple_glob_dot_star_is_a_free_tail() {
        assert!(glob_match(".*", ""));
        assert!(glob_match(".*", "xyz"));
        assert!(glob_match("a.*", "abc"));
        assert!(glob_match("a.*c", "abbbc"));
        // The free-tail scan needs the following character to exist.
        assert!(!glob_match("a.*c", "abbb"));
    }

    #[test]
    fn simple_glob_escape_is_literal() {
        assert!(glob_match("a\\*b", "a*b"));
        assert!(!glob_match("a\\*b", "aXXb"));
        assert!(glob_match("\\a", "a"));
    }

    #[test]
    fn advanced_glob_sets_and_ranges() {
        assert!(advanced_match("[a-z]+", "abc").unwrap());
        assert!(!advanced_match("[a-z]+", "ab1").unwrap());
        assert!(advanced_match("[^0-9]{2}", "ab").unwrap());
        assert!(!advanced_match("[^0-9]{2}", "a1").unwrap());
        assert!(advanced_match("a{2}", "aa").unwrap());
        assert!(!advanced_match("a{2}", "a").unwrap());
        assert!(advanced_match("a{1,}", "aaaa").unwrap());
        assert!(!advanced_match("a{2,3}", "aaaa").unwrap());
        assert!(advanced_match(".*", "anything").unwrap());
    }

    #[test]
    fn advanced_glob_is_greedy_without_backtracking() {
        // A star eats all it can, so a following literal only survives when
        // the star's own class stops before it.
        assert!(advanced_match("[a-z]*1", "ab1").unwrap());
        assert!(!advanced_match(".*1", "a1").unwrap());
    }

    #[test]
    fn advanced_glob_rejects_malformed_patterns() {
        assert!(advanced_match("abc\\", "abc").is_err());
        assert!(advanced_match("[abc", "a").is_err());
        assert!(advanced_match("*a", "a").is_err());
        assert!(advanced_match("a{}", "a").is_err());
        assert!(advanced_match("a{3,1}", "a").is_err());
        // dangling `{`: the loop ends with `in_range` still set.
        assert!(advanced_match("a{", "a").is_err());
    }
}
