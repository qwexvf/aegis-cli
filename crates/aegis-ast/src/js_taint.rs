//! JS taint analysis. Port of `ast/js/taint.go`. Two passes that run after the
//! tree-sitter pattern queries, catching obfuscation that requires tracking
//! values across variable assignments — something the queries can't express.
//!
//! Pass 1 — constant folding: a numeric-array or `String.fromCharCode` var that
//! evaluates to a suspicious URL/host or a `curl|sh` command.
//! Pass 2 — taint tracking: a var assigned from a decode source (`atob`,
//! `Buffer.from(..,'base64')`, `String.fromCharCode`) that reaches a dangerous
//! sink (`eval`/`exec`/`fetch`/…).
//!
//! Both passes are conservative — false positives beat missed detections.

use std::collections::HashMap;

use aegis_domain::Capability;
use tree_sitter::Node;

use crate::Findings;

/// A hit found during a walk, applied to `Findings` afterwards (so the
/// recursive walk doesn't hold a mutable borrow of `Findings`).
struct Hit {
    capability: Capability,
    line: usize,
    snippet: String,
}

/// One variable's shallow static value. Mirrors `jsVar`.
#[derive(Default, Clone)]
struct JsVar {
    /// Statically computed string value, when known.
    evaluated: Option<String>,
    /// Assigned from a decode/obfuscation source (atob / Buffer.from base64 /
    /// String.fromCharCode).
    tainted: bool,
}

/// The [`crate::scanner::PostPass`] entry point. Builds a symbol table, then
/// runs the constant-folding and tainted-sink passes.
pub fn taint_pass(root: Node, src: &[u8], path: &str, findings: &mut Findings) {
    let symtab = build_symtab(root, src);
    let mut hits = Vec::new();
    check_constant_folding(root, src, &symtab, &mut hits);
    check_tainted_sinks(src, &symtab, &mut hits);

    for h in hits {
        findings.add_capability(h.capability);
        if findings.collect_evidence {
            findings.add_evidence(h.capability, path, h.line, h.snippet);
        }
    }
}

/// Walk every `variable_declarator` and record name → [`JsVar`]. Pre-order, so
/// an earlier `const a = [..]` is available when a later
/// `const b = String.fromCharCode(...a)` is evaluated.
fn build_symtab(root: Node, src: &[u8]) -> HashMap<String, JsVar> {
    let mut tab: HashMap<String, JsVar> = HashMap::new();
    walk(root, &mut |n| {
        if n.kind() != "variable_declarator" {
            return;
        }
        let (Some(name_node), Some(val_node)) = (
            n.child_by_field_name("name"),
            n.child_by_field_name("value"),
        ) else {
            return;
        };
        if name_node.kind() != "identifier" {
            return;
        }
        let Ok(name) = name_node.utf8_text(src) else {
            return;
        };
        let mut v = JsVar::default();
        match val_node.kind() {
            "array" => {
                if let Some(nums) = eval_numeric_array(val_node, src) {
                    v.evaluated = Some(nums_to_string(&nums));
                }
            }
            "call_expression" => match call_function_name(val_node, src).as_deref() {
                Some("atob" | "btoa") => v.tainted = true,
                Some("Buffer.from") => v.tainted = call_has_base64_arg(val_node, src),
                Some("String.fromCharCode") => {
                    v.tainted = true;
                    v.evaluated = eval_from_charcode(val_node, src, &tab);
                }
                _ => {}
            },
            _ => {}
        }
        tab.insert(name.to_string(), v);
    });
    tab
}

/// Pass 1: a variable (or inline `String.fromCharCode`) that folds to a
/// suspicious string.
fn check_constant_folding(
    root: Node,
    src: &[u8],
    tab: &HashMap<String, JsVar>,
    hits: &mut Vec<Hit>,
) {
    for (name, v) in tab {
        let Some(s) = &v.evaluated else { continue };
        if contains_suspicious_url(s) || contains_suspicious_host(s) {
            hits.push(Hit {
                capability: Capability::SuspiciousUrl,
                line: 0,
                snippet: format!("constant-fold: {name} = {:?}", truncate(s, 80)),
            });
        }
        if looks_like_shell_fetch(s) {
            hits.push(Hit {
                capability: Capability::InstallHookSuspicious,
                line: 0,
                snippet: format!("constant-fold: {name} = {:?}", truncate(s, 80)),
            });
        }
    }

    // Also fold inline String.fromCharCode(n1, n2, …) at its call site.
    walk(root, &mut |n| {
        if n.kind() != "call_expression" {
            return;
        }
        if call_function_name(n, src).as_deref() != Some("String.fromCharCode") {
            return;
        }
        let Some(s) = eval_from_charcode(n, src, tab) else {
            return;
        };
        if contains_suspicious_url(&s) || contains_suspicious_host(&s) {
            hits.push(Hit {
                capability: Capability::SuspiciousUrl,
                line: n.start_position().row + 1,
                snippet: format!("constant-fold String.fromCharCode → {}", truncate(&s, 80)),
            });
        }
        if looks_like_shell_fetch(&s) {
            hits.push(Hit {
                capability: Capability::InstallHookSuspicious,
                line: n.start_position().row + 1,
                snippet: format!("constant-fold String.fromCharCode → {}", truncate(&s, 80)),
            });
        }
    });
}

/// Dangerous sink function names → their capability.
const SINK_FUNCS: &[&str] = &[
    "eval",
    "Function",
    "execSync",
    "exec",
    "spawn",
    "spawnSync",
    "fetch",
    "XMLHttpRequest",
];

fn sink_to_capability(sink: &str) -> Capability {
    match sink {
        "eval" | "Function" => Capability::DynamicEval,
        "execSync" | "exec" | "spawn" | "spawnSync" => Capability::ShellSpawn,
        "fetch" | "XMLHttpRequest" => Capability::NetEgress,
        _ => Capability::DynamicEval,
    }
}

/// Pass 2: a tainted variable used as an argument to a dangerous sink. Text-
/// level (like the Go original) because tree-sitter queries can't cross-
/// reference a var's definition and its use sites.
fn check_tainted_sinks(src: &[u8], tab: &HashMap<String, JsVar>, hits: &mut Vec<Hit>) {
    let tainted: Vec<&String> = tab
        .iter()
        .filter(|(_, v)| v.tainted)
        .map(|(name, _)| name)
        .collect();
    if tainted.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(src) else {
        return;
    };
    for sink in SINK_FUNCS {
        for var in &tainted {
            if sink_call_contains_var(text, sink, var) {
                let cap = sink_to_capability(sink);
                hits.push(Hit {
                    capability: cap,
                    line: 0,
                    snippet: format!("taint: decoded var {var:?} reaches {sink}()"),
                });
            }
        }
    }
}

/// True when `text` contains `sink(...var...)` — the sink called as a word,
/// with `var` appearing as a whole word inside the first argument group (up to
/// the first `)`). Mirrors the Go regex `\bsink\s*\([^)]*\bvar\b`.
fn sink_call_contains_var(text: &str, sink: &str, var: &str) -> bool {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(rel) = text[from..].find(sink) {
        let start = from + rel;
        let end = start + sink.len();
        from = start + 1;
        // Word boundary before the sink name.
        if start > 0 && is_word_byte(bytes[start - 1]) {
            continue;
        }
        // Optional whitespace, then '('.
        let mut i = end;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'(' {
            continue;
        }
        // Argument slice up to the first ')'.
        let arg_start = i + 1;
        let arg_end = text[arg_start..]
            .find(')')
            .map_or(bytes.len(), |r| arg_start + r);
        if word_in(&text[arg_start..arg_end], var) {
            return true;
        }
    }
    false
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// `needle` appears in `hay` bounded by non-word chars on both sides.
fn word_in(hay: &str, needle: &str) -> bool {
    let hb = hay.as_bytes();
    let mut from = 0;
    while let Some(rel) = hay[from..].find(needle) {
        let start = from + rel;
        let end = start + needle.len();
        from = start + 1;
        let before_ok = start == 0 || !is_word_byte(hb[start - 1]);
        let after_ok = end >= hb.len() || !is_word_byte(hb[end]);
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Pre-order walk. Mirrors `walkAST`, but iterative.
///
/// Recursion here was a stack overflow — one frame per level of AST nesting,
/// and nesting depth is attacker-controlled. `@babel/traverse@8.0.4` and
/// `@babel/types@8.0.4` (both scanned by nearly every JS project) crashed the
/// scanner outright on a 512 KiB thread stack; a hand-written file can nest
/// arbitrarily deep. A tree cursor walks the same order in constant stack.
fn walk(root: Node, f: &mut impl FnMut(Node)) {
    let mut cursor = root.walk();
    'descend: loop {
        f(cursor.node());
        if cursor.goto_first_child() {
            continue;
        }
        // Leaf: climb until a node has a next sibling, stopping at the root so
        // a subtree walk never escapes upward into the rest of the tree.
        loop {
            if cursor.node() == root {
                return;
            }
            if cursor.goto_next_sibling() {
                continue 'descend;
            }
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

/// Dot-joined function name of a call. Mirrors `callFunctionName`.
fn call_function_name(call: Node, src: &[u8]) -> Option<String> {
    let f = call.child_by_field_name("function")?;
    match f.kind() {
        "identifier" => f.utf8_text(src).ok().map(String::from),
        "member_expression" => {
            let obj = f.child_by_field_name("object")?;
            let prop = f.child_by_field_name("property")?;
            Some(format!(
                "{}.{}",
                obj.utf8_text(src).ok()?,
                prop.utf8_text(src).ok()?
            ))
        }
        _ => None,
    }
}

/// Statically evaluate `String.fromCharCode(...)`. Handles literal numeric args
/// and a spread of a previously-evaluated numeric-array var (`...a`). Mirrors
/// `evalFromCharCode`.
fn eval_from_charcode(call: Node, src: &[u8], tab: &HashMap<String, JsVar>) -> Option<String> {
    let args = call.child_by_field_name("arguments")?;
    let mut nums: Vec<u32> = Vec::new();
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        match child.kind() {
            "," | "(" | ")" => continue,
            "number" => {
                let txt = child.utf8_text(src).ok()?;
                let n = txt.parse::<i64>().ok()?; // Go bails on non-int here
                if !(0..0x110000).contains(&n) {
                    return None;
                }
                nums.push(n as u32);
            }
            "spread_element" => {
                // ...varName — return its already-evaluated string, if known.
                let inner = child.child(1)?; // skip "..."
                if inner.kind() != "identifier" {
                    return None;
                }
                let var = inner.utf8_text(src).ok()?;
                return tab.get(var).and_then(|v| v.evaluated.clone());
            }
            _ => return None,
        }
    }
    if nums.is_empty() {
        return None;
    }
    Some(nums.into_iter().filter_map(char::from_u32).collect())
}

/// Evaluate a numeric-literal array node (`[104, 116, …]`) to its code-point
/// values. `None` if any element isn't a plain number. Mirrors
/// `evalNumericArray`.
fn eval_numeric_array(array: Node, src: &[u8]) -> Option<Vec<u32>> {
    let mut nums: Vec<u32> = Vec::new();
    let mut cursor = array.walk();
    for child in array.children(&mut cursor) {
        match child.kind() {
            "," | "[" | "]" => continue,
            "number" => {
                let txt = child.utf8_text(src).ok()?;
                let n = txt
                    .parse::<i64>()
                    .ok()
                    .or_else(|| txt.parse::<f64>().ok().map(|f| f as i64))?;
                if !(0..0x110000).contains(&n) {
                    return None;
                }
                nums.push(n as u32);
            }
            _ => return None,
        }
    }
    (!nums.is_empty()).then_some(nums)
}

/// Convert code points to a string, dropping out-of-range values.
fn nums_to_string(nums: &[u32]) -> String {
    nums.iter().filter_map(|&n| char::from_u32(n)).collect()
}

/// True when a call has a `'base64'` string-literal argument
/// (`Buffer.from(x, 'base64')`). Mirrors `callHasBase64Arg`.
fn call_has_base64_arg(call: Node, src: &[u8]) -> bool {
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        if child.kind() == "string" {
            if let Ok(t) = child.utf8_text(src) {
                if t.trim_matches(['"', '\'']).eq_ignore_ascii_case("base64") {
                    return true;
                }
            }
        }
    }
    false
}

/// Suspicious host substrings (subset of source_patterns, per the Go
/// original's short list for the folder output check).
const SUSPICIOUS_HOSTS: &[&str] = &[
    "pastebin.com",
    "hastebin.com",
    "paste.ee",
    "transfer.sh",
    "file.io",
    "0x0.st",
    "ngrok.io",
    "ngrok-free.app",
    "trycloudflare.com",
    "discord.com/api/webhooks",
    "api.telegram.org/bot",
    "ipinfo.io",
    "ipify.org",
    "getsession.org",
];

/// Folded string is an http(s) URL to a suspicious host. Mirrors
/// `containsSuspiciousURLString`.
fn contains_suspicious_url(s: &str) -> bool {
    let lower = s.to_lowercase();
    if !lower.contains("http://") && !lower.contains("https://") {
        return false;
    }
    SUSPICIOUS_HOSTS.iter().any(|h| lower.contains(h))
}

/// Folded string contains a suspicious bare hostname (scheme added at
/// runtime). Mirrors `containsSuspiciousHostString`.
fn contains_suspicious_host(s: &str) -> bool {
    let lower = s.trim().to_lowercase();
    SUSPICIOUS_HOSTS.iter().any(|h| {
        let bare = h.split('/').next().unwrap_or(h);
        lower.contains(bare)
    })
}

/// `curl|sh` / `wget|bash` style fetch-execute. Hand-rolled (mirrors
/// `shellCmdPattern` intent without a regex dep).
fn looks_like_shell_fetch(s: &str) -> bool {
    let lower = s.to_lowercase();
    let has_fetcher = lower.contains("curl") || lower.contains("wget");
    if !has_fetcher || !lower.contains('|') {
        return false;
    }
    [
        "|sh", "| sh", "|bash", "| bash", "|zsh", "| zsh", "|ksh", "| ksh", "|dash", "| dash",
    ]
    .iter()
    .any(|p| lower.contains(p))
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect()
    }
}
