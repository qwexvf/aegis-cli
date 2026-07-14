//! JS constant-folding pass. Port of the `String.fromCharCode` folding
//! in `ast/js/taint.go`. Catches obfuscation that tree-sitter queries
//! can't express: `eval(String.fromCharCode(112,97,...))` decoded to a
//! suspicious host/URL or a `curl|sh` command.
//!
//! Scope: inline literal numeric args (the common case). Symbol-table /
//! spread-of-array and full tainted-sink tracking are a follow-up.

use aegis_domain::Capability;
use tree_sitter::Node;

use crate::Findings;

/// A hit found during the walk, applied to `Findings` afterwards (so the
/// recursive walk doesn't hold a mutable borrow of `Findings`).
struct Hit {
    capability: Capability,
    line: usize,
    snippet: String,
}

/// The [`crate::scanner::PostPass`] entry point. Walks for foldable
/// `String.fromCharCode(...)` calls and flags suspicious decoded strings.
pub fn taint_pass(root: Node, src: &[u8], path: &str, findings: &mut Findings) {
    let mut hits = Vec::new();
    walk(root, &mut |n| {
        if n.kind() != "call_expression" {
            return;
        }
        if call_function_name(n, src).as_deref() != Some("String.fromCharCode") {
            return;
        }
        if let Some(s) = eval_from_charcode(n, src) {
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
        }
    });

    for h in hits {
        findings.add_capability(h.capability);
        if findings.collect_evidence {
            findings.add_evidence(h.capability, path, h.line, h.snippet);
        }
    }
}

/// Pre-order walk. Mirrors `walkAST`.
fn walk(node: Node, f: &mut impl FnMut(Node)) {
    f(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, f);
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

/// Fold `String.fromCharCode(n1, n2, …)` with literal numeric args into a
/// string. Mirrors the inline-literal branch of `evalFromCharCode`.
fn eval_from_charcode(call: Node, src: &[u8]) -> Option<String> {
    let args = call.child_by_field_name("arguments")?;
    let mut nums: Vec<u32> = Vec::new();
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        match child.kind() {
            "," | "(" | ")" => continue,
            "number" => {
                let txt = child.utf8_text(src).ok()?;
                // integer, or float truncated (matches the Go fallback).
                let n = txt
                    .parse::<i64>()
                    .ok()
                    .or_else(|| txt.parse::<f64>().ok().map(|f| f as i64))?;
                if !(0..0x110000).contains(&n) {
                    return None;
                }
                nums.push(n as u32);
            }
            _ => return None, // unknown arg (spread/var) — bail (follow-up)
        }
    }
    if nums.is_empty() {
        return None;
    }
    Some(nums.into_iter().filter_map(char::from_u32).collect())
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
