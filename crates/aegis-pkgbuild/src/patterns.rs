//! Compiled regexes and the builtin IOC denylists.
//!
//! Ported verbatim from the Go `internal/domain/aur.go` so the two
//! implementations agree on what matches. Compiled once via `OnceLock`;
//! every pattern here is a literal that is known to compile, so the
//! `expect` calls are unreachable in practice.

use std::sync::OnceLock;

use regex::Regex;

macro_rules! lazy_re {
    ($name:ident, $pat:expr) => {
        pub(crate) fn $name() -> &'static Regex {
            static RE: OnceLock<Regex> = OnceLock::new();
            RE.get_or_init(|| Regex::new($pat).expect("literal regex compiles"))
        }
    };
}

lazy_re!(
    source_line,
    r"(?i)^\s*(?:source|_patches?|_src)\s*(?:\+?=|=)\s*\("
);
lazy_re!(url_assign, r#"(?i)^\s*url\s*=\s*["']?([^"'\s]+)"#);

// download-then-exec: curl/wget piped into a shell, or eval of $(...)
lazy_re!(
    net_exec,
    r"(?i)(curl|wget|fetch)\b[^|;&]*(\||;|&&)\s*(sh|bash|zsh|python|perl|node|eval)\b"
);
lazy_re!(eval_sub, r#"(?i)\beval\s+["'$]"#);

// base64 / hex obfuscation decoded then run
lazy_re!(
    b64_exec,
    r"(?i)base64\s+(-d|--decode)[^|]*\|\s*(sh|bash|zsh|python|perl|node)\b"
);
lazy_re!(hex_esc, r"(\\x[0-9a-fA-F]{2}){4,}");

// foreign toolchain injected into the build (the Atomic Arch tell)
lazy_re!(
    foreign_tool,
    r"(?i)\b(npm|npx|pnpm|yarn|pip|pip3)\s+(install|i|add|run|exec|ci)\b"
);

// credential / secret harvesting paths
lazy_re!(
    exfil_paths,
    r"(?i)(\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.config/google-chrome|\.mozilla/firefox|wallet\.dat|\.electrum|keychain|/etc/shadow)"
);

lazy_re!(bare_ip, r"https?://\d{1,3}(\.\d{1,3}){3}");
lazy_re!(url_token, r#"(?i)\b(?:git\+)?https?://[^\s"')]+"#);

// Bash functions a PKGBUILD/.install can define that run during install.
lazy_re!(
    pkgbuild_funcs,
    r"^\s*(prepare|build|package|pkgver|post_install|post_upgrade|pre_install|pre_upgrade)\s*\("
);

// --- new content rules (see AEGIS-PLAN.txt 3.5) ---

// Privilege escalation inside a build function. makepkg refuses to run as
// root by design, so a PKGBUILD reaching for sudo has no legitimate need.
// Anchored on a word boundary and required to be command-position (start
// of line, or after a pipe/;/&&/$( ) so `sudo_prompt=` and prose in a
// comment do not match.
lazy_re!(
    privilege_escalation,
    r"(?:^|[;&|]|\$\(|\bthen\b|\bdo\b)\s*(sudo|doas|pkexec|su)\s+[^\s]"
);

// An array element that is a bare filename rather than a URL: no scheme,
// no `::` rename syntax pointing at one. Used to find sources that ship
// inside the AUR repo itself.
lazy_re!(quoted_or_bare_word, r#"['"]([^'"]+)['"]|(\S+)"#);

/// AUR package names confirmed malicious in the 2025–2026 campaigns.
/// Exact-match here is a hard block regardless of current content — a
/// reverted PKGBUILD can still have a poisoned `.install` in a stale cache.
pub(crate) const DENY_PACKAGES: &[&str] = &[
    "librewolf-fix-bin",
    "firefox-patch-bin",
    "zen-browser-patched-bin",
];

/// Rogue registry packages that AUR malware pulled in during the build
/// (Atomic Arch infostealer stagers).
pub(crate) const DENY_DEPS: &[&str] = &["atomic-lockfile", "js-digest"];

/// Paste, shortener, and anonymous-file hosts. A source fetched from one
/// of these has no provenance at all.
pub(crate) const UNTRUSTED_HOSTS: &[&str] = &[
    "pastebin.com",
    "paste.ee",
    "ghostbin",
    "gist.github.com",
    "bit.ly",
    "tinyurl.com",
    "is.gd",
    "t.co",
    "transfer.sh",
    "anonfiles",
    "filebin",
    "0x0.st",
    "termbin.com",
];

/// Reports whether `name` is on the builtin malicious-AUR denylist.
pub fn package_denied(name: &str) -> bool {
    DENY_PACKAGES.contains(&name.trim())
}

/// Host portion of a URL, lowercased, with `git+` and scheme stripped.
pub(crate) fn host_of(u: &str) -> String {
    let u = u.strip_prefix("git+").unwrap_or(u);
    let u = u
        .strip_prefix("https://")
        .or_else(|| u.strip_prefix("http://"))
        .unwrap_or(u);
    let end = u.find(['/', ':']).unwrap_or(u.len());
    u[..end].to_ascii_lowercase()
}

pub(crate) fn is_code_host(h: &str) -> bool {
    ["github", "gitlab", "bitbucket", "codeberg", "sr.ht"]
        .iter()
        .any(|c| h.contains(c))
}
