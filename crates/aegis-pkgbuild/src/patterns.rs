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
// process substitution: the shell runs first, reading a fetched payload —
// `bash <(curl ...)`, `source <(wget ...)`, `. <(fetch ...)`. The pipe form
// above never matches this because there's no `|`/`;`/`&&`.
lazy_re!(
    proc_subst_exec,
    r"(?i)(^|[\s;&|])(sh|bash|zsh|source|eval|\.)\s+<\([^)]*(curl|wget|fetch)\b"
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
// `eval "package_$_p() {` — the split-package idiom used by kernel and
// other multi-output PKGBUILDs. Generates functions, does not hide payloads.
lazy_re!(
    split_package_eval,
    r#"(?i)^\s*eval\s+["']?(package|prepare|build|check)_"#
);

lazy_re!(quoted_or_bare_word, r#"['"]([^'"]+)['"]|(\S+)"#);

// --- .install root-context rules ---
//
// These apply ONLY to .install hook bodies, which pacman runs AS ROOT.
// `install -Dm755` in package() is ordinary; the same line in post_install
// is not. Base rates below are measured across the 41 .INSTALL scripts
// shipped by 1200 official repo packages — every one of these patterns
// occurs ZERO times, which is what makes them safe to weight heavily.

// Fetching anything at install time. 0/41.
lazy_re!(
    ih_network,
    r"(?i)\b(curl|wget|ncat|ftp|scp|rsync)\s|\bnc\s+-|\bpython3?\s+-c\s.{0,40}urllib|\bgit\s+clone\b"
);
// Granting sudo rights. 0/41.
lazy_re!(ih_sudoers, r"(?i)/etc/sudoers|\bvisudo\b");
// Injecting into every process. 0/41.
lazy_re!(ih_ld_preload, r"(?i)/etc/ld\.so\.preload");
// SSH key persistence. 0/41.
lazy_re!(ih_authorized_keys, r"(?i)authorized_keys");
// Making something setuid after the fact. 0/41.
lazy_re!(ih_setuid, r"(?i)\bchmod\s+(u?\+s\b|[24][0-7]{3}\b)");
// Shell-startup and scheduler persistence. 0/41.
lazy_re!(
    ih_persistence,
    r"(?i)/etc/profile\.d/|\.bashrc|\.zshrc|\.bash_profile|\bcrontab\b|/etc/cron\.|/etc/systemd/system/"
);
// Adding an account to a privileged group. 0/41.
lazy_re!(
    ih_priv_group,
    r"(?i)\b(usermod|gpasswd)\b.*\b(wheel|sudo|root|adm|docker)\b"
);
// Dropping an executable file. `install -d` (make a directory) is the only
// form that occurs in the sample, so an explicit executable mode is the
// signal. 0/41.
lazy_re!(
    ih_drop_exec,
    r"(?i)\binstall\s+[^\n]*-[A-Za-z]*m[A-Za-z]*\s*[0-7]?[0-7][0-7][157]\b|\bchmod\s+\+x\b"
);
// Enabling a system unit. Arch policy says packages must not; 0/41 do it
// system-wide (--global and --user forms are legitimate and excluded).
//
// The regex crate has no look-around, so the carve-out lives in
// `is_system_enable` rather than in the pattern.
lazy_re!(ih_enable_unit_raw, r"(?i)\bsystemctl\b.*\benable\b");

/// True when the line installs an executable FILE, not a directory.
///
/// `install -d -o root -g root -m 755 some/dir` creates a directory and is
/// perfectly ordinary — it was the only false positive left across the 41
/// real .INSTALL scripts. Lowercase `-d` is the directory-only flag;
/// `-Dm755` (capital D, "make leading dirs") still installs a file.
pub(crate) fn is_exec_drop(line: &str) -> bool {
    ih_drop_exec().is_match(line) && !line.split_whitespace().any(|t| t == "-d")
}

/// True for a system-wide `systemctl enable`.
pub(crate) fn is_system_enable(line: &str) -> bool {
    ih_enable_unit_raw().is_match(line) && !line.contains("--global") && !line.contains("--user")
}

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

/// Host-blocklist match that is not a naive substring test.
///
/// The Go original used `strings.Contains`, which makes `t.co` match
/// `raw.githubusercon`+`tent.co`+`m` — four of 97 sampled packages were
/// flagged as "paste/shortener host" for fetching from
/// raw.githubusercontent.com. Entries with a dot are domains and match
/// exactly or as a parent domain; bare entries are brand names and match a
/// whole label.
pub(crate) fn is_untrusted_host(h: &str) -> bool {
    UNTRUSTED_HOSTS.iter().any(|bad| {
        if bad.contains('.') {
            h == *bad || h.ends_with(&format!(".{bad}"))
        } else {
            h.split('.').any(|label| label.contains(bad))
        }
    })
}

pub(crate) fn is_code_host(h: &str) -> bool {
    ["github", "gitlab", "bitbucket", "codeberg", "sr.ht"]
        .iter()
        .any(|c| h.contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every pattern is behind `expect("literal regex compiles")`, so an
    /// uncompilable one is a panic the first time that rule runs rather
    /// than a build error. The regex crate has no look-around, which is
    /// easy to reach for by habit — this catches it at test time.
    #[test]
    fn every_pattern_compiles() {
        let _ = (
            source_line(),
            url_assign(),
            net_exec(),
            eval_sub(),
            b64_exec(),
            hex_esc(),
            foreign_tool(),
            exfil_paths(),
            bare_ip(),
            url_token(),
            pkgbuild_funcs(),
            privilege_escalation(),
            split_package_eval(),
            quoted_or_bare_word(),
            ih_network(),
            ih_sudoers(),
            ih_ld_preload(),
            ih_authorized_keys(),
            ih_setuid(),
            ih_persistence(),
            ih_priv_group(),
            ih_drop_exec(),
            ih_enable_unit_raw(),
        );
    }

    #[test]
    fn system_enable_carve_out() {
        assert!(is_system_enable("  systemctl enable foo.service"));
        assert!(!is_system_enable(
            "  systemctl --global enable pipewire.socket"
        ));
        assert!(!is_system_enable("  systemctl --user enable foo.service"));
        assert!(!is_system_enable("  systemctl daemon-reload"));
    }
}
