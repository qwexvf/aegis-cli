//! Inspection of a **built** pacman package (`.pkg.tar.zst`).
//!
//! This is the gate that runs after makepkg and before `pacman -U`. It sees
//! what the build actually produced, which no amount of PKGBUILD text
//! analysis can reach: a package can fetch a payload from a legitimate host
//! and drop it wherever it likes, and the PKGBUILD will look ordinary.
//!
//! Adversarial testing of the text rules alone found four trivial evasions
//! (payload in `.install`, binary in a subdirectory, fetch-and-exec from
//! GitHub, base64 split across lines). Three of the four land here, because
//! whatever they do has to show up in the produced file list eventually.
//!
//! Pure: the caller reads the archive and passes the entry list in.

use crate::types::{Finding, ScanResult, Severity};

/// One entry in the built package's tar stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkgEntry {
    /// Path relative to the package root, no leading slash: `usr/bin/foo`.
    pub path: String,
    /// Unix mode bits, for the setuid/setgid check.
    pub mode: u32,
    pub size: u64,
}

const SETUID: u32 = 0o4000;
const SETGID: u32 = 0o2000;

/// Directory prefixes a package may legitimately install into. Anything
/// outside these is writing somewhere pacman-managed packages do not go.
const STANDARD_PREFIXES: &[&str] = &["usr/", "etc/", "opt/", "srv/", "var/", "boot/"];

/// Inspect the file list of a built package.
pub fn inspect_package(name: &str, entries: &[PkgEntry]) -> ScanResult {
    let mut findings = Vec::new();

    for e in entries {
        let p = e.path.trim_start_matches("./").trim_start_matches('/');

        // Metadata members, not files placed on the filesystem.
        if matches!(p, ".PKGINFO" | ".BUILDINFO" | ".MTREE" | ".CHANGELOG") {
            continue;
        }

        // The install script, run by pacman AS ROOT. Its mere presence is
        // ordinary — 3.4% of 1200 sampled repo packages ship one — so this
        // is informational on its own. What deserves attention is a package
        // GAINING one it did not have before, which needs the previous
        // version's file list and belongs in the diff layer.
        if p == ".INSTALL" {
            findings.push(f(
                Severity::Medium,
                "install-script",
                p,
                "ships a .INSTALL script — pacman runs it as root at install time",
            ));
            continue;
        }

        // Loaded into EVERY dynamically linked process on the system.
        if p == "etc/ld.so.preload" {
            findings.push(f(
                Severity::Critical,
                "ld-preload",
                p,
                "installs /etc/ld.so.preload — injected into every dynamically \
                 linked process on the system",
            ));
        }

        // Grants sudo rights without the admin ever editing sudoers.
        if p.starts_with("etc/sudoers.d/") && !p.ends_with('/') {
            findings.push(f(
                Severity::Critical,
                "sudoers-drop-in",
                p,
                "drops a sudoers rule — can grant passwordless root",
            ));
        }

        // Runs as root on EVERY future pacman transaction, forever, even
        // after this package is the only thing that put it there.
        if p.starts_with("usr/share/libalpm/hooks/") && !p.ends_with('/') {
            findings.push(f(
                Severity::High,
                "pacman-hook",
                p,
                "installs a pacman hook — root code that runs on every future \
                 pacman transaction",
            ));
        }

        // Authenticates logins; a rogue module is a credential capture.
        if p.starts_with("usr/lib/security/") && p.ends_with(".so") {
            findings.push(f(
                Severity::High,
                "pam-module",
                p,
                "installs a PAM module — sits in the authentication path",
            ));
        }

        if p.starts_with("etc/cron.") || p.starts_with("var/spool/cron/") {
            findings.push(f(
                Severity::High,
                "cron-drop-in",
                p,
                "installs a cron job — scheduled execution outside the package \
                 lifecycle",
            ));
        }

        if e.mode & SETUID != 0 {
            findings.push(f(
                Severity::High,
                "setuid-binary",
                p,
                "setuid binary — runs as its owner regardless of who executes it",
            ));
        } else if e.mode & SETGID != 0 && !p.ends_with('/') {
            findings.push(f(Severity::Medium, "setgid-binary", p, "setgid binary"));
        }

        // Directories are created implicitly by many packages; only flag
        // actual files landing outside the managed prefixes.
        if !p.ends_with('/') && !p.is_empty() && !STANDARD_PREFIXES.iter().any(|s| p.starts_with(s))
        {
            // Writing into a user's home or /root is the persistence shape
            // and has no legitimate use: across 1200 sampled repo packages
            // exactly one installed outside the prefixes at all, and it was
            // `filesystem` owning the /bin /lib /sbin compat symlinks.
            let personal = p.starts_with("home/") || p.starts_with("root/");
            findings.push(f(
                if personal {
                    Severity::Critical
                } else {
                    Severity::High
                },
                "file-outside-prefix",
                p,
                if personal {
                    "installs into a user home directory — packages do not own user data, and this is how persistence is planted"
                } else {
                    "installs a file outside usr/ etc/ opt/ srv/ var/ boot/"
                },
            ));
        }
    }

    let verdict = ScanResult::derive_verdict(&findings);
    ScanResult {
        package: name.to_string(),
        findings,
        verdict,
    }
}

fn f(severity: Severity, rule: &'static str, path: &str, message: &str) -> Finding {
    Finding {
        severity,
        rule,
        where_: "package".into(),
        message: message.into(),
        evidence: path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Verdict;

    fn e(path: &str, mode: u32) -> PkgEntry {
        PkgEntry {
            path: path.into(),
            mode,
            size: 10,
        }
    }
    fn rules(r: &ScanResult) -> Vec<&str> {
        r.findings.iter().map(|f| f.rule).collect()
    }

    #[test]
    fn ordinary_package_is_clean() {
        let r = inspect_package(
            "x",
            &[
                e(".PKGINFO", 0o644),
                e("usr/bin/x", 0o755),
                e("usr/share/doc/x/README", 0o644),
                e("usr/lib/systemd/system/x.service", 0o644),
                e("etc/x.conf", 0o644),
            ],
        );
        assert_eq!(r.verdict, Verdict::Allow, "{:#?}", r.findings);
    }

    #[test]
    fn ld_preload_blocks() {
        let r = inspect_package("x", &[e("etc/ld.so.preload", 0o644)]);
        assert_eq!(r.verdict, Verdict::Block);
        assert!(rules(&r).contains(&"ld-preload"));
    }

    #[test]
    fn sudoers_drop_in_blocks() {
        let r = inspect_package("x", &[e("etc/sudoers.d/x", 0o440)]);
        assert_eq!(r.verdict, Verdict::Block);
    }

    #[test]
    fn pacman_hook_warns() {
        let r = inspect_package("x", &[e("usr/share/libalpm/hooks/x.hook", 0o644)]);
        assert!(rules(&r).contains(&"pacman-hook"));
    }

    #[test]
    fn setuid_flagged() {
        let r = inspect_package("x", &[e("usr/bin/x", 0o4755)]);
        assert!(rules(&r).contains(&"setuid-binary"));
    }

    #[test]
    fn file_outside_prefix_flagged() {
        // The persistence shape: drop into the user's home or /root.
        for p in ["home/user/.bashrc", "root/.ssh/authorized_keys", "tmp/x"] {
            let r = inspect_package("x", &[e(p, 0o644)]);
            assert!(rules(&r).contains(&"file-outside-prefix"), "missed {p}");
        }
    }

    #[test]
    fn install_script_is_informational_not_outside_prefix() {
        // .INSTALL is a metadata member, not a file on the filesystem. It
        // accounted for 41 of 42 file-outside-prefix hits across 1200 real
        // packages before this was separated out.
        let r = inspect_package("x", &[e(".INSTALL", 0o644), e("usr/bin/x", 0o755)]);
        assert!(rules(&r).contains(&"install-script"));
        assert!(!rules(&r).contains(&"file-outside-prefix"));
        assert_eq!(r.verdict, Verdict::Allow, "medium alone must not warn");
    }

    #[test]
    fn home_and_root_writes_block() {
        for p in ["home/user/.bashrc", "root/.ssh/authorized_keys"] {
            let r = inspect_package("x", &[e(p, 0o644)]);
            assert_eq!(r.verdict, Verdict::Block, "should block {p}");
        }
    }

    #[test]
    fn filesystem_style_compat_symlinks_only_warn() {
        // The one real package that installs outside the prefixes.
        let r = inspect_package("filesystem", &[e("bin", 0o777), e("lib64", 0o777)]);
        assert_eq!(r.verdict, Verdict::Warn);
    }

    #[test]
    fn leading_dot_slash_is_normalised() {
        let r = inspect_package("x", &[e("./etc/ld.so.preload", 0o644)]);
        assert!(rules(&r).contains(&"ld-preload"));
    }

    #[test]
    fn metadata_members_are_not_files_outside_prefix() {
        let r = inspect_package(
            "x",
            &[
                e(".PKGINFO", 0o644),
                e(".BUILDINFO", 0o644),
                e(".MTREE", 0o644),
            ],
        );
        assert_eq!(r.verdict, Verdict::Allow, "{:#?}", r.findings);
    }
}
