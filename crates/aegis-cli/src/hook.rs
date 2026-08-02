//! `aegis hook install` / `uninstall` — the git pre-commit gate.
//!
//! Ported from the Go `internal/usecase/hook.go`. Two things make this
//! more than a file write:
//!
//! - **Framework detection.** A project that uses lefthook or husky has
//!   its pre-commit wiring in a config file, not in `.git/hooks`. Writing
//!   a native hook there would be ignored.
//! - **Managed markers.** Our entry is bracketed by sentinel comments, so
//!   reinstalling replaces our block instead of stacking duplicates, and
//!   uninstalling removes only our lines. The previous Rust version wrote
//!   `.git/hooks/pre-commit` wholesale, silently destroying any hook the
//!   user already had.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Sentinels. Both install and uninstall key on these, so nothing outside
/// the block is ever touched.
const MARKER_START: &str = "# >>> aegis-managed pre-commit (do not edit) >>>";
const MARKER_END: &str = "# <<< aegis-managed pre-commit <<<";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framework {
    Lefthook,
    Husky,
    Native,
}

impl Framework {
    fn name(self) -> &'static str {
        match self {
            Framework::Lefthook => "lefthook",
            Framework::Husky => "husky",
            Framework::Native => "native git hooks",
        }
    }
}

/// The scan step we wire in. Kept conservative: only staged lockfiles, and
/// only a block verdict fails the commit.
const SCAN_STEP: &str = r#"for lock in $(git diff --cached --name-only --diff-filter=ACM | grep -E '(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|go\.sum|requirements\.txt|poetry\.lock|Gemfile\.lock|composer\.lock)$' || true); do
  [ -f "$lock" ] || continue
  echo "aegis: scanning $lock"
  aegis ci "$lock" --fail-on block || {
    echo "aegis: commit blocked — blocking finding in $lock" >&2
    exit 1
  }
done
"#;

const LEFTHOOK_ENTRY: &str = r#"pre-commit:
  commands:
    aegis:
      run: aegis ci --fail-on block
"#;

fn native_hook() -> String {
    format!("#!/bin/sh\nset -e\n{}", inject("", SCAN_STEP))
}

/// Replace the marked block if present, otherwise append it.
///
/// Pure so the marker handling is testable without touching a filesystem.
pub(crate) fn inject(existing: &str, body: &str) -> String {
    let body = if body.ends_with('\n') {
        body.to_string()
    } else {
        format!("{body}\n")
    };
    let block = format!("{MARKER_START}\n{body}{MARKER_END}\n");

    if let Some(start) = existing.find(MARKER_START) {
        if let Some(rel_end) = existing[start..].find(MARKER_END) {
            let mut end = start + rel_end + MARKER_END.len();
            if existing[end..].starts_with('\n') {
                end += 1;
            }
            return format!("{}{}{}", &existing[..start], block, &existing[end..]);
        }
    }
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&block);
    out
}

/// Remove the marked block. Returns `None` when there was nothing of ours
/// to remove, so callers can report "not installed" rather than rewriting
/// the file for no reason.
pub(crate) fn strip(existing: &str) -> Option<String> {
    let start = existing.find(MARKER_START)?;
    let rel_end = existing[start..].find(MARKER_END)?;
    let mut end = start + rel_end + MARKER_END.len();
    if existing[end..].starts_with('\n') {
        end += 1;
    }
    Some(format!("{}{}", &existing[..start], &existing[end..]))
}

/// lefthook -> husky -> native, in that order. `None` when there is no git
/// repository to install into at all.
fn detect(dir: &Path) -> Option<(Framework, PathBuf)> {
    for f in ["lefthook.yml", ".lefthook.yml"] {
        let p = dir.join(f);
        if p.is_file() {
            return Some((Framework::Lefthook, p));
        }
    }
    if dir.join(".husky").is_dir() {
        return Some((Framework::Husky, dir.join(".husky").join("pre-commit")));
    }
    if dir.join(".git").is_dir() {
        return Some((Framework::Native, dir.join(".git/hooks/pre-commit")));
    }
    None
}

pub(crate) fn run_hook(install: bool, uninstall: bool) -> ExitCode {
    let cwd = Path::new(".");

    if !install && !uninstall {
        print!("{}", native_hook());
        return ExitCode::SUCCESS;
    }

    let Some((fw, path)) = detect(cwd) else {
        eprintln!("aegis: no git repository here (run `git init` first)");
        return ExitCode::from(2);
    };

    if uninstall {
        return do_uninstall(fw, &path);
    }
    do_install(fw, &path)
}

fn do_install(fw: Framework, path: &Path) -> ExitCode {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let body = match fw {
        Framework::Lefthook => LEFTHOOK_ENTRY,
        Framework::Husky | Framework::Native => SCAN_STEP,
    };

    let updated = match fw {
        // A fresh native hook needs the shebang; an existing one already
        // has whatever the user put there, so only our block is injected.
        Framework::Native if existing.is_empty() => native_hook(),
        Framework::Husky if existing.is_empty() => {
            format!("#!/bin/sh\n{}", inject(&existing, body))
        }
        _ => inject(&existing, body),
    };

    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("aegis: cannot create {}: {e}", parent.display());
            return ExitCode::from(2);
        }
    }
    if let Err(e) = std::fs::write(path, &updated) {
        eprintln!("aegis: cannot write {}: {e}", path.display());
        return ExitCode::from(2);
    }
    if matches!(fw, Framework::Husky | Framework::Native) {
        make_executable(path);
    }
    println!(
        "installed aegis pre-commit step ({}) → {}",
        fw.name(),
        path.display()
    );
    ExitCode::SUCCESS
}

fn do_uninstall(fw: Framework, path: &Path) -> ExitCode {
    let Ok(existing) = std::fs::read_to_string(path) else {
        println!("aegis: no aegis hook installed ({})", fw.name());
        return ExitCode::SUCCESS;
    };
    let Some(updated) = strip(&existing) else {
        println!("aegis: no aegis hook installed ({})", fw.name());
        return ExitCode::SUCCESS;
    };

    // If stripping our block leaves nothing but a shebang, the file was
    // ours alone — remove it rather than leaving an empty hook behind.
    let leftover = updated
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with("#!") && *l != "set -e")
        .count();
    let res = if leftover == 0 && fw != Framework::Lefthook {
        std::fs::remove_file(path).map(|_| true)
    } else {
        std::fs::write(path, &updated).map(|_| false)
    };
    match res {
        Ok(removed) => {
            let what = if removed { "removed" } else { "updated" };
            println!("aegis: hook {what} ({}) → {}", fw.name(), path.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("aegis: cannot write {}: {e}", path.display());
            ExitCode::from(2)
        }
    }
}

fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_appends_to_an_empty_file() {
        let out = inject("", "echo hi\n");
        assert!(out.starts_with(MARKER_START));
        assert!(out.trim_end().ends_with(MARKER_END));
    }

    #[test]
    fn inject_preserves_surrounding_content() {
        let existing = "user line before\n";
        let out = inject(existing, "ours\n");
        assert!(out.starts_with("user line before\n"));
        assert!(out.contains("ours"));
    }

    #[test]
    fn reinstall_replaces_rather_than_stacking() {
        // The bug markers exist to prevent: running install twice must not
        // leave two copies of our step.
        let once = inject("keep me\n", "v1\n");
        let twice = inject(&once, "v2\n");
        assert_eq!(twice.matches(MARKER_START).count(), 1);
        assert!(twice.contains("v2"));
        assert!(!twice.contains("v1"));
        assert!(twice.contains("keep me"));
    }

    #[test]
    fn strip_removes_only_our_block() {
        let existing = inject("before\n", "ours\n") + "after\n";
        let out = strip(&existing).expect("block present");
        assert_eq!(out, "before\nafter\n");
        assert!(!out.contains("ours"));
        assert!(!out.contains(MARKER_START));
    }

    #[test]
    fn strip_reports_when_nothing_is_ours() {
        assert!(strip("someone else's hook\n").is_none());
    }

    #[test]
    fn strip_is_idempotent() {
        let once = strip(&inject("x\n", "ours\n")).unwrap();
        assert!(strip(&once).is_none());
    }

    #[test]
    fn detect_prefers_lefthook_then_husky_then_native() {
        let d = tempdir();
        std::fs::create_dir_all(d.join(".git")).unwrap();
        assert_eq!(detect(&d).unwrap().0, Framework::Native);

        std::fs::create_dir_all(d.join(".husky")).unwrap();
        assert_eq!(detect(&d).unwrap().0, Framework::Husky);

        std::fs::write(d.join("lefthook.yml"), "").unwrap();
        assert_eq!(detect(&d).unwrap().0, Framework::Lefthook);

        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn detect_returns_none_without_a_repo() {
        let d = tempdir();
        assert!(detect(&d).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "aegis-hook-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
