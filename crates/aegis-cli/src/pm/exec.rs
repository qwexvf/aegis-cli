//! Finding and handing off to the real package manager.
//!
//! This is the half of the gate that has to be paranoid. `aegis pnpm …` is
//! reached *because* something named `pnpm` routed to us, so a naive
//! `which pnpm` here can find aegis again and spin forever. The Go original
//! does exactly that and relies on shell functions not being on `PATH`.
//!
//! Three defences, all needed:
//!
//! 1. `AEGIS_GATE_ACTIVE` in the environment means we already gated once —
//!    pass through immediately. Set on the child, so a nested install cannot
//!    re-gate.
//! 2. PATH resolution rejects any candidate that *is* aegis, by canonical
//!    path and by file name.
//! 3. If every candidate is aegis, fail loudly. Never fall through to a plain
//!    exec — that is the fork bomb.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Set on the child so a re-entered gate passes straight through.
pub(crate) const ENV_GATE_ACTIVE: &str = "AEGIS_GATE_ACTIVE";
/// User-facing bypass: `AEGIS_NO_GATE=1 pnpm install …`.
pub(crate) const ENV_NO_GATE: &str = "AEGIS_NO_GATE";

/// Should the gate be skipped entirely — because the user asked, or because
/// we are already inside a gated process?
pub(crate) fn gate_suppressed() -> bool {
    non_empty(ENV_NO_GATE) || non_empty(ENV_GATE_ACTIVE)
}

fn non_empty(key: &str) -> bool {
    std::env::var_os(key).is_some_and(|v| !v.is_empty())
}

/// Why the real binary could not be found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolveError {
    /// No such binary anywhere on PATH.
    NotFound,
    /// Every candidate resolved to aegis itself — running one would recurse.
    OnlyAegis(Vec<PathBuf>),
}

/// Find the real `pm` binary on `path`, refusing to return aegis itself.
///
/// `path` and `self_path` are parameters rather than environment reads so
/// this is unit-testable: `std::env::set_var` races across the test
/// harness's threads and is `unsafe` from edition 2024 on.
pub(crate) fn resolve_pm(
    pm: &str,
    path: &OsStr,
    self_path: Option<&Path>,
) -> Result<PathBuf, ResolveError> {
    let mut rejected = Vec::new();

    for dir in std::env::split_paths(path) {
        // An empty PATH component means the current directory in POSIX.
        // Executing `./pnpm` out of a checkout is the exact thing this tool
        // exists to prevent.
        if dir.as_os_str().is_empty() {
            continue;
        }
        let cand = dir.join(pm);
        if !is_executable_file(&cand) {
            continue;
        }
        let canon = std::fs::canonicalize(&cand).unwrap_or_else(|_| cand.clone());

        let is_self = self_path.is_some_and(|s| canon == s);
        // A renamed copy has a different inode, so also reject by name.
        let named_aegis = canon
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|n| n == "aegis" || n == "aegis.exe");

        if is_self || named_aegis {
            rejected.push(cand);
            continue;
        }

        // Return the candidate AS FOUND, never the canonicalized path.
        //
        // Load-bearing: mise's shims are symlinks to the `mise` binary, which
        // dispatches on argv[0]. Exec the canonical target and the user gets
        // mise's help text instead of pnpm. Canonicalization is only ever for
        // the identity check above.
        return Ok(cand);
    }

    if rejected.is_empty() {
        Err(ResolveError::NotFound)
    } else {
        Err(ResolveError::OnlyAegis(rejected))
    }
}

fn is_executable_file(p: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(p) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Resolve and hand off to the real package manager. On unix this replaces
/// the process image and never returns on success.
pub(crate) fn exec_real(pm: &str, args: &[String]) -> ExitCode {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let self_path = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok());

    match resolve_pm(pm, &path, self_path.as_deref()) {
        Ok(bin) => handoff(&bin, args),
        Err(ResolveError::NotFound) => {
            eprintln!("aegis: {pm}: not found in PATH");
            // 127 is the shell's "command not found", so wrappers behave.
            ExitCode::from(127)
        }
        Err(ResolveError::OnlyAegis(cands)) => {
            let list: Vec<String> = cands.iter().map(|p| p.display().to_string()).collect();
            eprintln!(
                "aegis: refusing to run — every {pm:?} on PATH resolves to aegis itself, \
                 which would recurse.\n  candidates: {}\nFix your PATH, or bypass with \
                 {ENV_NO_GATE}=1.",
                list.join(", ")
            );
            ExitCode::from(2)
        }
    }
}

/// Replace this process with the real package manager.
///
/// `exec` rather than spawn-and-wait: it gives correct signal handling, job
/// control, TTY ownership and exit-code propagation for free. With a child
/// process, Ctrl-C during a long install kills aegis while the manager keeps
/// running reparented — and fixing that needs libc, which this workspace
/// deliberately does not depend on.
///
/// Everything the gate wants to say or record must therefore happen before
/// this is called.
#[cfg(unix)]
fn handoff(bin: &Path, args: &[String]) -> ExitCode {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(bin)
        .args(args)
        .env(ENV_GATE_ACTIVE, "1")
        .exec();
    // exec() only returns on failure.
    eprintln!("aegis: cannot execute {}: {err}", bin.display());
    ExitCode::from(126)
}

#[cfg(not(unix))]
fn handoff(bin: &Path, args: &[String]) -> ExitCode {
    match std::process::Command::new(bin)
        .args(args)
        .env(ENV_GATE_ACTIVE, "1")
        .status()
    {
        Ok(st) => ExitCode::from(st.code().unwrap_or(1) as u8),
        Err(e) => {
            eprintln!("aegis: cannot execute {}: {e}", bin.display());
            ExitCode::from(126)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "aegis-pmexec-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// Write an executable stub at `dir/name`.
    fn stub(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        p
    }

    fn path_of(dirs: &[&Path]) -> std::ffi::OsString {
        std::env::join_paths(dirs.iter().map(|d| d.to_path_buf())).unwrap()
    }

    #[test]
    fn finds_a_real_binary() {
        let d = tmp("ok");
        let want = stub(&d, "pnpm");
        let got = resolve_pm("pnpm", &path_of(&[&d]), None).unwrap();
        assert_eq!(got, want);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn missing_binary_is_not_found() {
        let d = tmp("missing");
        assert_eq!(
            resolve_pm("pnpm", &path_of(&[&d]), None).unwrap_err(),
            ResolveError::NotFound
        );
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_symlink_to_ourselves_is_refused_not_followed() {
        // The fork bomb: a PATH shim named `pnpm` pointing at aegis.
        let d = tmp("selflink");
        let me = stub(&d, "aegis");
        let me_canon = fs::canonicalize(&me).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&me, d.join("pnpm")).unwrap();

        let err = resolve_pm("pnpm", &path_of(&[&d]), Some(&me_canon)).unwrap_err();
        assert!(
            matches!(err, ResolveError::OnlyAegis(ref v) if v.len() == 1),
            "expected OnlyAegis, got {err:?}"
        );
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_renamed_copy_of_aegis_is_refused_by_name() {
        // Different inode, so the identity check alone would let it through.
        let d = tmp("renamed");
        let other = tmp("renamed-src");
        let real_aegis = stub(&other, "aegis");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_aegis, d.join("pnpm")).unwrap();

        // self_path deliberately points somewhere else entirely.
        let err = resolve_pm("pnpm", &path_of(&[&d]), Some(Path::new("/nonexistent"))).unwrap_err();
        assert!(matches!(err, ResolveError::OnlyAegis(_)), "got {err:?}");
        fs::remove_dir_all(&d).ok();
        fs::remove_dir_all(&other).ok();
    }

    #[test]
    fn a_shadowing_shim_is_skipped_for_the_real_one_later_on_path() {
        let shim = tmp("shim");
        let real = tmp("real");
        let me = stub(&shim, "aegis");
        let me_canon = fs::canonicalize(&me).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&me, shim.join("pnpm")).unwrap();
        let want = stub(&real, "pnpm");

        let got = resolve_pm("pnpm", &path_of(&[&shim, &real]), Some(&me_canon)).unwrap();
        assert_eq!(got, want);
        fs::remove_dir_all(&shim).ok();
        fs::remove_dir_all(&real).ok();
    }

    #[test]
    fn mise_style_shim_is_returned_as_found_not_canonicalized() {
        // mise's shims are symlinks to the `mise` binary, which dispatches on
        // argv[0]. Returning the canonical target would run `mise` and print
        // its help instead of installing anything.
        let d = tmp("mise");
        let target = stub(&d, "mise");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, d.join("pnpm")).unwrap();

        let got = resolve_pm("pnpm", &path_of(&[&d]), None).unwrap();
        assert_eq!(got, d.join("pnpm"), "must not resolve through the symlink");
        assert_ne!(got, target);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_non_executable_file_is_skipped() {
        let d = tmp("noexec");
        let real = tmp("noexec-real");
        fs::write(d.join("pnpm"), "not executable").unwrap();
        let want = stub(&real, "pnpm");

        let got = resolve_pm("pnpm", &path_of(&[&d, &real]), None).unwrap();
        assert_eq!(got, want);
        fs::remove_dir_all(&d).ok();
        fs::remove_dir_all(&real).ok();
    }

    #[test]
    fn an_empty_path_component_never_means_the_current_directory() {
        // `PATH=:/usr/bin` would otherwise run ./pnpm from whatever checkout
        // the user happens to be standing in.
        let d = tmp("emptycomp");
        let joined = std::ffi::OsString::from(format!(":{}", d.display()));
        let want = stub(&d, "pnpm");
        let got = resolve_pm("pnpm", &joined, None).unwrap();
        assert_eq!(got, want);
        fs::remove_dir_all(&d).ok();
    }
}
