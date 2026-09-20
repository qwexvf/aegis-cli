//! Install-gate integration tests: argv passthrough, the recursion guard, and
//! shell-init.
//!
//! Network-free by design. Nothing here resolves a real package: the tests
//! that would need a registry point `AEGIS_HTTP_REPLAY` at an empty cassette
//! directory, which makes every request fail and exercises the fail-closed
//! path — the branch that matters most and the one a live registry cannot
//! reproduce on demand.
//!
//! No package manager is ever run either. A stub shell script stands in, so
//! "did the gate hand off?" is answered by what the stub printed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_aegis");

fn tmp(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "aegis-gate-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&d).unwrap();
    d
}

/// An executable stub that reports its arguments and exits with `code`.
fn stub_pm(dir: &Path, name: &str, code: i32) {
    let p = dir.join(name);
    fs::write(
        &p,
        format!("#!/bin/sh\necho \"RAN {name}: $*\"\nexit {code}\n"),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn all(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

/// Run aegis with `PATH` pointing at `bin_dir` first, plus extra env.
fn run_in(bin_dir: &Path, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Out {
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let audit = tmp("audit");
    let cache = tmp("cache");
    let mut c = Command::new(BIN);
    c.args(args)
        .current_dir(cwd)
        .env("PATH", path)
        // Keep the developer's real ~/.aegis and caches out of the tests.
        .env("AEGIS_AUDIT_DIR", &audit)
        .env("XDG_CACHE_HOME", &cache)
        .env_remove("AEGIS_NO_GATE")
        .env_remove("AEGIS_GATE_ACTIVE")
        .env_remove("AEGIS_GATE_ALLOW_UNCHECKED");
    for (k, v) in env {
        c.env(k, v);
    }
    let o = c.output().unwrap();
    Out {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

#[test]
fn a_non_install_verb_is_handed_straight_through() {
    let d = tmp("passthrough");
    stub_pm(&d, "npm", 0);
    let out = run_in(&d, &d, &["npm", "run", "build"], &[]);
    assert!(
        out.stdout.contains("RAN npm: run build"),
        "argv not forwarded verbatim: {out:?}",
        out = out.all()
    );
    assert_eq!(out.code, 0);
    fs::remove_dir_all(&d).ok();
}

#[test]
fn the_managers_exit_code_is_propagated() {
    let d = tmp("exitcode");
    stub_pm(&d, "npm", 7);
    let out = run_in(&d, &d, &["npm", "run", "test"], &[]);
    assert_eq!(out.code, 7, "exit code lost: {}", out.all());
    fs::remove_dir_all(&d).ok();
}

#[test]
fn flags_reach_the_manager_instead_of_being_eaten_by_clap() {
    // `--version` and `--help` are the ones that bite: clap would answer them
    // itself and the user would never see npm's output.
    let d = tmp("flags");
    stub_pm(&d, "npm", 0);
    for flag in ["--version", "--help"] {
        let out = run_in(&d, &d, &["npm", flag], &[]);
        assert!(
            out.stdout.contains(&format!("RAN npm: {flag}")),
            "{flag} was intercepted: {}",
            out.all()
        );
    }
    fs::remove_dir_all(&d).ok();
}

#[test]
fn a_manager_that_resolves_to_aegis_is_refused_rather_than_looping() {
    // The fork bomb. A PATH shim named `npm` that points at aegis means a
    // naive lookup finds us again, forever. This must fail loudly and fast.
    let d = tmp("recursion");
    #[cfg(unix)]
    std::os::unix::fs::symlink(BIN, d.join("npm")).unwrap();

    // Only our directory on PATH, so aegis is the only candidate.
    let out = Command::new(BIN)
        .args(["npm", "install", "lodash"])
        .env("PATH", d.display().to_string())
        .env("AEGIS_AUDIT_DIR", tmp("audit"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("recurse"),
        "expected a recursion refusal: {err}"
    );
    fs::remove_dir_all(&d).ok();
}

#[test]
fn a_missing_manager_reports_127_like_a_shell() {
    let d = tmp("notfound");
    let out = Command::new(BIN)
        .args(["npm", "run", "build"])
        .env("PATH", d.display().to_string())
        .env("AEGIS_AUDIT_DIR", tmp("audit"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(127));
    fs::remove_dir_all(&d).ok();
}

#[test]
fn the_bypass_skips_the_gate_entirely() {
    let d = tmp("bypass");
    stub_pm(&d, "npm", 0);
    // An empty replay dir fails every request, so a gate that ran at all
    // would block here. Reaching the stub proves it did not run.
    let out = run_in(
        &d,
        &d,
        &["npm", "install", "some-package"],
        &[
            ("AEGIS_NO_GATE", "1"),
            ("AEGIS_HTTP_REPLAY", &tmp("cass").display().to_string()),
        ],
    );
    assert!(
        out.stdout.contains("RAN npm: install some-package"),
        "{}",
        out.all()
    );
    assert_eq!(out.code, 0);
    fs::remove_dir_all(&d).ok();
}

#[test]
fn the_reentry_guard_passes_a_nested_gate_straight_through() {
    // Set on the child before exec, so an install that itself shells out to a
    // package manager does not re-gate and prompt mid-install.
    let d = tmp("reentry");
    stub_pm(&d, "npm", 0);
    let out = run_in(
        &d,
        &d,
        &["npm", "install", "some-package"],
        &[
            ("AEGIS_GATE_ACTIVE", "1"),
            ("AEGIS_HTTP_REPLAY", &tmp("cass").display().to_string()),
        ],
    );
    assert!(out.stdout.contains("RAN npm: install"), "{}", out.all());
    fs::remove_dir_all(&d).ok();
}

#[test]
fn an_unverifiable_package_blocks_and_names_its_escape_hatches() {
    let d = tmp("failclosed");
    stub_pm(&d, "npm", 0);
    let cass = tmp("cass");
    let out = run_in(
        &d,
        &d,
        &["npm", "install", "some-package"],
        &[("AEGIS_HTTP_REPLAY", &cass.display().to_string())],
    );
    assert_eq!(out.code, 1, "should fail closed: {}", out.all());
    assert!(
        !out.stdout.contains("RAN npm"),
        "the manager must not run: {}",
        out.all()
    );
    // A gate whose bypass is undiscoverable gets uninstalled instead.
    assert!(out.stderr.contains("AEGIS_NO_GATE=1"), "{}", out.stderr);
    assert!(
        out.stderr.contains("AEGIS_GATE_ALLOW_UNCHECKED=1"),
        "{}",
        out.stderr
    );
    fs::remove_dir_all(&d).ok();
}

#[test]
fn allow_unchecked_lets_an_unverifiable_package_through() {
    let d = tmp("allowunchecked");
    stub_pm(&d, "npm", 0);
    let cass = tmp("cass");
    let out = run_in(
        &d,
        &d,
        &["npm", "install", "some-package"],
        &[
            ("AEGIS_GATE_ALLOW_UNCHECKED", "1"),
            ("AEGIS_HTTP_REPLAY", &cass.display().to_string()),
        ],
    );
    assert!(out.stdout.contains("RAN npm: install"), "{}", out.all());
    assert!(out.stderr.contains("unverified"), "{}", out.stderr);
    fs::remove_dir_all(&d).ok();
}

#[test]
fn a_local_path_spec_is_skipped_not_blocked() {
    // There is no registry entry to check, so blocking would be wrong — but
    // staying silent would overstate what was verified.
    let d = tmp("nonregistry");
    stub_pm(&d, "npm", 0);
    let cass = tmp("cass");
    let out = run_in(
        &d,
        &d,
        &["npm", "install", "./local-thing"],
        &[("AEGIS_HTTP_REPLAY", &cass.display().to_string())],
    );
    assert!(
        out.stdout.contains("RAN npm: install ./local-thing"),
        "{}",
        out.all()
    );
    assert!(out.stderr.contains("skipped"), "{}", out.stderr);
    fs::remove_dir_all(&d).ok();
}

#[test]
fn a_bare_install_with_no_lockfile_says_so_and_proceeds() {
    // Refusing every `npm install` in a directory we cannot read a lockfile
    // from would be worse than useless.
    let d = tmp("nolock");
    let work = tmp("nolock-work");
    stub_pm(&d, "npm", 0);
    let out = run_in(&d, &work, &["npm", "install"], &[]);
    assert!(out.stdout.contains("RAN npm: install"), "{}", out.all());
    assert!(
        out.stderr.contains("lockfile not checked"),
        "{}",
        out.stderr
    );
    fs::remove_dir_all(&d).ok();
    fs::remove_dir_all(&work).ok();
}

// ---------------------------------------------------------------- shell-init

#[test]
fn shell_init_emits_syntactically_valid_shell() {
    for (shell, checker, flag) in [
        ("bash", "bash", "-n"),
        ("zsh", "zsh", "-n"),
        ("fish", "fish", "--no-execute"),
    ] {
        // Skip a shell that is not installed rather than failing the suite.
        if Command::new(checker).arg("--version").output().is_err() {
            continue;
        }
        let out = Command::new(BIN)
            .args(["shell-init", shell])
            .output()
            .unwrap();
        assert!(out.status.success(), "{shell}: generation failed");

        let f = tmp("snippet").join(format!("init.{shell}"));
        fs::write(&f, &out.stdout).unwrap();
        let check = Command::new(checker).arg(flag).arg(&f).output().unwrap();
        assert!(
            check.status.success(),
            "{shell} rejected the generated snippet: {}",
            String::from_utf8_lossy(&check.stderr)
        );
    }
}

#[test]
fn an_unsupported_shell_exits_two_with_empty_stdout() {
    // `eval "$(aegis shell-init nu)"` must degrade to `eval ""`, never to
    // evaluating an error message.
    let out = Command::new(BIN)
        .args(["shell-init", "powershell"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "stdout must be empty on error");
    assert!(!out.stderr.is_empty(), "the reason belongs on stderr");
}

#[test]
fn an_injected_pm_name_is_rejected() {
    // This string would otherwise reach a generated `eval`.
    let out = Command::new(BIN)
        .args(["shell-init", "bash", "--pm", "npm; rm -rf ~"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
}

#[test]
fn installing_twice_leaves_one_block_and_uninstall_restores_the_file() {
    let d = tmp("rc");
    let rc = d.join("rcfile");
    let original = "# my settings\nexport FOO=1\n";
    fs::write(&rc, original).unwrap();
    let rc_s = rc.display().to_string();

    for _ in 0..2 {
        let out = Command::new(BIN)
            .args([
                "shell-init",
                "bash",
                "--pm",
                "pnpm",
                "--install",
                "--rc",
                &rc_s,
            ])
            .env_remove("CI")
            .env_remove("GITHUB_ACTIONS")
            .output()
            .unwrap();
        assert!(out.status.success());
    }
    let body = fs::read_to_string(&rc).unwrap();
    assert_eq!(
        body.matches("aegis shell integration (do not edit)")
            .count(),
        1,
        "installing twice stacked blocks"
    );
    assert!(
        body.starts_with("# my settings\n"),
        "clobbered prior content"
    );

    let out = Command::new(BIN)
        .args(["shell-init", "bash", "--uninstall", "--rc", &rc_s])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        fs::read_to_string(&rc).unwrap(),
        original,
        "uninstall did not restore the file exactly"
    );
    fs::remove_dir_all(&d).ok();
}

#[test]
fn uninstalling_when_absent_leaves_the_file_byte_identical() {
    let d = tmp("rc-absent");
    let rc = d.join("rcfile");
    let original = "# untouched\n";
    fs::write(&rc, original).unwrap();
    let out = Command::new(BIN)
        .args([
            "shell-init",
            "bash",
            "--uninstall",
            "--rc",
            &rc.display().to_string(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(fs::read_to_string(&rc).unwrap(), original);
    fs::remove_dir_all(&d).ok();
}

#[test]
fn install_refuses_in_ci_unless_forced() {
    let d = tmp("rc-ci");
    let rc = d.join("rcfile");
    fs::write(&rc, "").unwrap();
    let rc_s = rc.display().to_string();

    let out = Command::new(BIN)
        .args(["shell-init", "bash", "--install", "--rc", &rc_s])
        .env("CI", "true")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "should refuse in CI");
    assert_eq!(
        fs::read_to_string(&rc).unwrap(),
        "",
        "file was written anyway"
    );

    let out = Command::new(BIN)
        .args(["shell-init", "bash", "--install", "--force", "--rc", &rc_s])
        .env("CI", "true")
        .output()
        .unwrap();
    assert!(out.status.success(), "--force should override");
    assert!(fs::read_to_string(&rc)
        .unwrap()
        .contains("aegis shell-init"));
    fs::remove_dir_all(&d).ok();
}
