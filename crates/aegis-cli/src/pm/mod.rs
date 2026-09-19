//! Package-manager models for the install gate.
//!
//! One [`Pm`] per supported manager, with everything that differs between
//! them expressed as **data** in a `&'static PmDef` rather than as code. That
//! keeps the per-manager knowledge auditable in one table, lets a single test
//! assert invariants across all seven, and makes "added a manager, forgot the
//! spec parser" a compile error via the exhaustive `match` in [`Pm::def`].
//!
//! Deliberately *not* a trait: the Go original used an interface because Go
//! has no sum types, and porting that shape would buy dynamic dispatch we
//! never use. Nothing here does I/O — exec lives in `pm::exec`, the gate in
//! `crate::gate` — so this module and `argv`/`spec` are unit-testable with no
//! process and no network.

// The argv walker and spec parser are consumed by the gate, which lands in
// the next commit; `exec` is wired now. The attribute goes away with the gate.
#![allow(dead_code)]

pub(crate) mod argv;
pub(crate) mod exec;
pub(crate) mod spec;

use aegis_domain::Ecosystem;

/// How a package spec is written in this ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpecStyle {
    /// `lodash`, `lodash@^4`, `@scope/pkg@1.2.3`
    Npm,
    /// `serde`, `serde@1.0`
    Cargo,
    /// `requests`, `requests==2.31.0`, `requests[security]>=2,<3`
    Pep508,
    /// `example.com/m`, `example.com/m@v1.2.3`
    GoModule,
}

/// A supported package manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pm {
    Npm,
    Pnpm,
    Yarn,
    Bun,
    Cargo,
    Pip,
    Go,
}

/// Everything that differs between managers.
pub(crate) struct PmDef {
    /// Subcommand name, and the binary we hand off to.
    pub name: &'static str,
    pub eco: Ecosystem,
    /// The canonical install verb, for messages and override hints.
    pub install_verb: &'static str,
    /// Verbs that install something. `argv[0]` is matched against these.
    pub install_verbs: &'static [&'static str],
    /// Verbs that always install from a lockfile, regardless of positionals.
    pub lockfile_verbs: &'static [&'static str],
    /// Flags whose *next* token is a value, not a package name. Getting this
    /// wrong invents a phantom package out of a flag's argument, which is why
    /// the tables are per-manager: npm's `-w` takes a value, pnpm's does not.
    pub value_flags: &'static [&'static str],
    /// Every flag we know about. A flag outside this set sets
    /// `saw_unknown_flag`, which the gate uses to soften a block — if our
    /// parse may have invented a package, refusing the install is worse than
    /// missing one.
    pub known_flags: &'static [&'static str],
    /// Lockfile basenames to look for in lockfile mode, in priority order.
    pub lockfiles: &'static [&'static str],
    pub spec_style: SpecStyle,
}

impl Pm {
    pub(crate) fn def(self) -> &'static PmDef {
        match self {
            Pm::Npm => &NPM,
            Pm::Pnpm => &PNPM,
            Pm::Yarn => &YARN,
            Pm::Bun => &BUN,
            Pm::Cargo => &CARGO,
            Pm::Pip => &PIP,
            Pm::Go => &GO,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        self.def().name
    }

    pub(crate) fn ecosystem(self) -> Ecosystem {
        self.def().eco
    }

    /// Every manager, for table-wide tests and for `shell-init`.
    pub(crate) const ALL: [Pm; 7] = [
        Pm::Npm,
        Pm::Pnpm,
        Pm::Yarn,
        Pm::Bun,
        Pm::Cargo,
        Pm::Pip,
        Pm::Go,
    ];

    /// Parse a manager name. `pip3` is accepted as `pip`; note that
    /// `python -m pip` cannot be wrapped and is documented as uncovered.
    pub(crate) fn parse(s: &str) -> Option<Pm> {
        match s {
            "npm" => Some(Pm::Npm),
            "pnpm" => Some(Pm::Pnpm),
            "yarn" => Some(Pm::Yarn),
            "bun" => Some(Pm::Bun),
            "cargo" => Some(Pm::Cargo),
            "pip" | "pip3" => Some(Pm::Pip),
            "go" => Some(Pm::Go),
            _ => None,
        }
    }
}

/// npm. The install-verb list is npm's own prefix-matching set, typo aliases
/// included; `ci` is added, which the Go original never gated even though it
/// is the CI install path.
static NPM: PmDef = PmDef {
    name: "npm",
    eco: Ecosystem::Npm,
    install_verb: "install",
    install_verbs: &[
        "install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal",
        "isntall", "add", "ci",
    ],
    lockfile_verbs: &["ci"],
    // NOTE: `--workspaces` is a boolean in modern npm and is deliberately
    // absent here — the Go table lists it, which eats the following package
    // name.
    value_flags: &[
        "--workspace",
        "-w",
        "--prefix",
        "--registry",
        "--tag",
        "--access",
        "--omit",
        "--include",
        "--install-strategy",
        "--loglevel",
        "--cache",
        "--userconfig",
        "--globalconfig",
        "--before",
        "--save-prefix",
        "--node-options",
    ],
    known_flags: &[
        "--workspace",
        "-w",
        "--workspaces",
        "--prefix",
        "--registry",
        "--tag",
        "--access",
        "--omit",
        "--include",
        "--install-strategy",
        "--loglevel",
        "--cache",
        "--userconfig",
        "--globalconfig",
        "--before",
        "--save-prefix",
        "--node-options",
        "--save",
        "--save-dev",
        "-D",
        "--save-exact",
        "-E",
        "--save-optional",
        "-O",
        "--save-peer",
        "--no-save",
        "--global",
        "-g",
        "--force",
        "-f",
        "--legacy-peer-deps",
        "--strict-peer-deps",
        "--package-lock",
        "--no-package-lock",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--dry-run",
        "--silent",
        "-s",
        "--verbose",
        "--prefer-offline",
        "--prefer-online",
        "--offline",
        "--production",
        "--omit-dev",
    ],
    lockfiles: &["package-lock.json", "npm-shrinkwrap.json"],
    spec_style: SpecStyle::Npm,
};

/// pnpm. `-w` is `--workspace-root`, a *boolean*, unlike npm — the single
/// clearest reason these tables are per-manager. `dlx` fetches and executes
/// in one step, so it is gated like an install.
static PNPM: PmDef = PmDef {
    name: "pnpm",
    eco: Ecosystem::Npm,
    install_verb: "add",
    install_verbs: &["add", "install", "i", "up", "update", "dlx"],
    lockfile_verbs: &[],
    value_flags: &[
        "--filter",
        "-F",
        "--dir",
        "-C",
        "--store-dir",
        "--registry",
        "--virtual-store-dir",
        "--reporter",
        "--config",
        "--package",
        "--workspace-concurrency",
    ],
    known_flags: &[
        "--filter",
        "-F",
        "--dir",
        "-C",
        "--store-dir",
        "--registry",
        "--virtual-store-dir",
        "--reporter",
        "--config",
        "--package",
        "--workspace-concurrency",
        "--workspace-root",
        "-w",
        "--save-dev",
        "-D",
        "--save-prod",
        "-P",
        "--save-optional",
        "-O",
        "--save-exact",
        "-E",
        "--save-peer",
        "--global",
        "-g",
        "--frozen-lockfile",
        "--no-frozen-lockfile",
        "--prefer-frozen-lockfile",
        "--lockfile-only",
        "--ignore-scripts",
        "--offline",
        "--prefer-offline",
        "--shamefully-hoist",
        "--recursive",
        "-r",
        "--prod",
        "--dev",
        "--silent",
        "--force",
    ],
    lockfiles: &["pnpm-lock.yaml"],
    spec_style: SpecStyle::Npm,
};

/// yarn, covering classic and berry. `global add <pkg>` is a classic-only
/// shape handled in [`argv`].
static YARN: PmDef = PmDef {
    name: "yarn",
    eco: Ecosystem::Npm,
    install_verb: "add",
    install_verbs: &["add", "install", "global", "up", "upgrade"],
    lockfile_verbs: &[],
    value_flags: &[
        "--registry",
        "--cwd",
        "--mutex",
        "--cache-folder",
        "--modules-folder",
        "--global-folder",
        "--preferred-cache-folder",
        "--proxy",
        "--https-proxy",
        "--network-concurrency",
        "--network-timeout",
        "--otp",
        "--mode",
    ],
    known_flags: &[
        "--registry",
        "--cwd",
        "--mutex",
        "--cache-folder",
        "--modules-folder",
        "--global-folder",
        "--preferred-cache-folder",
        "--proxy",
        "--https-proxy",
        "--network-concurrency",
        "--network-timeout",
        "--otp",
        "--mode",
        "--dev",
        "-D",
        "--peer",
        "-P",
        "--optional",
        "-O",
        "--exact",
        "-E",
        "--tilde",
        "-T",
        "--frozen-lockfile",
        "--immutable",
        "--production",
        "--ignore-scripts",
        "--ignore-engines",
        "--ignore-optional",
        "--non-interactive",
        "--silent",
        "--offline",
        "--prefer-offline",
        "--check-files",
        "--flat",
        "--force",
    ],
    lockfiles: &["yarn.lock"],
    spec_style: SpecStyle::Npm,
};

/// bun. `x` is bunx — fetch-and-execute, gated like `pnpm dlx`.
///
/// `bun.lockb` is binary and has no parser; lockfile mode skips it with a
/// warning rather than pretending to have checked it.
static BUN: PmDef = PmDef {
    name: "bun",
    eco: Ecosystem::Npm,
    install_verb: "add",
    install_verbs: &["install", "i", "add", "a", "x", "update"],
    lockfile_verbs: &[],
    value_flags: &[
        "--cwd",
        "--config",
        "-c",
        "--registry",
        "--backend",
        "--filter",
        "--lockfile-version",
    ],
    known_flags: &[
        "--cwd",
        "--config",
        "-c",
        "--registry",
        "--backend",
        "--filter",
        "--lockfile-version",
        "--development",
        "-d",
        "--dev",
        "-D",
        "--optional",
        "--peer",
        "--exact",
        "-E",
        "--global",
        "-g",
        "--production",
        "-p",
        "--frozen-lockfile",
        "--no-save",
        "--dry-run",
        "--force",
        "-f",
        "--yarn",
        "-y",
        "--silent",
        "--no-cache",
        "--ignore-scripts",
    ],
    lockfiles: &["bun.lock", "bun.lockb"],
    spec_style: SpecStyle::Npm,
};

/// cargo. `build`/`run`/`test` are deliberately **not** install verbs: they
/// install from `Cargo.lock` on every invocation, and gating them would turn
/// every build into a network round trip.
static CARGO: PmDef = PmDef {
    name: "cargo",
    eco: Ecosystem::Crates,
    install_verb: "add",
    install_verbs: &["add", "install"],
    lockfile_verbs: &[],
    value_flags: &[
        "--features",
        "-F",
        "--rename",
        "--registry",
        "--manifest-path",
        "--package",
        "-p",
        "--path",
        "--git",
        "--branch",
        "--tag",
        "--rev",
        "--target",
        "--index",
        "--root",
        "--profile",
        "--version",
        "--vers",
        "--bin",
        "--example",
        "--jobs",
        "-j",
        "--config",
        "-Z",
    ],
    known_flags: &[
        "--features",
        "-F",
        "--rename",
        "--registry",
        "--manifest-path",
        "--package",
        "-p",
        "--path",
        "--git",
        "--branch",
        "--tag",
        "--rev",
        "--target",
        "--index",
        "--root",
        "--profile",
        "--version",
        "--vers",
        "--bin",
        "--example",
        "--jobs",
        "-j",
        "--config",
        "-Z",
        "--dev",
        "--build",
        "--optional",
        "--no-default-features",
        "--default-features",
        "--locked",
        "--offline",
        "--frozen",
        "--force",
        "-f",
        "--dry-run",
        "--quiet",
        "-q",
        "--verbose",
        "-v",
        "--all-features",
        "--no-track",
        "--debug",
    ],
    lockfiles: &["Cargo.lock"],
    spec_style: SpecStyle::Cargo,
};

/// pip. `download` stages a tarball without installing it, which is still
/// worth gating. `-r requirements.txt` is pip's lockfile shape and routes to
/// lockfile mode.
static PIP: PmDef = PmDef {
    name: "pip",
    eco: Ecosystem::PyPI,
    install_verb: "install",
    install_verbs: &["install", "download"],
    lockfile_verbs: &[],
    value_flags: &[
        "-r",
        "--requirement",
        "-c",
        "--constraint",
        "-i",
        "--index-url",
        "--extra-index-url",
        "-f",
        "--find-links",
        "-t",
        "--target",
        "--prefix",
        "--root",
        "--python",
        "--proxy",
        "--cert",
        "--client-cert",
        "--log",
        "--platform",
        "--python-version",
        "--implementation",
        "--abi",
        "--report",
        "--no-binary",
        "--only-binary",
        "--progress-bar",
        "--timeout",
        "--default-timeout",
        "--retries",
        "--exists-action",
        "--trusted-host",
        "--src",
        "-e",
        "--editable",
        "--upgrade-strategy",
        "--config-settings",
        "-C",
        "-d",
        "--dest",
    ],
    known_flags: &[
        "-r",
        "--requirement",
        "-c",
        "--constraint",
        "-i",
        "--index-url",
        "--extra-index-url",
        "-f",
        "--find-links",
        "-t",
        "--target",
        "--prefix",
        "--root",
        "--python",
        "--proxy",
        "--cert",
        "--client-cert",
        "--log",
        "--platform",
        "--python-version",
        "--implementation",
        "--abi",
        "--report",
        "--no-binary",
        "--only-binary",
        "--progress-bar",
        "--timeout",
        "--default-timeout",
        "--retries",
        "--exists-action",
        "--trusted-host",
        "--src",
        "-e",
        "--editable",
        "--upgrade-strategy",
        "--config-settings",
        "-C",
        "-d",
        "--dest",
        "-U",
        "--upgrade",
        "--user",
        "--no-deps",
        "--force-reinstall",
        "--ignore-installed",
        "--no-cache-dir",
        "--pre",
        "--quiet",
        "-q",
        "--verbose",
        "-v",
        "--no-index",
        "--require-hashes",
        "--break-system-packages",
        "--no-build-isolation",
        "--use-pep517",
        "--dry-run",
    ],
    lockfiles: &["requirements.txt"],
    spec_style: SpecStyle::Pep508,
};

/// go. Most `go` flags are single-dash-long, which the "starts with `-`" rule
/// already covers.
static GO: PmDef = PmDef {
    name: "go",
    eco: Ecosystem::Go,
    install_verb: "get",
    install_verbs: &["get", "install"],
    lockfile_verbs: &[],
    value_flags: &[
        "-C",
        "-modfile",
        "-ldflags",
        "-tags",
        "-gcflags",
        "-o",
        "-p",
        "-covermode",
        "-overlay",
        "-pkgdir",
        "-toolexec",
    ],
    known_flags: &[
        "-C",
        "-modfile",
        "-ldflags",
        "-tags",
        "-gcflags",
        "-o",
        "-p",
        "-covermode",
        "-overlay",
        "-pkgdir",
        "-toolexec",
        "-u",
        "-d",
        "-t",
        "-x",
        "-v",
        "-n",
        "-mod",
        "-race",
        "-insecure",
    ],
    lockfiles: &["go.sum"],
    spec_style: SpecStyle::GoModule,
};

/// Entry point for `aegis <pm> <args...>`.
///
/// Until the gate lands this is a transparent wrapper: classify the argv,
/// then hand off to the real manager either way. Wiring it as a no-op first
/// keeps the passthrough path — the part that can break someone's shell —
/// reviewable on its own.
pub(crate) fn run(pm: Pm, args: &[String]) -> std::process::ExitCode {
    exec::exec_real(pm.name(), args)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test over the whole table: every invariant the argv walker relies
    /// on, checked for all seven managers at once. Adding a manager with a
    /// malformed table fails here rather than silently mis-parsing an install.
    #[test]
    fn pm_table_invariants_hold_for_every_manager() {
        for pm in Pm::ALL {
            let d = pm.def();
            let who = d.name;

            assert!(!d.name.is_empty(), "{who}: empty name");
            assert!(
                Pm::parse(d.name) == Some(pm),
                "{who}: name does not round-trip through parse"
            );
            assert!(
                d.install_verbs.contains(&d.install_verb),
                "{who}: install_verb {:?} missing from install_verbs",
                d.install_verb
            );
            assert!(!d.lockfiles.is_empty(), "{who}: no lockfile names");

            for f in d.value_flags {
                assert!(f.starts_with('-'), "{who}: value flag {f:?} lacks a dash");
                assert!(
                    d.known_flags.contains(f),
                    "{who}: value flag {f:?} missing from known_flags — the \
                     unknown-flag safety valve would fire on every use of it"
                );
            }
            for f in d.known_flags {
                assert!(f.starts_with('-'), "{who}: known flag {f:?} lacks a dash");
            }
            for v in d.lockfile_verbs {
                assert!(
                    d.install_verbs.contains(v),
                    "{who}: lockfile verb {v:?} is not an install verb, so it \
                     can never be reached"
                );
            }

            let mut seen: Vec<&str> = Vec::new();
            for v in d.install_verbs {
                assert!(!seen.contains(v), "{who}: duplicate install verb {v:?}");
                seen.push(v);
            }
        }
    }

    #[test]
    fn npm_and_pnpm_disagree_about_dash_w() {
        // npm -w <name> takes a value; pnpm -w is --workspace-root, a boolean.
        // Sharing one flag table across the npm family would break one of them.
        assert!(NPM.value_flags.contains(&"-w"));
        assert!(!PNPM.value_flags.contains(&"-w"));
        assert!(PNPM.known_flags.contains(&"-w"));
    }

    #[test]
    fn npm_workspaces_is_not_a_value_flag() {
        // Regression guard: the Go table lists `--workspaces` as taking a
        // value, which swallows the package name after it.
        assert!(!NPM.value_flags.contains(&"--workspaces"));
        assert!(NPM.known_flags.contains(&"--workspaces"));
    }

    #[test]
    fn npm_ci_is_gated_as_a_lockfile_install() {
        assert!(NPM.install_verbs.contains(&"ci"));
        assert!(NPM.lockfile_verbs.contains(&"ci"));
    }

    #[test]
    fn cargo_build_is_not_an_install_verb() {
        // Gating `cargo build` would put a network round trip in front of
        // every compile.
        for v in ["build", "run", "test", "check"] {
            assert!(!CARGO.install_verbs.contains(&v), "cargo {v} must not gate");
        }
    }

    #[test]
    fn pip_aliases_resolve() {
        assert_eq!(Pm::parse("pip3"), Some(Pm::Pip));
        assert_eq!(Pm::parse("python"), None);
        assert_eq!(Pm::parse("nope"), None);
    }
}
