//! Argv classification: is this an install, and what is it installing?
//!
//! Pure functions over the raw argv that follows `aegis <pm>`. The hard part
//! is not the verbs, it is *not* mistaking a flag's value for a package name:
//! `npm i -w frontend lodash` installs one package, not two. Each manager's
//! value-flag table (see [`PmDef`](super::PmDef)) drives that.

use super::{Pm, PmDef};

/// What the argv asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstallKind {
    /// Not an install — pass straight through, no gate.
    NotInstall,
    /// Installs the packages named on the command line.
    Named,
    /// Installs whatever the lockfile pins: `npm ci`, bare `pnpm install`,
    /// `pip install -r requirements.txt`.
    Lockfile,
}

/// The result of walking an argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Walk {
    pub kind: InstallKind,
    /// Positional tokens that look like package specs, in order.
    pub specs: Vec<String>,
    /// Values of `-r`/`--requirement` flags (pip), which name further
    /// requirement files to gate.
    pub requirement_files: Vec<String>,
    /// A directory named by `--prefix`/`--dir`/`-C`/`--cwd`, if any. Lockfile
    /// mode looks there instead of the current directory.
    pub dir: Option<String>,
    /// We met a flag that is not in `known_flags`. Our value-flag table may
    /// therefore be wrong for this argv, and a positional we collected could
    /// be that flag's value rather than a package. The gate softens a block
    /// when this is set: refusing an install because *we* mis-parsed is worse
    /// than missing one.
    pub saw_unknown_flag: bool,
}

/// Is `argv[0]` a verb that installs something?
pub(crate) fn is_install_command(pm: Pm, argv: &[String]) -> bool {
    let d = pm.def();
    let Some(first) = argv.first() else {
        return false;
    };
    if pm == Pm::Yarn && first == "global" {
        // Classic yarn: only `global add` installs; `global list` does not.
        return argv.get(1).is_some_and(|s| s == "add");
    }
    d.install_verbs.contains(&first.as_str())
}

/// Classify and extract specs from a full argv (including the leading verb).
pub(crate) fn walk(pm: Pm, argv: &[String]) -> Walk {
    let d = pm.def();
    let mut w = Walk {
        kind: InstallKind::NotInstall,
        specs: Vec::new(),
        requirement_files: Vec::new(),
        dir: None,
        saw_unknown_flag: false,
    };
    if !is_install_command(pm, argv) {
        return w;
    }

    // Drop the verb, plus yarn's `global` prefix.
    let rest: &[String] = if pm == Pm::Yarn && argv.first().is_some_and(|s| s == "global") {
        &argv[2..]
    } else {
        &argv[1..]
    };

    let mut i = 0;
    while i < rest.len() {
        let a = &rest[i];
        if a.is_empty() {
            i += 1;
            continue;
        }
        // Everything after a bare `--` belongs to the underlying tool.
        if a == "--" {
            break;
        }
        if a.starts_with('-') {
            let (head, glued) = match a.split_once('=') {
                Some((h, v)) => (h, Some(v)),
                None => (a.as_str(), None),
            };
            if !d.known_flags.contains(&head) {
                w.saw_unknown_flag = true;
            }
            let value = if let Some(v) = glued {
                Some(v.to_string())
            } else if d.value_flags.contains(&head)
                && rest
                    .get(i + 1)
                    .is_some_and(|n| !n.starts_with('-') && n != "--")
            {
                i += 1;
                Some(rest[i].clone())
            } else {
                None
            };
            if let Some(v) = value {
                capture_flag_value(head, &v, &mut w);
            }
            i += 1;
            continue;
        }
        w.specs.push(a.clone());
        i += 1;
    }

    let verb = argv.first().map(String::as_str).unwrap_or("");
    w.kind = if d.lockfile_verbs.contains(&verb)
        || !w.requirement_files.is_empty()
        || w.specs.is_empty()
    {
        InstallKind::Lockfile
    } else {
        InstallKind::Named
    };
    w
}

/// Keep the few flag values the gate actually needs.
fn capture_flag_value(flag: &str, value: &str, w: &mut Walk) {
    match flag {
        "-r" | "--requirement" => w.requirement_files.push(value.to_string()),
        "--prefix" | "--dir" | "-C" | "--cwd" | "--manifest-path" if w.dir.is_none() => {
            w.dir = Some(value.to_string());
        }
        _ => {}
    }
}

/// The lockfile basenames to look for, in priority order.
pub(crate) fn lockfiles(pm: Pm) -> &'static [&'static str] {
    pm.def().lockfiles
}

/// The canonical install verb, for messages.
pub(crate) fn install_verb(def: &PmDef) -> &'static str {
    def.install_verb
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn specs(pm: Pm, args: &[&str]) -> Vec<String> {
        walk(pm, &v(args)).specs
    }

    fn kind(pm: Pm, args: &[&str]) -> InstallKind {
        walk(pm, &v(args)).kind
    }

    #[test]
    fn npm_install_aliases_and_typos_are_recognized() {
        for verb in ["install", "i", "in", "inst", "isntall", "add", "ci"] {
            assert!(
                is_install_command(Pm::Npm, &v(&[verb])),
                "npm {verb} should gate"
            );
        }
        for verb in ["run", "test", "publish", "exec"] {
            assert!(
                !is_install_command(Pm::Npm, &v(&[verb])),
                "npm {verb} should not gate"
            );
        }
        assert!(!is_install_command(Pm::Npm, &[]));
    }

    #[test]
    fn a_flag_value_is_never_mistaken_for_a_package() {
        // The whole point of the per-manager value-flag table.
        assert_eq!(
            specs(Pm::Npm, &["i", "-w", "frontend", "lodash@4.17.21"]),
            vec!["lodash@4.17.21"]
        );
        // Glued form needs no lookahead.
        assert_eq!(
            specs(Pm::Npm, &["i", "--workspace=frontend", "lodash"]),
            vec!["lodash"]
        );
        // pnpm's -w is a boolean, so the next token IS a package.
        assert_eq!(specs(Pm::Pnpm, &["add", "-w", "lodash"]), vec!["lodash"]);
    }

    #[test]
    fn boolean_flags_are_skipped_not_consumed() {
        assert_eq!(
            specs(Pm::Npm, &["i", "-D", "--no-save", "lodash"]),
            vec!["lodash"]
        );
        assert_eq!(
            specs(Pm::Npm, &["install", "--save-dev", "typescript", "vite"]),
            vec!["typescript", "vite"]
        );
    }

    #[test]
    fn bare_install_is_lockfile_mode() {
        // This is the hole the Go original leaves open: no positionals means
        // it gated nothing at all.
        assert_eq!(kind(Pm::Npm, &["install"]), InstallKind::Lockfile);
        assert_eq!(
            kind(Pm::Pnpm, &["install", "--frozen-lockfile"]),
            InstallKind::Lockfile
        );
        assert_eq!(kind(Pm::Yarn, &["install"]), InstallKind::Lockfile);
        assert_eq!(kind(Pm::Bun, &["install"]), InstallKind::Lockfile);
        // `npm ci` is lockfile mode even though it never takes positionals.
        assert_eq!(kind(Pm::Npm, &["ci"]), InstallKind::Lockfile);
        assert_eq!(kind(Pm::Npm, &["i", "lodash"]), InstallKind::Named);
    }

    #[test]
    fn nothing_after_a_bare_double_dash_is_a_package() {
        assert_eq!(
            specs(Pm::Npm, &["i", "lodash", "--", "--weird"]),
            vec!["lodash"]
        );
        assert!(specs(Pm::Cargo, &["install", "--", "x"]).is_empty());
    }

    #[test]
    fn yarn_global_add_skips_two_tokens() {
        assert!(is_install_command(Pm::Yarn, &v(&["global", "add"])));
        assert!(!is_install_command(Pm::Yarn, &v(&["global", "list"])));
        assert_eq!(
            specs(Pm::Yarn, &["global", "add", "left-pad"]),
            vec!["left-pad"]
        );
    }

    #[test]
    fn pip_requirement_files_route_to_lockfile_mode() {
        let w = walk(Pm::Pip, &v(&["install", "-r", "requirements.txt"]));
        assert_eq!(w.kind, InstallKind::Lockfile);
        assert_eq!(w.requirement_files, vec!["requirements.txt"]);
        assert!(w.specs.is_empty());

        // Both forms, and more than one file.
        let w = walk(
            Pm::Pip,
            &v(&["install", "-r", "base.txt", "--requirement=dev.txt"]),
        );
        assert_eq!(w.requirement_files, vec!["base.txt", "dev.txt"]);
    }

    #[test]
    fn pip_named_installs_still_parse() {
        assert_eq!(
            specs(Pm::Pip, &["install", "-U", "requests==2.31.0"]),
            vec!["requests==2.31.0"]
        );
        // -e takes a value, and that value is a path, never a registry package.
        assert!(specs(Pm::Pip, &["install", "-e", "."]).is_empty());
    }

    #[test]
    fn cargo_and_go_specs_survive_their_flags() {
        assert_eq!(
            specs(Pm::Cargo, &["add", "serde@1.0", "--features", "derive"]),
            vec!["serde@1.0"]
        );
        assert_eq!(
            specs(Pm::Go, &["get", "example.com/m@v1.2.3"]),
            vec!["example.com/m@v1.2.3"]
        );
        assert_eq!(
            specs(
                Pm::Go,
                &["install", "-tags", "netgo", "example.com/cmd@latest"]
            ),
            vec!["example.com/cmd@latest"]
        );
    }

    #[test]
    fn a_directory_flag_is_captured_for_lockfile_lookup() {
        let w = walk(Pm::Pnpm, &v(&["install", "-C", "packages/web"]));
        assert_eq!(w.dir.as_deref(), Some("packages/web"));
        assert_eq!(w.kind, InstallKind::Lockfile);
    }

    #[test]
    fn an_unknown_flag_raises_the_mis_parse_flag() {
        // We cannot know whether `--totally-new` takes a value, so a
        // positional after it may be that value rather than a package.
        let w = walk(Pm::Npm, &v(&["i", "--totally-new", "maybe-a-value"]));
        assert!(w.saw_unknown_flag);
        // Known flags never raise it.
        let w = walk(Pm::Npm, &v(&["i", "--save-dev", "lodash"]));
        assert!(!w.saw_unknown_flag);
    }

    #[test]
    fn non_install_verbs_produce_nothing() {
        let w = walk(Pm::Npm, &v(&["run", "build"]));
        assert_eq!(w.kind, InstallKind::NotInstall);
        assert!(w.specs.is_empty());
        assert!(!w.saw_unknown_flag);
    }
}
