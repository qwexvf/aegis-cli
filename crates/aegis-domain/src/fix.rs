//! Fix planning — the minimal version bumps that resolve known
//! vulnerabilities. Pure port of `domain/fix.go`. No I/O.
//!
//! Group advisories per dep; the target version is the highest `fixed_in`
//! that is a forward upgrade from the installed version (a `fixed_in` at or
//! below the install is a backport on an older range, not a valid fix — never
//! a downgrade). Advisories without `fixed_in`, or whose `fixed_in` isn't a
//! forward upgrade, stay unresolved for the user to handle manually.

use std::cmp::Ordering;

use crate::{Advisory, Dependency, Ecosystem};

/// One dep with at least one advisory and a computed upgrade target.
#[derive(Debug, Clone)]
pub struct FixItem {
    pub dep: Dependency,
    /// Highest forward `fixed_in`; empty when no advisory has usable fix data.
    pub target_version: String,
    /// Advisories the upgrade to `target_version` clears.
    pub resolved: Vec<Advisory>,
    /// Advisories with no forward fix (no `fixed_in`, or a backport/downgrade).
    pub unresolved: Vec<Advisory>,
}

/// Compute the fix plan from (dependency, its advisories) pairs. Deps with no
/// advisories are skipped.
pub fn build_fix_plan(deps: &[(Dependency, Vec<Advisory>)]) -> Vec<FixItem> {
    let mut out = Vec::new();
    for (dep, advisories) in deps {
        if advisories.is_empty() {
            continue;
        }
        let mut resolved = Vec::new();
        let mut unresolved = Vec::new();
        let mut target = String::new();
        for a in advisories {
            if a.fixed_in.is_empty() {
                unresolved.push(a.clone());
                continue;
            }
            // Only a forward upgrade clears the advisory; never a downgrade.
            if compare_fix_version(&a.fixed_in, &dep.version) != Ordering::Greater {
                unresolved.push(a.clone());
                continue;
            }
            if target.is_empty() || compare_fix_version(&a.fixed_in, &target) == Ordering::Greater {
                target = a.fixed_in.clone();
            }
            resolved.push(a.clone());
        }
        if resolved.is_empty() && unresolved.is_empty() {
            continue;
        }
        out.push(FixItem {
            dep: dep.clone(),
            target_version: target,
            resolved,
            unresolved,
        });
    }
    out
}

/// Compare two version strings. When both parse as semver, uses full semver
/// precedence — including pre-release ordering, so `1.2.3-rc.1 < 1.2.3` (the
/// naive per-segment compare got this backwards). Falls back to a
/// numerically-aware per-dotted-segment compare for non-semver shapes
/// (date tags, `latest`, calendar versions). Handles a leading `v`.
pub fn compare_fix_version(a: &str, b: &str) -> Ordering {
    // Prefer real semver precedence when both sides parse.
    if let (Some(va), Some(vb)) = (
        crate::semver::Version::parse(a),
        crate::semver::Version::parse(b),
    ) {
        return va.cmp(&vb);
    }
    let a = a.strip_prefix('v').unwrap_or(a);
    let b = b.strip_prefix('v').unwrap_or(b);
    let (as_, bs): (Vec<&str>, Vec<&str>) = (a.split('.').collect(), b.split('.').collect());
    for (x, y) in as_.iter().zip(bs.iter()) {
        match (parse_leading_int(x), parse_leading_int(y)) {
            (Some(ax), Some(by)) => {
                if ax != by {
                    return ax.cmp(&by);
                }
            }
            _ => {
                if x != y {
                    return x.cmp(y);
                }
            }
        }
    }
    as_.len().cmp(&bs.len())
}

/// Leading numeric prefix of `s`, or `None` if it doesn't start with a digit.
fn parse_leading_int(s: &str) -> Option<u64> {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// True when `name` contains only chars safe to interpolate into a shell
/// upgrade command without quoting. Mirrors `isSafePkgName`.
fn is_safe_pkg_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 256 {
        return false;
    }
    name.bytes().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, b'.' | b'_' | b'-' | b'+' | b'/' | b'@' | b':' | b'~')
    })
}

/// Stricter than [`is_safe_pkg_name`] — range operators (`^`, `~`, …) excluded
/// so a tainted `fixed_in` can't smuggle shell metacharacters. Mirrors
/// `isSafeVersion`.
fn is_safe_version(v: &str) -> bool {
    if v.is_empty() || v.len() > 128 {
        return false;
    }
    v.bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'+' | b'-' | b'_'))
}

/// The ecosystem-appropriate upgrade command for `dep`, pinned to
/// `target_version` when given. `None` when no command shape is known or the
/// name/version fails the shell-safety check. Output is safe to pipe to `sh`.
/// Mirrors `UpgradeCommand`.
pub fn upgrade_command(dep: &Dependency, target_version: &str) -> Option<String> {
    if !is_safe_pkg_name(&dep.name) {
        return None;
    }
    if !target_version.is_empty() && !is_safe_version(target_version) {
        return None;
    }
    let name = &dep.name;
    let pinned = !target_version.is_empty();
    let t = target_version;
    let cmd = match dep.ecosystem {
        Ecosystem::Npm => {
            if pinned {
                format!("npm install {name}@{t}")
            } else {
                format!("npm install {name}@latest")
            }
        }
        Ecosystem::PyPI => {
            if pinned {
                format!("pip install {name}=={t}")
            } else {
                format!("pip install --upgrade {name}")
            }
        }
        Ecosystem::RubyGems => {
            if pinned {
                format!("bundle update --conservative {name}  # target: {t}")
            } else {
                format!("bundle update {name}")
            }
        }
        Ecosystem::Crates => {
            let cn = name.replace('/', "-");
            if pinned {
                format!("cargo update -p {cn} --precise {t}")
            } else {
                format!("cargo update -p {cn}")
            }
        }
        Ecosystem::Go => {
            if pinned {
                format!("go get {name}@{t}")
            } else {
                format!("go get {name}@latest")
            }
        }
        Ecosystem::Maven => {
            let (group, artifact) = name.split_once(':')?;
            if pinned {
                format!("mvn versions:set-property -Dproperty={artifact}.version -DnewVersion={t}")
            } else {
                format!("mvn versions:use-latest-versions -Dincludes={group}:{artifact}")
            }
        }
        Ecosystem::Packagist => {
            if pinned {
                format!("composer require {name}:{t}")
            } else {
                format!("composer update {name}")
            }
        }
        Ecosystem::NuGet => {
            if pinned {
                format!("dotnet add package {name} --version {t}")
            } else {
                format!("dotnet add package {name}")
            }
        }
        Ecosystem::Pub => {
            if pinned {
                format!("dart pub upgrade {name}  # target: {t} (pin in pubspec.yaml)")
            } else {
                format!("dart pub upgrade {name}")
            }
        }
        Ecosystem::CocoaPods => {
            if pinned {
                format!("pod update {name}  # target: {t} (pin in Podfile)")
            } else {
                format!("pod update {name}")
            }
        }
        Ecosystem::Cpan => {
            if pinned {
                format!("cpanm {name}@{t}")
            } else {
                format!("cpanm {name}")
            }
        }
        Ecosystem::Hackage => {
            if pinned {
                format!("cabal install --constraint=\"{name} =={t}\"")
            } else {
                format!("cabal install {name}")
            }
        }
        Ecosystem::Cran => {
            if pinned {
                format!("R -e 'remotes::install_version(\"{name}\", \"{t}\")'")
            } else {
                format!("R -e 'install.packages(\"{name}\")'")
            }
        }
        Ecosystem::Hex => {
            // hex.pm serves Gleam + Elixir; the dep doesn't record which, so
            // emit a manual hint naming both toolchains rather than guessing.
            if pinned {
                format!("# upgrade {name} to {t}: `mix deps.update {name}` (Elixir) or `gleam update {name}` (Gleam)")
            } else {
                format!("# upgrade {name}: `mix deps.update {name}` (Elixir) or `gleam update {name}` (Gleam)")
            }
        }
        // No known upgrade shape.
        Ecosystem::SwiftPM
        | Ecosystem::Neovim
        | Ecosystem::Aur
        | Ecosystem::Conan
        | Ecosystem::Nix
        | Ecosystem::Julia
        | Ecosystem::Conda
        | Ecosystem::Nimble => return None,
    };
    Some(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;

    fn adv(id: &str, fixed_in: &str) -> Advisory {
        Advisory {
            id: id.into(),
            severity: Severity::High,
            fixed_in: fixed_in.into(),
            ..Default::default()
        }
    }
    fn dep(eco: Ecosystem, name: &str, version: &str) -> Dependency {
        Dependency {
            ecosystem: eco,
            name: name.into(),
            version: version.into(),
            ..Default::default()
        }
    }

    #[test]
    fn compare_numeric_aware() {
        assert_eq!(compare_fix_version("1.2.10", "1.2.9"), Ordering::Greater);
        assert_eq!(compare_fix_version("v1.0.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare_fix_version("1.0", "1.0.1"), Ordering::Less);
        assert_eq!(compare_fix_version("2.0.0", "1.9.9"), Ordering::Greater);
    }

    #[test]
    fn compare_orders_prerelease_below_release() {
        // The naive per-segment compare got this backwards (treated the extra
        // `-rc.1` segment as "greater"); semver precedence puts it lower.
        assert_eq!(compare_fix_version("1.2.3-rc.1", "1.2.3"), Ordering::Less);
        assert_eq!(
            compare_fix_version("1.2.3", "1.2.3-rc.1"),
            Ordering::Greater
        );
        assert_eq!(
            compare_fix_version("1.0.0-alpha", "1.0.0-beta"),
            Ordering::Less
        );
        // Non-semver shapes still fall back to the byte/segment compare.
        assert_eq!(compare_fix_version("latest", "latest"), Ordering::Equal);
    }

    #[test]
    fn plan_does_not_treat_prerelease_as_forward_fix() {
        // Installed 1.2.3; a `fixed_in` of a *prerelease* of the same release
        // is not a forward upgrade → stays unresolved (was wrongly "resolved"
        // before the semver fix).
        let d = dep(Ecosystem::Npm, "pkg", "1.2.3");
        let plan = build_fix_plan(&[(d, vec![adv("GHSA-x", "1.2.3-rc.1")])]);
        assert_eq!(plan.len(), 1);
        assert!(plan[0].target_version.is_empty());
        assert_eq!(plan[0].unresolved.len(), 1);
        assert!(plan[0].resolved.is_empty());
    }

    #[test]
    fn plan_picks_highest_forward_fix() {
        let d = dep(Ecosystem::Npm, "lodash", "4.17.4");
        let advs = vec![adv("GHSA-a", "4.17.11"), adv("GHSA-b", "4.17.21")];
        let plan = build_fix_plan(&[(d, advs)]);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].target_version, "4.17.21");
        assert_eq!(plan[0].resolved.len(), 2);
        assert!(plan[0].unresolved.is_empty());
    }

    #[test]
    fn plan_never_downgrades() {
        // fixed_in <= installed → unresolved, no target.
        let d = dep(Ecosystem::Npm, "x", "5.0.0");
        let advs = vec![adv("GHSA-old", "4.9.0")];
        let plan = build_fix_plan(&[(d, advs)]);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].target_version, "");
        assert_eq!(plan[0].unresolved.len(), 1);
    }

    #[test]
    fn plan_advisory_without_fixed_in_unresolved() {
        let d = dep(Ecosystem::Npm, "x", "1.0.0");
        let plan = build_fix_plan(&[(d, vec![adv("GHSA-c", "")])]);
        assert_eq!(plan[0].unresolved.len(), 1);
        assert_eq!(plan[0].target_version, "");
    }

    #[test]
    fn upgrade_commands_per_ecosystem() {
        assert_eq!(
            upgrade_command(&dep(Ecosystem::Npm, "lodash", "0"), "4.17.21").as_deref(),
            Some("npm install lodash@4.17.21")
        );
        assert_eq!(
            upgrade_command(&dep(Ecosystem::PyPI, "requests", "0"), "2.31.0").as_deref(),
            Some("pip install requests==2.31.0")
        );
        assert_eq!(
            upgrade_command(&dep(Ecosystem::Crates, "serde", "0"), "1.0.0").as_deref(),
            Some("cargo update -p serde --precise 1.0.0")
        );
        assert_eq!(
            upgrade_command(&dep(Ecosystem::Go, "github.com/x/y", "0"), "v1.2.0").as_deref(),
            Some("go get github.com/x/y@v1.2.0")
        );
        // unpinned falls back to latest verbs
        assert_eq!(
            upgrade_command(&dep(Ecosystem::Npm, "x", "0"), "").as_deref(),
            Some("npm install x@latest")
        );
    }

    #[test]
    fn maven_coord_split() {
        assert_eq!(
            upgrade_command(
                &dep(Ecosystem::Maven, "com.google.guava:guava", "0"),
                "33.0"
            )
            .as_deref(),
            Some("mvn versions:set-property -Dproperty=guava.version -DnewVersion=33.0")
        );
    }

    #[test]
    fn refuses_shell_unsafe_name_or_version() {
        assert!(upgrade_command(&dep(Ecosystem::Npm, "x; rm -rf /", "0"), "1.0.0").is_none());
        assert!(upgrade_command(&dep(Ecosystem::Npm, "x", "0"), "1.0.0; evil").is_none());
    }

    #[test]
    fn no_command_shape_returns_none() {
        assert!(upgrade_command(&dep(Ecosystem::SwiftPM, "x", "0"), "1.0.0").is_none());
    }
}
