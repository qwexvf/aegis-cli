//! VCS-dependency detectors. Port of `check_vcs_dep.go` +
//! `check_optional_git_dep.go`.
//!
//! Both read the parsed [`NormalizedPackage::deps`] populated by the
//! manifest parser (see [`crate::manifest`]).

use aegis_domain::Capability;

use crate::{DepSource, NormalizedPackage};

/// Fires when any dependency (in any group) is pinned to a VCS URL instead
/// of a registry version. Lower-weight than [`check_optional_git_dep`]:
/// pushes to Prompt alone, Block when combined with other signals.
pub fn check_vcs_deps(pkg: &NormalizedPackage) -> Vec<Capability> {
    if pkg.deps.iter().any(|d| d.source == DepSource::Vcs) {
        return vec![Capability::VcsDependency];
    }
    Vec::new()
}

/// Fires when any *optional* dependency resolves to a VCS URL — the
/// canonical Mini Shai-Hulud worm-propagation injection vector.
pub fn check_optional_git_dep(pkg: &NormalizedPackage) -> Vec<Capability> {
    let hit = pkg
        .deps
        .iter()
        .any(|d| d.source == DepSource::Vcs && d.groups.iter().any(|g| g == "optional"));
    if hit {
        return vec![Capability::GitDepInOptionalDep];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Dep;
    use aegis_domain::Ecosystem;

    fn pkg_with(deps: Vec<Dep>) -> NormalizedPackage {
        let mut p = NormalizedPackage::new("t", Ecosystem::Npm);
        p.deps = deps;
        p
    }

    fn dep(source: DepSource, groups: &[&str]) -> Dep {
        Dep {
            name: "x".into(),
            spec: "".into(),
            source,
            groups: groups.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn vcs_dep_in_any_group_flags() {
        let p = pkg_with(vec![dep(DepSource::Vcs, &["dev"])]);
        assert_eq!(check_vcs_deps(&p), vec![Capability::VcsDependency]);
    }

    #[test]
    fn registry_only_no_vcs_signal() {
        let p = pkg_with(vec![dep(DepSource::Registry, &["direct"])]);
        assert!(check_vcs_deps(&p).is_empty());
    }

    #[test]
    fn optional_vcs_flags_git_dep() {
        let p = pkg_with(vec![dep(DepSource::Vcs, &["optional"])]);
        assert_eq!(
            check_optional_git_dep(&p),
            vec![Capability::GitDepInOptionalDep]
        );
    }

    #[test]
    fn vcs_in_non_optional_group_no_optional_signal() {
        let p = pkg_with(vec![dep(DepSource::Vcs, &["direct"])]);
        assert!(check_optional_git_dep(&p).is_empty());
        // but the broader vcs check still fires
        assert_eq!(check_vcs_deps(&p), vec![Capability::VcsDependency]);
    }

    #[test]
    fn optional_registry_dep_no_signal() {
        let p = pkg_with(vec![dep(DepSource::Registry, &["optional"])]);
        assert!(check_optional_git_dep(&p).is_empty());
    }

    #[test]
    fn empty_deps_no_signal() {
        let p = pkg_with(vec![]);
        assert!(check_vcs_deps(&p).is_empty());
        assert!(check_optional_git_dep(&p).is_empty());
    }
}
