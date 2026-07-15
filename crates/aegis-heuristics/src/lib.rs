//! Behavioral supply-chain heuristics. Port of the detectors in
//! `internal/infra/scan/heuristics`.
//!
//! Each detector is a pure function over a [`NormalizedPackage`] that
//! emits domain [`Capability`] values fed into risk scoring. Detectors
//! are feature-gated so a build includes only what it needs.

use std::collections::HashMap;

use aegis_domain::{Capability, Ecosystem};

#[cfg(feature = "binary-dropper")]
pub mod binary_dropper;
#[cfg(feature = "vcs-dep")]
pub mod deps;
#[cfg(feature = "go-retract")]
pub mod go_retract;
#[cfg(feature = "install-hook")]
pub mod install_hook;
#[cfg(any(
    feature = "vcs-dep",
    feature = "install-hook",
    feature = "unlisted-payload"
))]
pub mod manifest;
#[cfg(feature = "secrets")]
pub mod secrets;
#[cfg(feature = "source-patterns")]
pub mod source_patterns;
#[cfg(feature = "typosquat")]
pub mod typosquat;
#[cfg(feature = "unlisted-payload")]
pub mod unlisted_payload;

#[cfg(any(feature = "secrets", feature = "source-patterns"))]
mod source;

/// How a dependency is resolved. Mirrors Go's `DepSource`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DepSource {
    /// Resolved from the ecosystem registry by version.
    #[default]
    Registry,
    /// Resolved from a VCS URL (git+https://, github:, git = "..."). Bypasses
    /// registry immutability; the exact code is unpredictable across installs.
    Vcs,
    /// Resolved from a local file path (file:, ./path, ../path).
    Local,
}

/// One entry from a package manifest's dependency list.
#[derive(Debug, Clone, Default)]
pub struct Dep {
    /// Package name (best-effort; may be empty for some ecosystems).
    pub name: String,
    /// Raw version spec or VCS URL.
    pub spec: String,
    pub source: DepSource,
    /// e.g. "direct", "dev", "peer", "optional".
    pub groups: Vec<String>,
}

/// An inclusive `[low, high]` version range from a go.mod `retract` directive.
#[derive(Debug, Clone, Default)]
pub struct RetractRange {
    /// inclusive lower bound, e.g. "v1.0.0"
    pub low: String,
    /// inclusive upper bound, e.g. "v1.1.0"
    pub high: String,
}

/// One install-time or build-time lifecycle script.
#[derive(Debug, Clone, Default)]
pub struct Hook {
    /// "preinstall", "install", "postinstall", "prepare", "build".
    pub phase: String,
    /// Full script or file content.
    pub body: String,
}

/// The scanner's normalized view of one package: identity plus its
/// source files. Faithful subset of `heuristics.NormalizedPackage` —
/// the fields the ported detectors read.
#[derive(Debug, Clone, Default)]
pub struct NormalizedPackage {
    pub name: String,
    /// Installed version, e.g. "v1.2.3" (go). Populated by the pipeline.
    pub version: String,
    pub ecosystem_name: Option<Ecosystem>,
    /// filename → file body. Used by content-scanning detectors.
    pub files: HashMap<String, Vec<u8>>,
    /// Full dependency list across all groups. Populated by the manifest parser.
    pub deps: Vec<Dep>,
    /// Install/build lifecycle hooks. Populated by the manifest parser.
    pub hooks: Vec<Hook>,
    /// Unparsed manifest bytes (package.json, …) for detectors that need
    /// ecosystem-specific raw parsing (e.g. the `files` allowlist field).
    pub manifest_raw: Vec<u8>,
    /// Exact versions this module retracted in its go.mod.
    pub retracted_versions: Vec<String>,
    /// Inclusive version ranges this module retracted in its go.mod.
    pub retracted_ranges: Vec<RetractRange>,
}

impl NormalizedPackage {
    pub fn new(name: impl Into<String>, ecosystem: Ecosystem) -> Self {
        NormalizedPackage {
            name: name.into(),
            ecosystem_name: Some(ecosystem),
            ..Default::default()
        }
    }

    pub fn with_file(mut self, name: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        self.files.insert(name.into(), body.into());
        self
    }
}

/// Run every compiled-in detector and return the deduped union of
/// capabilities they emit. Mirrors the heuristics pipeline's fan-out.
pub fn run_heuristics(pkg: &NormalizedPackage) -> Vec<Capability> {
    let mut caps: Vec<Capability> = Vec::new();
    #[cfg(feature = "binary-dropper")]
    caps.extend(binary_dropper::check_binary_dropper(pkg));
    #[cfg(feature = "vcs-dep")]
    {
        caps.extend(deps::check_vcs_deps(pkg));
        caps.extend(deps::check_optional_git_dep(pkg));
    }
    #[cfg(feature = "install-hook")]
    caps.extend(install_hook::check_install_hooks(pkg));
    #[cfg(feature = "unlisted-payload")]
    caps.extend(unlisted_payload::check_unlisted_payload(pkg));
    #[cfg(feature = "go-retract")]
    caps.extend(go_retract::check_go_retract(pkg));
    #[cfg(feature = "secrets")]
    caps.extend(secrets::check_secrets(pkg));
    #[cfg(feature = "source-patterns")]
    caps.extend(source_patterns::check_source_patterns(pkg));
    #[cfg(feature = "typosquat")]
    caps.extend(typosquat::check_typosquat(pkg));
    caps.sort();
    caps.dedup();
    caps
}
