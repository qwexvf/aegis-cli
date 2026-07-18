//! Supporting domain types referenced by risk scoring.
//!
//! Faithful subset of `internal/domain/snapshot.go` + `install_hook.go`
//! — only the fields the risk engine reads. The rest of these structs
//! (integrity, dependency graph, advisories, …) arrive with the layers
//! that need them.

/// When an install-time script fires. Mirrors `HookPhase`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookPhase {
    /// before the package files are placed.
    PreInstall,
    /// after files are placed.
    PostInstall,
    /// during compilation/build steps.
    Build,
}

impl HookPhase {
    /// Canonical name, mirrors `HookPhase.String()`.
    pub fn name(self) -> &'static str {
        match self {
            HookPhase::PreInstall => "pre-install",
            HookPhase::PostInstall => "post-install",
            HookPhase::Build => "build",
        }
    }
}

/// A declared install-time script. Mirrors `InstallHook`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallHook {
    pub phase: HookPhase,
    /// human-readable location, e.g. "scripts.postinstall" / "setup.py".
    pub source: String,
    /// hex sha256 of the hook body; empty when the body couldn't be read.
    pub sha256: String,
}

/// Behavioral profile of one dependency version. Mirrors `Fingerprint`
/// (risk-relevant fields only).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fingerprint {
    /// true once an AST scanner has visited this dependency.
    pub analyzed: bool,
    /// behaviors the scanner detected (sorted, deduped).
    pub capabilities: crate::CapabilitySet,
    /// declared install-time scripts.
    pub hooks: Vec<InstallHook>,
    /// env-var names read at the source level (e.g. "AWS_ACCESS_KEY_ID").
    pub env_reads: Vec<String>,
    /// total size of the source the scanner walked; used by drift.
    pub source_size_bytes: i64,
}

/// Package ecosystem. Mirrors `domain.Ecosystem` (a Go string type).
/// The `as_str` value is the canonical registry/OSV identifier and is
/// load-bearing — it appears in [`Dependency::versioned_key`] and is
/// what OSV.dev matches against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    Npm,
    PyPI,
    Crates,
    Go,
    Maven,
    RubyGems,
    Packagist,
    NuGet,
    /// Gleam + Elixir both resolve through Hex.
    Hex,
    Pub,
    SwiftPM,
    Cran,
    Hackage,
    Cpan,
    CocoaPods,
    Neovim,
    Aur,
}

impl Ecosystem {
    /// Canonical identifier string, mirroring the Go `Ecosystem` const
    /// values. Used in versioned keys and OSV queries.
    pub fn as_str(self) -> &'static str {
        use Ecosystem::*;
        match self {
            Npm => "npm",
            PyPI => "pypi",
            Crates => "crates",
            Go => "go",
            Maven => "maven",
            RubyGems => "rubygems",
            Packagist => "packagist",
            NuGet => "nuget",
            Hex => "hex",
            Pub => "pub",
            SwiftPM => "swifturl",
            Cran => "cran",
            Hackage => "hackage",
            Cpan => "cpan",
            CocoaPods => "cocoapods",
            Neovim => "neovim",
            Aur => "aur",
        }
    }
}

/// A resolved dependency. Mirrors `domain.Dependency` (the fields the
/// lockfile + risk layers populate; graph/advisory fields arrive with
/// their layers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    /// sha512-… from the lockfile, when available.
    pub integrity: String,
    /// true when the dep is declared in the project manifest (not purely
    /// transitive). Best-effort per ecosystem.
    pub direct: bool,
    /// `versioned_key` values of packages this dep directly requires,
    /// when the lockfile exposes the transitive graph. Empty otherwise.
    pub depends_on: Vec<String>,
    /// "missing" when the npm provenance lookup found no attestation;
    /// empty when unqueried.
    pub provenance_status: String,
    /// SPDX license expression from the registry, when resolved (e.g.
    /// "MIT", "Apache-2.0"). Empty when unqueried or unknown — SBOM
    /// emitters render empty as the spec's `NOASSERTION`.
    pub license: String,
}

impl Dependency {
    /// Stable "ecosystem/name@version" key. Mirrors `VersionedKey()` —
    /// disambiguates multiple versions of the same package in a graph.
    pub fn versioned_key(&self) -> String {
        format!("{}/{}@{}", self.ecosystem.as_str(), self.name, self.version)
    }
}

impl Default for Dependency {
    fn default() -> Self {
        Dependency {
            ecosystem: Ecosystem::Npm,
            name: String::new(),
            version: String::new(),
            integrity: String::new(),
            direct: false,
            depends_on: Vec::new(),
            provenance_status: String::new(),
            license: String::new(),
        }
    }
}
