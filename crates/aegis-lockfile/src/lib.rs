//! Lockfile parsers. Port of `internal/infra/locksnap`.
//!
//! One parser per lockfile format; each turns raw bytes into canonical
//! [`Dependency`] values (a pure function — no I/O, no env, no time).
//! Parsers are feature-gated per ecosystem so a downstream build can
//! ship only the languages it needs:
//!
//! ```text
//! cargo build --no-default-features --features npm,pypi,cargo
//! ```

use std::collections::HashMap;

use aegis_domain::{Dependency, Ecosystem};

mod common;

#[cfg(feature = "npm")]
pub mod bun;
#[cfg(feature = "cargo")]
pub mod cargo;
#[cfg(feature = "cocoapods")]
pub mod cocoapods;
#[cfg(feature = "packagist")]
pub mod composer;
#[cfg(feature = "conan")]
pub mod conan;
#[cfg(feature = "conda")]
pub mod conda;
#[cfg(feature = "cpan")]
pub mod cpan;
#[cfg(feature = "cran")]
pub mod cran;
#[cfg(feature = "elm")]
pub mod elm;
#[cfg(feature = "rubygems")]
pub mod gemfile;
#[cfg(feature = "go")]
pub mod go;
#[cfg(feature = "hackage")]
pub mod hackage;
#[cfg(feature = "hex")]
pub mod hex;
#[cfg(feature = "julia")]
pub mod julia;
#[cfg(feature = "maven")]
pub mod maven;
#[cfg(feature = "nimble")]
pub mod nimble;
#[cfg(feature = "nix")]
pub mod nix;
#[cfg(feature = "npm")]
pub mod npm;
#[cfg(feature = "nuget")]
pub mod nuget;
#[cfg(feature = "opam")]
pub mod opam;
#[cfg(feature = "npm")]
pub mod pnpm;
#[cfg(feature = "pub")]
pub mod pubspec;
#[cfg(feature = "pypi")]
pub mod python;
#[cfg(feature = "swift")]
pub mod swift;
#[cfg(feature = "npm")]
pub mod yarn;

/// A lockfile parse failure. Corrupt/unsupported input errors; an empty
/// lockfile (zero deps) is a successful parse with an empty vec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ParseError {}

/// Map of dependency-name → is-direct, read from the project manifest.
/// Non-nil (non-empty) only for npm; other ecosystems get an empty map
/// and flag direct/transitive from their own lockfile.
pub type DirectMap = HashMap<String, bool>;

/// Turns the raw bytes of one lockfile into canonical dependencies.
/// Mirrors the Go `LockfileParser` interface.
pub trait LockfileParser {
    /// Exact file name this parser handles (case-sensitive), e.g.
    /// "package-lock.json", "Cargo.lock", "go.sum".
    fn filename(&self) -> &'static str;

    /// Whether this parser handles a given basename. Defaults to an exact
    /// match on [`filename`](Self::filename); parsers whose lockfile name is
    /// variable (e.g. opam's project-prefixed `<name>.opam.locked`) override
    /// this with a suffix match.
    fn matches(&self, filename: &str) -> bool {
        self.filename() == filename
    }

    /// Which ecosystem the produced dependencies belong to. Drives the
    /// scanner's first-match-per-ecosystem rule.
    fn ecosystem(&self) -> Ecosystem;

    /// Decode the lockfile bytes. `direct` is populated only for npm.
    fn parse(&self, raw: &[u8], direct: &DirectMap) -> Result<Vec<Dependency>, ParseError>;
}

/// Every built-in parser compiled into this build. The set shrinks with
/// disabled features — a `--no-default-features --features npm` build
/// returns only the npm parser. Mirrors the Go package-level registry,
/// but assembled from enabled features instead of `init()` side effects.
pub fn builtin_parsers() -> Vec<Box<dyn LockfileParser>> {
    // cfg-gated pushes can't be a `vec![]` literal — the element set depends on
    // enabled features. Lean builds (few features) otherwise trip
    // vec_init_then_push.
    #[allow(unused_mut, clippy::vec_init_then_push)]
    let mut v: Vec<Box<dyn LockfileParser>> = Vec::new();
    #[cfg(feature = "npm")]
    {
        v.push(Box::new(npm::PackageLockJson));
        v.push(Box::new(yarn::YarnLock));
        v.push(Box::new(pnpm::PnpmLock));
        v.push(Box::new(bun::BunLock));
    }
    #[cfg(feature = "pypi")]
    {
        v.push(Box::new(python::PoetryLock));
        v.push(Box::new(python::UvLock));
        v.push(Box::new(python::PipfileLock));
        v.push(Box::new(python::RequirementsTxt));
    }
    #[cfg(feature = "cargo")]
    v.push(Box::new(cargo::CargoLock));
    #[cfg(feature = "go")]
    v.push(Box::new(go::GoSum));
    #[cfg(feature = "packagist")]
    v.push(Box::new(composer::ComposerLock));
    #[cfg(feature = "nuget")]
    v.push(Box::new(nuget::PackagesLockJson));
    #[cfg(feature = "cran")]
    v.push(Box::new(cran::RenvLock));
    #[cfg(feature = "swift")]
    v.push(Box::new(swift::PackageResolved));
    #[cfg(feature = "rubygems")]
    v.push(Box::new(gemfile::GemfileLock));
    #[cfg(feature = "maven")]
    {
        v.push(Box::new(maven::PomXml));
        v.push(Box::new(maven::GradleLockfile));
    }
    #[cfg(feature = "hex")]
    {
        v.push(Box::new(hex::GleamManifest));
        v.push(Box::new(hex::MixLock));
    }
    #[cfg(feature = "pub")]
    v.push(Box::new(pubspec::PubspecLock));
    #[cfg(feature = "cocoapods")]
    v.push(Box::new(cocoapods::PodfileLock));
    #[cfg(feature = "cpan")]
    v.push(Box::new(cpan::CpanfileSnapshot));
    #[cfg(feature = "hackage")]
    {
        v.push(Box::new(hackage::CabalFreeze));
        v.push(Box::new(hackage::StackYamlLock));
    }
    #[cfg(feature = "conan")]
    v.push(Box::new(conan::ConanLock));
    #[cfg(feature = "nix")]
    v.push(Box::new(nix::FlakeLock));
    #[cfg(feature = "julia")]
    v.push(Box::new(julia::JuliaManifest));
    #[cfg(feature = "conda")]
    v.push(Box::new(conda::CondaLock));
    #[cfg(feature = "nimble")]
    v.push(Box::new(nimble::NimbleLock));
    #[cfg(feature = "elm")]
    v.push(Box::new(elm::ElmJson));
    #[cfg(feature = "opam")]
    v.push(Box::new(opam::OpamLocked));
    v
}

/// Find the built-in parser for `filename` (exact match) and run it.
/// Returns `Ok(None)` when no compiled-in parser handles that filename.
pub fn parse_file(
    filename: &str,
    raw: &[u8],
    direct: &DirectMap,
) -> Result<Option<Vec<Dependency>>, ParseError> {
    for p in builtin_parsers() {
        if p.matches(filename) {
            let mut deps = p.parse(raw, direct)?;
            // Deterministic order: several parsers build from a HashMap, so their
            // natural order is nondeterministic across runs — which made `parse`
            // and `sbom` output (both routinely committed/diffed) unstable. Sort
            // by (ecosystem, name, version) so output is reproducible.
            deps.sort_by(|a, b| {
                a.ecosystem
                    .as_str()
                    .cmp(b.ecosystem.as_str())
                    .then_with(|| a.name.cmp(&b.name))
                    .then_with(|| a.version.cmp(&b.version))
            });
            return Ok(Some(deps));
        }
    }
    Ok(None)
}
