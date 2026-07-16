//! SBOM generation for the aegis scanner. Ports of `internal/infra/sbomcdx`.
//!
//! Pure, deterministic transforms from a dependency list to standard SBOM
//! documents. The [`purl`] builder is always available; format emitters are
//! feature-gated (CycloneDX today; SPDX / SARIF to follow).

pub mod purl;

#[cfg(feature = "cyclonedx")]
pub mod cyclonedx;

pub use purl::purl as package_url;
