//! Package-registry adapters. Ports of `internal/infra/{npm,pypi,crates,
//! rubygems,nuget}registry`, `licensefetch`, `depsdotdev`, and
//! `npmattestations`.
//!
//! Capabilities the enrich/CI layers consume:
//!  - **license** lookup per ecosystem (`LicenseFetcher`), for the SPDX
//!    license-policy gate;
//!  - **package health** (deprecation) via deps.dev, for `--fail-on-deprecated`;
//!  - **npm provenance** attestation lookup (`fetch_provenance`), the SLSA
//!    build-provenance signal.
//!
//! Transport goes through the [`aegis_net::HttpClient`] seam, so every
//! adapter is unit-tested offline against the mock.

#[cfg(feature = "attestations")]
pub mod attestations;
#[cfg(feature = "depsdev")]
pub mod depsdotdev;
#[cfg(feature = "github")]
pub mod github;
pub mod license;
#[cfg(feature = "npm")]
pub mod npm;
#[cfg(feature = "npm")]
pub mod pkgsource;

#[cfg(feature = "attestations")]
pub use attestations::{fetch_provenance, ProvenanceStatus};
#[cfg(feature = "depsdev")]
pub use depsdotdev::{DepsDevClient, PackageHealth};
pub use license::LicenseFetcher;
#[cfg(feature = "npm")]
pub use npm::{fetch_maintainer_signal, MaintainerSignal};
#[cfg(feature = "npm")]
pub use pkgsource::{
    fetch_crates_source, fetch_go_source, fetch_npm_source, fetch_pypi_source,
    fetch_rubygems_source,
};
