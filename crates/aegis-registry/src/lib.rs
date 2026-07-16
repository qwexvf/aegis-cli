//! Package-registry adapters. Ports of `internal/infra/{npm,pypi,crates,
//! rubygems,nuget}registry`, `licensefetch`, and `depsdotdev`.
//!
//! Two capabilities the enrich/CI layers consume:
//!  - **license** lookup per ecosystem (`LicenseFetcher`), for the SPDX
//!    license-policy gate;
//!  - **package health** (deprecation) via deps.dev, for `--fail-on-deprecated`.
//!
//! Transport goes through the [`aegis_net::HttpClient`] seam, so every
//! adapter is unit-tested offline against the mock.

#[cfg(feature = "depsdev")]
pub mod depsdotdev;
#[cfg(feature = "github")]
pub mod github;
pub mod license;
#[cfg(feature = "npm")]
pub mod npm;

#[cfg(feature = "depsdev")]
pub use depsdotdev::{DepsDevClient, PackageHealth};
pub use license::LicenseFetcher;
#[cfg(feature = "npm")]
pub use npm::{fetch_maintainer_signal, MaintainerSignal};
