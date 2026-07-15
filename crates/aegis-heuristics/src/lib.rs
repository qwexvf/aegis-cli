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
#[cfg(feature = "secrets")]
pub mod secrets;
#[cfg(feature = "source-patterns")]
pub mod source_patterns;
#[cfg(feature = "typosquat")]
pub mod typosquat;

#[cfg(any(feature = "secrets", feature = "source-patterns"))]
mod source;

/// The scanner's normalized view of one package: identity plus its
/// source files. Faithful subset of `heuristics.NormalizedPackage` —
/// the fields the ported detectors read.
#[derive(Debug, Clone, Default)]
pub struct NormalizedPackage {
    pub name: String,
    pub ecosystem_name: Option<Ecosystem>,
    /// filename → file body. Used by content-scanning detectors.
    pub files: HashMap<String, Vec<u8>>,
}

impl NormalizedPackage {
    pub fn new(name: impl Into<String>, ecosystem: Ecosystem) -> Self {
        NormalizedPackage {
            name: name.into(),
            ecosystem_name: Some(ecosystem),
            files: HashMap::new(),
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
