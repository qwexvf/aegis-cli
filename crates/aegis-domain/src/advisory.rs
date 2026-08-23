//! Advisory + severity types. Port of `internal/domain/advisory.go` and
//! the `Severity` enum from `decision.go`.

use crate::types::Ecosystem;

/// Upstream-reported severity bucketed onto our own enum. Mirrors the
/// Go `Severity` string constants. Defaults to `Info` (the OSV
/// advisory-without-CVSS fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    #[default]
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    /// Ordering rank for `max_severity`. Higher = more severe.
    fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

/// One known vulnerability against a specific package version. Mirrors
/// `domain.Advisory` (the fields the vuln layer populates; enrichment
/// fields like EPSS/KEV arrive with that layer).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Advisory {
    /// canonical id, e.g. "GHSA-jvqj-7wpc-9bqp" / "CVE-2018-16487".
    pub id: String,
    /// ids pointing at the same vuln via a different scheme.
    pub aliases: Vec<String>,
    pub severity: Severity,
    pub summary: String,
    /// canonical advisory page URL.
    pub url: String,
    /// which feed produced this ("osv", …).
    pub source: String,
    /// earliest version resolving this advisory; empty when unknown.
    pub fixed_in: String,
    /// specific vulnerable function names, when the feed reports them.
    pub affected_functions: Vec<String>,
    /// EPSS exploit-probability (0–1); 0 = not scored. From FIRST.org.
    pub epss: f64,
    /// EPSS percentile rank among all CVEs (0–1); 0 when unscored.
    pub epss_percentile: f64,
    /// true when the CVE is in CISA's Known Exploited Vulnerabilities catalog.
    pub in_kev: bool,
}

/// Typed (ecosystem, name, version) for batch vuln lookups. Mirrors
/// `AdvisoryQuery`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryQuery {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

impl AdvisoryQuery {
    /// Canonical `<ecosystem>/<name>@<version>` key for matching results
    /// back to inputs. Mirrors `AdvisoryQuery.Key()`.
    pub fn key(&self) -> String {
        format!("{}/{}@{}", self.ecosystem.as_str(), self.name, self.version)
    }
}

/// Highest severity in the slice, or Info when empty. Mirrors `MaxSeverity`.
pub fn max_severity(advs: &[Advisory]) -> Severity {
    advs.iter()
        .map(|a| a.severity)
        .max_by_key(|s| s.rank())
        .unwrap_or(Severity::Info)
}
