//! Small shared helpers: severity/ecosystem parsing and ordering.

use aegis_domain::{Ecosystem, Severity};

/// Severity ordering for the fail-on threshold (higher = more severe).
pub(crate) fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

pub(crate) fn parse_severity(s: &str) -> Option<Severity> {
    Some(match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" | "moderate" => Severity::Medium,
        "low" => Severity::Low,
        _ => return None,
    })
}

pub(crate) fn parse_ecosystem(s: &str) -> Option<Ecosystem> {
    Some(match s.to_lowercase().as_str() {
        "npm" => Ecosystem::Npm,
        "pypi" => Ecosystem::PyPI,
        "crates" | "cargo" => Ecosystem::Crates,
        "go" => Ecosystem::Go,
        "rubygems" | "ruby" => Ecosystem::RubyGems,
        "maven" => Ecosystem::Maven,
        "packagist" | "composer" => Ecosystem::Packagist,
        "nuget" => Ecosystem::NuGet,
        "hex" | "gleam" | "mix" => Ecosystem::Hex,
        "pub" | "dart" | "pubspec" => Ecosystem::Pub,
        "swift" | "swiftpm" => Ecosystem::SwiftPM,
        "cran" => Ecosystem::Cran,
        "hackage" | "haskell" => Ecosystem::Hackage,
        "cpan" | "perl" => Ecosystem::Cpan,
        "cocoapods" | "pods" => Ecosystem::CocoaPods,
        "neovim" => Ecosystem::Neovim,
        "aur" => Ecosystem::Aur,
        _ => return None,
    })
}

pub(crate) fn default_ecosystem() -> String {
    "npm".to_string()
}
