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
        // `swifturl` is what `Ecosystem::as_str` writes into aegis.lock.
        "swift" | "swiftpm" | "swifturl" => Ecosystem::SwiftPM,
        "cran" => Ecosystem::Cran,
        "hackage" | "haskell" => Ecosystem::Hackage,
        "cpan" | "perl" => Ecosystem::Cpan,
        "cocoapods" | "pods" => Ecosystem::CocoaPods,
        "neovim" => Ecosystem::Neovim,
        "aur" => Ecosystem::Aur,
        "conan" => Ecosystem::Conan,
        "nix" => Ecosystem::Nix,
        "julia" => Ecosystem::Julia,
        "conda" => Ecosystem::Conda,
        "nim" | "nimble" => Ecosystem::Nimble,
        "elm" => Ecosystem::Elm,
        "opam" => Ecosystem::Opam,
        _ => return None,
    })
}

pub(crate) fn default_ecosystem() -> String {
    "npm".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_ecosystem_round_trips_through_its_wire_name() {
        // aegis.lock stores `as_str()`, and a name that fails to parse back
        // is loaded as npm. The match has no wildcard arm, so adding a
        // variant without listing it here fails to compile.
        use Ecosystem::*;
        let all = |e: Ecosystem| match e {
            Npm | PyPI | Crates | Go | Maven | RubyGems | Packagist | NuGet | Hex | Pub
            | SwiftPM | Cran | Hackage | Cpan | CocoaPods | Neovim | Aur | Conan | Nix | Julia
            | Conda | Nimble | Elm | Opam => e,
        };
        for e in [
            Npm, PyPI, Crates, Go, Maven, RubyGems, Packagist, NuGet, Hex, Pub, SwiftPM, Cran,
            Hackage, Cpan, CocoaPods, Neovim, Aur, Conan, Nix, Julia, Conda, Nimble, Elm, Opam,
        ] {
            assert_eq!(parse_ecosystem(all(e).as_str()), Some(e), "{}", e.as_str());
        }
    }
}
