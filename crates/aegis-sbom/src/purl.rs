//! Package-URL (PURL) builder. Port of `sbomcdx/purl.go`.
//!
//! Produces a canonical `pkg:type/namespace/name@version` string for a
//! dependency. Percent-encodes each component per the PURL spec (unreserved
//! chars `A-Za-z0-9-._~` pass through; everything else is `%XX`). Namespace
//! keeps its `/` separators (golang paths, scoped npm) — each segment is
//! encoded independently. Empty string for an ecosystem with no PURL type.

use aegis_domain::{Dependency, Ecosystem};

/// Build the canonical PURL for a dependency, or "" if the ecosystem has no
/// PURL type mapping.
pub fn purl(dep: &Dependency) -> String {
    let Some(ty) = purl_type(dep.ecosystem) else {
        return String::new();
    };
    let (namespace, name) = split_name(dep.ecosystem, &dep.name);
    let mut s = format!("pkg:{ty}/");
    if !namespace.is_empty() {
        s.push_str(&encode_namespace(namespace));
        s.push('/');
    }
    s.push_str(&encode(name));
    s.push('@');
    s.push_str(&encode(&dep.version));
    s
}

/// Split a raw dependency name into (namespace, name) per ecosystem convention.
fn split_name(eco: Ecosystem, raw: &str) -> (&str, &str) {
    match eco {
        Ecosystem::Npm => {
            // "@scope/name" → namespace "@scope", name "name".
            if let Some(rest) = raw.strip_prefix('@') {
                if let Some(i) = rest.find('/') {
                    return (&raw[..i + 1], &rest[i + 1..]);
                }
            }
            ("", raw)
        }
        // "groupId:artifactId" → namespace + name.
        Ecosystem::Maven => raw.split_once(':').unwrap_or(("", raw)),
        // "vendor/name" → namespace + name.
        Ecosystem::Packagist => raw.split_once('/').unwrap_or(("", raw)),
        // golang: everything before the final segment is the namespace path.
        Ecosystem::Go => match raw.rfind('/') {
            Some(i) => (&raw[..i], &raw[i + 1..]),
            None => ("", raw),
        },
        _ => ("", raw),
    }
}

/// Map an ecosystem to its PURL type. `None` = no canonical type.
fn purl_type(eco: Ecosystem) -> Option<&'static str> {
    Some(match eco {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPI => "pypi",
        Ecosystem::Crates => "cargo",
        Ecosystem::Go => "golang",
        Ecosystem::Maven => "maven",
        Ecosystem::RubyGems => "gem",
        Ecosystem::Packagist => "composer",
        Ecosystem::NuGet => "nuget",
        Ecosystem::Hex => "hex",
        Ecosystem::Pub => "pub",
        Ecosystem::SwiftPM => "swift",
        Ecosystem::Cran => "cran",
        Ecosystem::Hackage => "hackage",
        Ecosystem::Cpan => "cpan",
        Ecosystem::CocoaPods => "cocoapods",
        Ecosystem::Conan => "conan",
        Ecosystem::Conda => "conda",
        // Git-distributed / no canonical PURL type → generic per PURL spec.
        Ecosystem::Neovim
        | Ecosystem::Aur
        | Ecosystem::Nix
        | Ecosystem::Julia
        | Ecosystem::Nimble
        | Ecosystem::Elm
        | Ecosystem::Opam => "generic",
    })
}

/// Percent-encode a single PURL component. Unreserved chars pass through.
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

/// Encode a namespace, preserving `/` between independently-encoded segments.
fn encode_namespace(ns: &str) -> String {
    ns.split('/').map(encode).collect::<Vec<_>>().join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(eco: Ecosystem, name: &str, version: &str) -> Dependency {
        Dependency {
            ecosystem: eco,
            name: name.into(),
            version: version.into(),
            ..Default::default()
        }
    }

    #[test]
    fn canonical_purls_match_go() {
        let cases = [
            (
                Ecosystem::Npm,
                "lodash",
                "4.17.21",
                "pkg:npm/lodash@4.17.21",
            ),
            (
                Ecosystem::Npm,
                "@types/node",
                "20.0.0",
                "pkg:npm/%40types/node@20.0.0",
            ),
            (
                Ecosystem::PyPI,
                "requests",
                "2.31.0",
                "pkg:pypi/requests@2.31.0",
            ),
            (Ecosystem::Crates, "serde", "1.0.0", "pkg:cargo/serde@1.0.0"),
            (
                Ecosystem::Go,
                "github.com/spf13/cobra",
                "v1.8.0",
                "pkg:golang/github.com/spf13/cobra@v1.8.0",
            ),
            (
                Ecosystem::Maven,
                "com.google.guava:guava",
                "33.0.0-jre",
                "pkg:maven/com.google.guava/guava@33.0.0-jre",
            ),
            (Ecosystem::RubyGems, "rails", "7.1.0", "pkg:gem/rails@7.1.0"),
            (
                Ecosystem::Packagist,
                "symfony/console",
                "6.4.0",
                "pkg:composer/symfony/console@6.4.0",
            ),
            (
                Ecosystem::NuGet,
                "Newtonsoft.Json",
                "13.0.3",
                "pkg:nuget/Newtonsoft.Json@13.0.3",
            ),
            (
                Ecosystem::Hex,
                "gleam_stdlib",
                "0.42.0",
                "pkg:hex/gleam_stdlib@0.42.0",
            ),
            (
                Ecosystem::Neovim,
                "telescope.nvim",
                "a4ed6831b7748a2ddc4e3d6207baf3df56cba6dd",
                "pkg:generic/telescope.nvim@a4ed6831b7748a2ddc4e3d6207baf3df56cba6dd",
            ),
        ];
        for (eco, name, version, want) in cases {
            assert_eq!(purl(&dep(eco, name, version)), want, "{name}");
        }
    }

    #[test]
    fn scoped_name_split() {
        // namespace is "@types", name "node"
        assert_eq!(
            purl(&dep(Ecosystem::Npm, "@babel/core", "7.0.0")),
            "pkg:npm/%40babel/core@7.0.0"
        );
    }
}
