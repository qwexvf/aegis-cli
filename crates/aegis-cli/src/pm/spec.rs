//! Package-spec parsing: a positional token → a name and a version request.
//!
//! Each ecosystem writes specs differently, and two of the differences bite:
//! npm scopes start with `@` (the same character that separates the version),
//! and PEP 508 packs extras and environment markers into the same token.
//!
//! A spec we cannot look up in a registry — a path, a URL, a git ref, a
//! workspace protocol — is marked [`SpecKind::NonRegistry`]. Those are
//! reported as skipped and allowed through: there is no registry entry to
//! check. That is a real coverage gap (a `git+https://` install is
//! unverified), and it is called out in the docs rather than hidden.

use super::SpecStyle;

/// Whether a spec can be looked up in a registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SpecKind {
    Registry,
    /// Not a registry package; the string says why, for the skip message.
    NonRegistry(&'static str),
}

/// One parsed package spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Spec {
    /// Registry name, normalized where the ecosystem requires it.
    pub name: String,
    /// What the user asked for: "", "1.2.3", "^4", "latest".
    pub requested: String,
    /// The original token, for messages.
    pub raw: String,
    pub kind: SpecKind,
}

impl Spec {
    fn non_registry(raw: &str, why: &'static str) -> Spec {
        Spec {
            name: String::new(),
            requested: String::new(),
            raw: raw.to_string(),
            kind: SpecKind::NonRegistry(why),
        }
    }
}

/// Parse one positional token in the given ecosystem's dialect.
pub(crate) fn parse(style: SpecStyle, raw: &str) -> Spec {
    if let Some(why) = non_registry_reason(style, raw) {
        return Spec::non_registry(raw, why);
    }
    match style {
        SpecStyle::Npm => parse_npm(raw),
        SpecStyle::Cargo => parse_at_separated(raw),
        SpecStyle::GoModule => parse_at_separated(raw),
        SpecStyle::Pep508 => parse_pep508(raw),
    }
}

/// `lodash`, `lodash@^4`, `@scope/pkg`, `@scope/pkg@1.2.3`.
fn parse_npm(raw: &str) -> Spec {
    // A leading `@` is a scope, not a separator, so split the remainder.
    let (name, requested) = match raw.strip_prefix('@') {
        Some(rest) => match rest.split_once('@') {
            Some((n, v)) => (format!("@{n}"), v.to_string()),
            None => (raw.to_string(), String::new()),
        },
        None => match raw.split_once('@') {
            Some((n, v)) => (n.to_string(), v.to_string()),
            None => (raw.to_string(), String::new()),
        },
    };
    Spec {
        name,
        requested,
        raw: raw.to_string(),
        kind: SpecKind::Registry,
    }
}

/// `serde@1.0`, `example.com/m@v1.2.3`. No scopes, so the last `@` wins.
fn parse_at_separated(raw: &str) -> Spec {
    let (name, requested) = match raw.rsplit_once('@') {
        Some((n, v)) => (n.to_string(), v.to_string()),
        None => (raw.to_string(), String::new()),
    };
    Spec {
        name,
        requested,
        raw: raw.to_string(),
        kind: SpecKind::Registry,
    }
}

/// `requests`, `requests==2.31.0`, `requests[security]>=2,<3; python_version<"3.9"`.
fn parse_pep508(raw: &str) -> Spec {
    // Environment markers first — everything after `;` is a condition.
    let body = raw.split(';').next().unwrap_or(raw).trim();
    // The name runs until an extras bracket or a version operator.
    let end = body
        .find(['[', '=', '<', '>', '!', '~', ' ', '('])
        .unwrap_or(body.len());
    let name = normalize_pypi(&body[..end]);
    // Skip the extras group when working out where the version starts.
    let after = match body[end..].strip_prefix('[') {
        Some(rest) => match rest.split_once(']') {
            Some((_, tail)) => tail,
            None => "",
        },
        None => &body[end..],
    };
    Spec {
        name,
        requested: after.trim().to_string(),
        raw: raw.to_string(),
        kind: SpecKind::Registry,
    }
}

/// PEP 503: lowercase, runs of `-_.` collapsed to a single `-`.
fn normalize_pypi(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for c in name.trim().chars() {
        if matches!(c, '-' | '_' | '.') {
            if !prev_sep {
                out.push('-');
            }
            prev_sep = true;
        } else {
            out.extend(c.to_lowercase());
            prev_sep = false;
        }
    }
    out
}

/// Why this token cannot be resolved against a registry, if it cannot.
pub(crate) fn non_registry_reason(style: SpecStyle, raw: &str) -> Option<&'static str> {
    const PATHS: [&str; 4] = ["./", "../", "/", "~"];
    const URLS: [&str; 6] = [
        "http://",
        "https://",
        "git://",
        "git+",
        "file:",
        "git+ssh://",
    ];

    if raw.is_empty() {
        return Some("empty");
    }
    if PATHS.iter().any(|p| raw.starts_with(p)) {
        return Some("local path");
    }
    if URLS.iter().any(|p| raw.starts_with(p)) {
        return Some("url/vcs");
    }
    let archive = [".tgz", ".tar.gz", ".whl", ".zip", ".egg"];
    if archive.iter().any(|s| raw.ends_with(s)) {
        return Some("archive");
    }

    match style {
        SpecStyle::Npm => {
            const PROTOCOLS: [&str; 7] = [
                "github:",
                "link:",
                "workspace:",
                "patch:",
                "portal:",
                "exec:",
                "npm:",
            ];
            if PROTOCOLS.iter().any(|p| raw.starts_with(p)) {
                return Some("protocol spec");
            }
            None
        }
        SpecStyle::GoModule => {
            // `./...`, `.`, `all` are build targets, not modules.
            if raw == "." || raw == "all" || raw.starts_with("./") || raw.contains("...") {
                return Some("local target");
            }
            None
        }
        SpecStyle::Pep508 => {
            // `foo @ https://…` is a PEP 508 direct reference.
            if raw.contains(" @ ") {
                return Some("direct reference");
            }
            None
        }
        SpecStyle::Cargo => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(style: SpecStyle, raw: &str) -> (String, String) {
        let s = parse(style, raw);
        assert_eq!(
            s.kind,
            SpecKind::Registry,
            "{raw} should be a registry spec"
        );
        (s.name, s.requested)
    }

    fn skipped(style: SpecStyle, raw: &str) -> bool {
        matches!(parse(style, raw).kind, SpecKind::NonRegistry(_))
    }

    #[test]
    fn npm_scopes_are_not_version_separators() {
        assert_eq!(p(SpecStyle::Npm, "lodash"), ("lodash".into(), "".into()));
        assert_eq!(
            p(SpecStyle::Npm, "lodash@4.17.21"),
            ("lodash".into(), "4.17.21".into())
        );
        assert_eq!(
            p(SpecStyle::Npm, "lodash@^4.17.0"),
            ("lodash".into(), "^4.17.0".into())
        );
        assert_eq!(
            p(SpecStyle::Npm, "@scope/pkg"),
            ("@scope/pkg".into(), "".into())
        );
        assert_eq!(
            p(SpecStyle::Npm, "@scope/pkg@1.2.3"),
            ("@scope/pkg".into(), "1.2.3".into())
        );
        assert_eq!(
            p(SpecStyle::Npm, "lodash@latest"),
            ("lodash".into(), "latest".into())
        );
    }

    #[test]
    fn npm_non_registry_forms_are_skipped() {
        for raw in [
            "./vendor/foo",
            "../sibling",
            "/abs/path",
            "https://example.com/p.tgz",
            "git+https://github.com/o/r.git",
            "github:owner/repo",
            "file:../local",
            "link:../pkg",
            "workspace:*",
            "patch:lodash@4.17.21#./fix.patch",
            "portal:../x",
            "npm:@types/lodash@^4",
            "pkg-1.0.0.tgz",
        ] {
            assert!(skipped(SpecStyle::Npm, raw), "{raw} should be skipped");
        }
    }

    #[test]
    fn cargo_and_go_split_on_the_last_at() {
        assert_eq!(p(SpecStyle::Cargo, "serde"), ("serde".into(), "".into()));
        assert_eq!(
            p(SpecStyle::Cargo, "serde@1.0"),
            ("serde".into(), "1.0".into())
        );
        assert_eq!(
            p(SpecStyle::GoModule, "example.com/m@v1.2.3"),
            ("example.com/m".into(), "v1.2.3".into())
        );
        assert_eq!(
            p(SpecStyle::GoModule, "example.com/m"),
            ("example.com/m".into(), "".into())
        );
    }

    #[test]
    fn go_build_targets_are_not_modules() {
        for raw in [".", "all", "./...", "./cmd/foo"] {
            assert!(skipped(SpecStyle::GoModule, raw), "{raw} should be skipped");
        }
    }

    #[test]
    fn pep508_strips_extras_and_markers_and_normalizes_the_name() {
        assert_eq!(
            p(SpecStyle::Pep508, "requests"),
            ("requests".into(), "".into())
        );
        assert_eq!(
            p(SpecStyle::Pep508, "requests==2.31.0"),
            ("requests".into(), "==2.31.0".into())
        );
        assert_eq!(
            p(SpecStyle::Pep508, "requests[security]>=2,<3"),
            ("requests".into(), ">=2,<3".into())
        );
        assert_eq!(
            p(SpecStyle::Pep508, "requests>=2 ; python_version<\"3.9\""),
            ("requests".into(), ">=2".into())
        );
        // PEP 503 normalization — advisory feeds key on this form.
        assert_eq!(
            p(SpecStyle::Pep508, "zope.interface==6.0"),
            ("zope-interface".into(), "==6.0".into())
        );
        assert_eq!(
            p(SpecStyle::Pep508, "Foo_Bar"),
            ("foo-bar".into(), "".into())
        );
    }

    #[test]
    fn pep508_direct_references_are_skipped() {
        assert!(skipped(
            SpecStyle::Pep508,
            "foo @ https://example.com/foo.tar.gz"
        ));
        assert!(skipped(SpecStyle::Pep508, "./local-dir"));
        assert!(skipped(SpecStyle::Pep508, "dist/pkg-1.0-py3-none-any.whl"));
    }
}
