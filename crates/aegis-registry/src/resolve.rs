//! Version resolution: turn what a user typed into an exact published
//! version.
//!
//! The scanners need a concrete version — [`fetch_npm_source`] and friends
//! error out on a range or an empty string. But an install gate sees what was
//! typed: `npm i lodash` (nothing), `npm i lodash@^4` (a range), `npm i
//! lodash@next` (a dist-tag). This module closes that gap, and is the one
//! piece of the gate that has to talk to a registry before anything can be
//! scanned.
//!
//! Range satisfaction reuses [`aegis_domain::max_satisfying`] — the npm/node
//! dialect, which is what npm, pnpm, yarn and bun all speak. PyPI's dialect is
//! different and is translated on the way in.
//!
//! [`fetch_npm_source`]: crate::fetch_npm_source

use aegis_domain::{max_satisfying, Ecosystem};
use aegis_net::HttpClient;
use serde_json::Value;

/// Why a version could not be resolved.
///
/// The gate branches on these: a [`NotFound`](ResolveError::NotFound) or
/// [`NoMatchingVersion`](ResolveError::NoMatchingVersion) is a fact about the
/// package (the install would fail anyway, or the name is a typo worth
/// blocking on), while [`Transport`](ResolveError::Transport) means *we*
/// failed and the user may be offline. Collapsing them into one `String` — the
/// convention elsewhere in this crate — would make that distinction
/// impossible to express.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// The registry has no such package.
    NotFound,
    /// The package exists, but nothing published satisfies the request.
    NoMatchingVersion,
    /// We could not ask: network down, DNS failure, 5xx, unparseable body.
    Transport(String),
    /// No resolver for this ecosystem.
    Unsupported,
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::NotFound => write!(f, "not found in registry"),
            ResolveError::NoMatchingVersion => write!(f, "no published version matches"),
            ResolveError::Transport(e) => write!(f, "registry unreachable: {e}"),
            ResolveError::Unsupported => write!(f, "no resolver for this ecosystem"),
        }
    }
}

/// Is `s` already an exact version? Then no network call is needed.
///
/// Deliberately strict: anything carrying a range operator, a wildcard, or a
/// `||` is not exact. A leading `v` is tolerated (Go writes `v1.2.3`).
pub fn is_exact_version(s: &str) -> bool {
    let t = s.strip_prefix('v').unwrap_or(s);
    if t.is_empty() {
        return false;
    }
    if t.contains(['^', '~', '*', '<', '>', '=', '|', ' ', ',', 'x', 'X']) {
        return false;
    }
    // Must start with a digit — rules out dist-tags like `latest` / `next`.
    t.starts_with(|c: char| c.is_ascii_digit())
}

/// Resolve `range_or_tag` to an exact published version of `name`.
///
/// An empty `range_or_tag` means "latest". An already-exact version is
/// returned as-is without a network call — that keeps the common
/// `pnpm add foo@1.2.3` path free.
pub fn resolve_version(
    http: &dyn HttpClient,
    eco: Ecosystem,
    name: &str,
    range_or_tag: &str,
) -> Result<String, ResolveError> {
    if name.is_empty() {
        return Err(ResolveError::NotFound);
    }
    if is_exact_version(range_or_tag) {
        // Go module versions *are* v-prefixed — the proxy serves
        // `@v/v1.6.0.zip` and 404s on `@v/1.6.0.zip` — so stripping the `v`
        // turned every pinned `go get pkg@v1.2.3` into an unfetchable version
        // and, under a fail-closed gate, a blocked install. Everywhere else a
        // leading `v` is a user-typed nicety the registry does not use.
        let exact = match eco {
            Ecosystem::Go => range_or_tag,
            _ => range_or_tag.strip_prefix('v').unwrap_or(range_or_tag),
        };
        return Ok(exact.to_string());
    }
    match eco {
        Ecosystem::Npm => resolve_npm(http, "https://registry.npmjs.org", name, range_or_tag),
        Ecosystem::Crates => resolve_crates(http, "https://crates.io", name, range_or_tag),
        Ecosystem::PyPI => resolve_pypi(http, "https://pypi.org", name, range_or_tag),
        Ecosystem::Go => resolve_go(http, "https://proxy.golang.org", name, range_or_tag),
        _ => Err(ResolveError::Unsupported),
    }
}

/// GET a URL and parse it as JSON, mapping HTTP 404 to `NotFound`.
fn get_json(
    http: &dyn HttpClient,
    url: &str,
    accept: &[(&str, &str)],
) -> Result<Value, ResolveError> {
    let resp = http
        .get(url, accept)
        .map_err(|e| ResolveError::Transport(e.to_string()))?;
    if resp.status == 404 {
        return Err(ResolveError::NotFound);
    }
    if !resp.is_ok() {
        return Err(ResolveError::Transport(format!("HTTP {}", resp.status)));
    }
    serde_json::from_slice(&resp.body).map_err(|e| ResolveError::Transport(format!("parse: {e}")))
}

/// npm: the abbreviated packument carries both `dist-tags` and `versions`.
/// Uses the same `Accept` header as [`crate::fetch_npm_source`], so the two
/// share any HTTP-level cache.
pub fn resolve_npm(
    http: &dyn HttpClient,
    registry_base: &str,
    name: &str,
    range_or_tag: &str,
) -> Result<String, ResolveError> {
    resolve_npm_auth(http, registry_base, name, range_or_tag, None)
}

/// As [`resolve_npm`], with a bearer token for a private registry.
pub fn resolve_npm_auth(
    http: &dyn HttpClient,
    registry_base: &str,
    name: &str,
    range_or_tag: &str,
    token: Option<&str>,
) -> Result<String, ResolveError> {
    let url = format!(
        "{}/{}",
        registry_base.trim_end_matches('/'),
        encode_pkg(name)
    );
    let auth = token.map(|t| format!("Bearer {t}"));
    let mut headers: Vec<(&str, &str)> = vec![("Accept", "application/vnd.npm.install-v1+json")];
    if let Some(a) = auth.as_deref() {
        headers.push(("Authorization", a));
    }
    let doc = get_json(http, &url, &headers)?;

    // A dist-tag (`latest`, `next`, `beta`) wins outright when it matches.
    let tag = if range_or_tag.is_empty() {
        "latest"
    } else {
        range_or_tag
    };
    if let Some(v) = doc
        .get("dist-tags")
        .and_then(|t| t.get(tag))
        .and_then(Value::as_str)
    {
        return Ok(v.to_string());
    }
    // An empty request that had no `latest` tag is a broken packument, not a
    // range to match.
    if range_or_tag.is_empty() {
        return Err(ResolveError::NoMatchingVersion);
    }

    let versions = version_keys(&doc, "versions")?;
    max_satisfying(range_or_tag, &versions)
        .map(str::to_string)
        .ok_or(ResolveError::NoMatchingVersion)
}

/// crates.io: `/api/v1/crates/{name}` lists every version; yanked ones are
/// skipped the way cargo skips them.
pub fn resolve_crates(
    http: &dyn HttpClient,
    base: &str,
    name: &str,
    range: &str,
) -> Result<String, ResolveError> {
    let url = format!("{}/api/v1/crates/{name}", base.trim_end_matches('/'));
    let doc = get_json(http, &url, &[("Accept", "application/json")])?;
    let versions: Vec<String> = doc
        .get("versions")
        .and_then(Value::as_array)
        .ok_or(ResolveError::NotFound)?
        .iter()
        .filter(|v| !v.get("yanked").and_then(Value::as_bool).unwrap_or(false))
        .filter_map(|v| v.get("num").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    pick(range, &versions)
}

/// PyPI: `/pypi/{name}/json` gives `info.version` (the latest) plus every
/// release key.
pub fn resolve_pypi(
    http: &dyn HttpClient,
    base: &str,
    name: &str,
    range: &str,
) -> Result<String, ResolveError> {
    let url = format!(
        "{}/pypi/{}/json",
        base.trim_end_matches('/'),
        normalize_pypi_name(name)
    );
    let doc = get_json(http, &url, &[("Accept", "application/json")])?;
    if range.is_empty() {
        return doc
            .get("info")
            .and_then(|i| i.get("version"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or(ResolveError::NoMatchingVersion);
    }
    let versions = version_keys(&doc, "releases")?;
    pick(&pypi_range_to_npm(range), &versions)
}

/// Go module proxy: `@latest` for an unpinned request. Exact `@v1.2.3` never
/// reaches here (handled by [`is_exact_version`]).
///
/// Go ranges do not exist — `@upgrade` / `@patch` are the only non-exact
/// forms, and both resolve to latest.
pub fn resolve_go(
    http: &dyn HttpClient,
    proxy_base: &str,
    name: &str,
    _range: &str,
) -> Result<String, ResolveError> {
    let url = format!(
        "{}/{}/@latest",
        proxy_base.trim_end_matches('/'),
        escape_go_module(name)
    );
    let doc = get_json(http, &url, &[("Accept", "application/json")])?;
    doc.get("Version")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or(ResolveError::NoMatchingVersion)
}

/// Collect the keys of a JSON object field as version strings.
fn version_keys(doc: &Value, field: &str) -> Result<Vec<String>, ResolveError> {
    Ok(doc
        .get(field)
        .and_then(Value::as_object)
        .ok_or(ResolveError::NotFound)?
        .keys()
        .cloned()
        .collect())
}

fn pick(range: &str, versions: &[String]) -> Result<String, ResolveError> {
    if versions.is_empty() {
        return Err(ResolveError::NotFound);
    }
    max_satisfying(range, versions)
        .map(str::to_string)
        .ok_or(ResolveError::NoMatchingVersion)
}

/// Translate the PEP 440 operators that have an npm equivalent.
///
/// `~=X.Y` is compatible-release: `>=X.Y, <X+1`. `==` and `!=` map to `=`/`!=`,
/// and `,` already means AND in both dialects. Exotic PEP 440 (`===`, epochs,
/// local versions) has no npm equivalent and is passed through, where it will
/// simply fail to match — under a fail-closed gate that surfaces as "could not
/// verify" rather than a wrong answer.
fn pypi_range_to_npm(range: &str) -> String {
    range
        .split(',')
        .map(|part| {
            let p = part.trim();
            match p.strip_prefix("~=") {
                Some(v) => {
                    let mut it = v.split('.');
                    let major = it.next().unwrap_or("0");
                    match it.next() {
                        // ~=1.4 → >=1.4 <2
                        Some(minor) => {
                            let next: u64 = major.parse::<u64>().unwrap_or(0) + 1;
                            format!(">={major}.{minor} <{next}")
                        }
                        None => format!(">={v}"),
                    }
                }
                None => p.replace("==", "=").to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// PEP 503 name normalization: lowercase, runs of `-_.` collapsed to `-`.
/// PyPI serves either form, but advisory feeds key on the normalized one.
fn normalize_pypi_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for c in name.chars() {
        if c == '-' || c == '_' || c == '.' {
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

/// `@scope/name` → `@scope%2fname`; bare names pass through.
fn encode_pkg(name: &str) -> String {
    match name.strip_prefix('@').and_then(|rest| rest.split_once('/')) {
        Some((scope, pkg)) => format!("@{scope}%2f{pkg}"),
        None => name.to_string(),
    }
}

/// Go proxy case-escaping: an uppercase letter becomes `!` + its lowercase,
/// so case-insensitive filesystems can host the module cache.
fn escape_go_module(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_net::MockHttpClient;

    fn mock(url: &str, body: &str) -> MockHttpClient {
        MockHttpClient::new().with(url, 200, body.as_bytes().to_vec())
    }

    #[test]
    fn exact_versions_skip_the_network() {
        assert!(is_exact_version("1.2.3"));
        assert!(is_exact_version("v1.2.3"));
        assert!(is_exact_version("4.17.21"));
        assert!(!is_exact_version(""));
        assert!(!is_exact_version("latest"));
        assert!(!is_exact_version("^4"));
        assert!(!is_exact_version("4.x"));
        assert!(!is_exact_version(">=1 <2"));

        // No HTTP client is consulted at all for an exact pin.
        let m = MockHttpClient::new();
        assert_eq!(
            resolve_version(&m, Ecosystem::Npm, "lodash", "4.17.21").unwrap(),
            "4.17.21"
        );
        // Go keeps its `v`: the module proxy serves `@v/v1.2.3.zip` and 404s
        // without it, so stripping it blocks every pinned `go get`.
        assert_eq!(
            resolve_version(&m, Ecosystem::Go, "example.com/m", "v1.2.3").unwrap(),
            "v1.2.3"
        );
        // Elsewhere a user-typed `v` is dropped, since registries do not use it.
        assert_eq!(
            resolve_version(&m, Ecosystem::Npm, "lodash", "v4.17.21").unwrap(),
            "4.17.21"
        );
    }

    const PACKUMENT: &str = r#"{
        "dist-tags": {"latest": "4.17.21", "next": "5.0.0-beta.1"},
        "versions": {"4.16.0": {}, "4.17.5": {}, "4.17.21": {}, "5.0.0": {}}
    }"#;

    #[test]
    fn npm_resolves_tags_and_ranges() {
        let m = mock("https://registry.npmjs.org/lodash", PACKUMENT);
        // Empty means latest.
        assert_eq!(
            resolve_npm(&m, "https://registry.npmjs.org", "lodash", "").unwrap(),
            "4.17.21"
        );
        // A named dist-tag wins outright, pre-release or not.
        assert_eq!(
            resolve_npm(&m, "https://registry.npmjs.org", "lodash", "next").unwrap(),
            "5.0.0-beta.1"
        );
        // A range picks the highest satisfying published version.
        assert_eq!(
            resolve_npm(&m, "https://registry.npmjs.org", "lodash", "^4.16.0").unwrap(),
            "4.17.21"
        );
        assert_eq!(
            resolve_npm(&m, "https://registry.npmjs.org", "lodash", "~4.17.0").unwrap(),
            "4.17.21"
        );
        assert_eq!(
            resolve_npm(&m, "https://registry.npmjs.org", "lodash", "^9").unwrap_err(),
            ResolveError::NoMatchingVersion
        );
    }

    #[test]
    fn npm_scoped_names_are_url_escaped() {
        let m = mock(
            "https://registry.npmjs.org/@scope%2fpkg",
            r#"{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}}}"#,
        );
        assert_eq!(
            resolve_npm(&m, "https://registry.npmjs.org", "@scope/pkg", "").unwrap(),
            "1.0.0"
        );
    }

    #[test]
    fn missing_package_is_not_found_not_transport() {
        let m = MockHttpClient::new().with("https://registry.npmjs.org/nope", 404, Vec::new());
        assert_eq!(
            resolve_npm(&m, "https://registry.npmjs.org", "nope", "").unwrap_err(),
            ResolveError::NotFound
        );
    }

    #[test]
    fn server_error_is_transport_so_the_gate_can_tell_them_apart() {
        let m = MockHttpClient::new().with("https://registry.npmjs.org/lodash", 503, Vec::new());
        assert!(matches!(
            resolve_npm(&m, "https://registry.npmjs.org", "lodash", "").unwrap_err(),
            ResolveError::Transport(_)
        ));
    }

    #[test]
    fn crates_skips_yanked_versions() {
        let body = r#"{"versions":[
            {"num":"1.0.0","yanked":false},
            {"num":"1.2.0","yanked":true},
            {"num":"1.1.0","yanked":false}
        ]}"#;
        let m = mock("https://crates.io/api/v1/crates/serde", body);
        // 1.2.0 is higher but yanked, so ^1 must land on 1.1.0.
        assert_eq!(
            resolve_crates(&m, "https://crates.io", "serde", "^1").unwrap(),
            "1.1.0"
        );
    }

    #[test]
    fn pypi_resolves_latest_and_translates_its_dialect() {
        let body = r#"{
            "info": {"version": "2.31.0"},
            "releases": {"2.28.0": [], "2.31.0": [], "3.0.0": []}
        }"#;
        let m = mock("https://pypi.org/pypi/requests/json", body);
        assert_eq!(
            resolve_pypi(&m, "https://pypi.org", "requests", "").unwrap(),
            "2.31.0"
        );
        assert_eq!(
            resolve_pypi(&m, "https://pypi.org", "requests", ">=2,<3").unwrap(),
            "2.31.0"
        );
        // ~=2.28 is PEP 440 compatible-release: >=2.28, <3.
        assert_eq!(
            resolve_pypi(&m, "https://pypi.org", "requests", "~=2.28").unwrap(),
            "2.31.0"
        );
        assert_eq!(
            resolve_pypi(&m, "https://pypi.org", "requests", "==2.28.0").unwrap(),
            "2.28.0"
        );
    }

    #[test]
    fn pypi_names_are_pep503_normalized() {
        assert_eq!(normalize_pypi_name("Foo.Bar_Baz"), "foo-bar-baz");
        assert_eq!(normalize_pypi_name("requests"), "requests");
        let m = mock(
            "https://pypi.org/pypi/zope-interface/json",
            r#"{"info":{"version":"6.0"},"releases":{"6.0":[]}}"#,
        );
        assert_eq!(
            resolve_pypi(&m, "https://pypi.org", "zope.interface", "").unwrap(),
            "6.0"
        );
    }

    #[test]
    fn go_uses_at_latest_and_case_escapes() {
        assert_eq!(
            escape_go_module("github.com/BurntSushi/toml"),
            "github.com/!burnt!sushi/toml"
        );
        let m = mock(
            "https://proxy.golang.org/example.com/m/@latest",
            r#"{"Version":"v1.4.0"}"#,
        );
        assert_eq!(
            resolve_go(&m, "https://proxy.golang.org", "example.com/m", "").unwrap(),
            "v1.4.0"
        );
    }

    #[test]
    fn unknown_ecosystem_is_unsupported() {
        let m = MockHttpClient::new();
        assert_eq!(
            resolve_version(&m, Ecosystem::NuGet, "Newtonsoft.Json", "").unwrap_err(),
            ResolveError::Unsupported
        );
    }
}
