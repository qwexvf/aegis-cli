//! GitHub git-tree adapter — the upstream file list for tarball-drift. Port of
//! `internal/infra/scan/drift/{client.go,tags.go}`.
//!
//! Given a package's `repository` field + version, resolves the matching tag
//! to a commit SHA and fetches the recursive git tree, returning the repo's
//! blob paths. Everything is best-effort: an unresolvable repo, a 404 tag, a
//! rate-limit, or a transport error yields `None` — "skip the drift check",
//! never "the package is bad".

use aegis_net::HttpClient;
use serde_json::Value;

/// Public GitHub REST endpoint.
pub const DEFAULT_GITHUB_API: &str = "https://api.github.com";

/// Parse a package.json `repository` field into `(owner, repo)` if it points
/// at GitHub. Accepts `github:owner/repo`, bare `owner/repo`, `git+https://`,
/// `git+ssh://`, and `git@github.com:owner/repo.git`. `None` for non-GitHub
/// hosts or unusable input — the detector skips those the same as "no repo".
pub fn parse_repository(raw: &str) -> Option<(String, String)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    // Shorthand: "github:owner/repo".
    if let Some(rest) = raw.strip_prefix("github:") {
        return split_owner_repo(rest);
    }
    // Bare "owner/repo" (npm shortcut) — exactly one slash, no scheme.
    if raw.matches('/').count() == 1 && !raw.contains(':') {
        return split_owner_repo(raw);
    }

    // Strip npm's "git+" prefix; normalize scp-style git@host:path.
    let mut s = raw.strip_prefix("git+").unwrap_or(raw).to_string();
    if s.starts_with("git@") {
        s = format!("ssh://{}", s.replacen(':', "/", 1));
    }
    // Minimal URL parse: scheme://[user@]host/path...
    let after_scheme = s.split_once("://").map(|(_, r)| r).unwrap_or(&s);
    let (authority, path) = after_scheme.split_once('/')?;
    // Strip user-info from the authority.
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.to_ascii_lowercase();
    if host != "github.com" && host != "www.github.com" {
        return None;
    }
    split_owner_repo(path)
}

fn split_owner_repo(path: &str) -> Option<(String, String)> {
    let path = path.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let (owner, rest) = path.split_once('/')?;
    // repo is the segment up to any further slash.
    let repo = rest.split('/').next().unwrap_or(rest);
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner.to_string(), repo.to_string()))
}

/// Enumerate candidate tag refs for `(pkg, version)`, priority order, deduped:
/// `v{ver}`, `{ver}`, then monorepo/changesets shapes (`{pkg}@{ver}`, etc.),
/// including the scope-stripped short name for scoped packages.
pub fn tag_candidates(pkg_name: &str, version: &str) -> Vec<String> {
    let pkg_name = pkg_name.trim();
    let version = version.trim();
    if version.is_empty() {
        return Vec::new();
    }
    // Scope-stripped short name: "@scope/name" → "name".
    let short = pkg_name
        .strip_prefix('@')
        .and_then(|s| s.split_once('/').map(|(_, n)| n))
        .unwrap_or(pkg_name);

    let mut candidates = vec![format!("v{version}"), version.to_string()];
    if !pkg_name.is_empty() {
        candidates.push(format!("{pkg_name}@{version}"));
        candidates.push(format!("{pkg_name}-v{version}"));
        candidates.push(format!("{pkg_name}-{version}"));
        if short != pkg_name {
            candidates.push(format!("{short}@{version}"));
            candidates.push(format!("{short}-v{version}"));
            candidates.push(format!("{short}-{version}"));
        }
    }

    let mut seen = std::collections::HashSet::new();
    candidates.retain(|c| !c.is_empty() && seen.insert(c.clone()));
    candidates
}

/// True when `r` is plausibly a semver tag (`v?MAJOR.MINOR.PATCH[-+…]`). Cheap
/// pre-filter so callers don't fire HTTP for refs like "main"/"HEAD".
pub fn looks_like_version(r: &str) -> bool {
    let r = r.trim();
    let core = r.strip_prefix('v').unwrap_or(r);
    // Split off any prerelease/build metadata.
    let core = core.split(['-', '+']).next().unwrap_or(core);
    let mut parts = core.split('.');
    let (Some(a), Some(b), Some(c), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    [a, b, c]
        .iter()
        .all(|p| !p.is_empty() && p.bytes().all(|d| d.is_ascii_digit()))
}

fn get_json(http: &dyn HttpClient, url: &str, token: Option<&str>) -> Option<Value> {
    let mut headers = vec![
        ("Accept", "application/vnd.github+json"),
        ("X-GitHub-Api-Version", "2022-11-28"),
        ("User-Agent", "aegis-cli"),
    ];
    let bearer;
    if let Some(t) = token.filter(|t| !t.is_empty()) {
        bearer = format!("Bearer {t}");
        headers.push(("Authorization", &bearer));
    }
    let resp = http.get(url, &headers).ok()?;
    if !resp.is_ok() {
        return None; // 404 / 403 rate-limit / etc. → skip cleanly
    }
    serde_json::from_slice(&resp.body).ok()
}

/// Fetch the recursive blob-path list for `(owner, repo, ref)`. Resolves the
/// ref to a commit SHA first (the trees endpoint needs a tree/commit SHA), then
/// lists the tree. `None` on any failure. A truncated tree (>100k entries)
/// still returns its partial list — callers may downgrade confidence.
pub fn fetch_tree_files(
    http: &dyn HttpClient,
    base: &str,
    token: Option<&str>,
    owner: &str,
    repo: &str,
    git_ref: &str,
) -> Option<Vec<String>> {
    let commit_url = format!("{base}/repos/{owner}/{repo}/commits/{git_ref}");
    let commit = get_json(http, &commit_url, token)?;
    let sha = commit.get("sha").and_then(Value::as_str)?;
    if sha.is_empty() {
        return None;
    }
    let tree_url = format!("{base}/repos/{owner}/{repo}/git/trees/{sha}?recursive=1");
    let tree = get_json(http, &tree_url, token)?;
    let nodes = tree.get("tree").and_then(Value::as_array)?;
    let files = nodes
        .iter()
        .filter(|n| n.get("type").and_then(Value::as_str) == Some("blob"))
        .filter_map(|n| n.get("path").and_then(Value::as_str).map(str::to_string))
        .collect();
    Some(files)
}

/// High-level: parse the `repository` field, try each versioned tag candidate,
/// and return the first repo tree that resolves. `None` when the repo isn't
/// GitHub or no candidate tag exists.
pub fn fetch_repo_files(
    http: &dyn HttpClient,
    base: &str,
    token: Option<&str>,
    repository: &str,
    pkg_name: &str,
    version: &str,
) -> Option<Vec<String>> {
    let (owner, repo) = parse_repository(repository)?;
    for tag in tag_candidates(pkg_name, version) {
        if let Some(files) = fetch_tree_files(http, base, token, &owner, &repo, &tag) {
            return Some(files);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_net::MockHttpClient;

    #[test]
    fn parse_repository_shapes() {
        let ok = [
            ("github:lodash/lodash", ("lodash", "lodash")),
            ("lodash/lodash", ("lodash", "lodash")),
            (
                "git+https://github.com/tanstack/router.git",
                ("tanstack", "router"),
            ),
            ("git+ssh://git@github.com/org/repo.git", ("org", "repo")),
            ("git@github.com:org/repo.git", ("org", "repo")),
            ("https://github.com/a/b", ("a", "b")),
        ];
        for (raw, (o, r)) in ok {
            assert_eq!(
                parse_repository(raw),
                Some((o.to_string(), r.to_string())),
                "{raw}"
            );
        }
    }

    #[test]
    fn parse_repository_rejects_non_github() {
        assert_eq!(parse_repository("https://gitlab.com/a/b"), None);
        assert_eq!(parse_repository("git+https://bitbucket.org/a/b.git"), None);
        assert_eq!(parse_repository(""), None);
    }

    #[test]
    fn tag_candidates_priority_and_dedup() {
        let c = tag_candidates("router", "1.2.3");
        assert_eq!(c[0], "v1.2.3");
        assert_eq!(c[1], "1.2.3");
        assert!(c.contains(&"router@1.2.3".to_string()));
        // deduped
        let n = c.len();
        let uniq: std::collections::HashSet<_> = c.iter().collect();
        assert_eq!(n, uniq.len());
    }

    #[test]
    fn tag_candidates_scoped_strips_scope() {
        let c = tag_candidates("@tanstack/react-router", "1.0.0");
        assert!(c.contains(&"react-router@1.0.0".to_string()));
        assert!(c.contains(&"@tanstack/react-router@1.0.0".to_string()));
    }

    #[test]
    fn looks_like_version_filter() {
        for good in ["1.2.3", "v1.2.3", "10.0.0-beta.1", "1.2.3+build"] {
            assert!(looks_like_version(good), "{good}");
        }
        for bad in ["main", "HEAD", "v1.2", "1.2.3.4", "latest", ""] {
            assert!(!looks_like_version(bad), "{bad}");
        }
    }

    #[test]
    fn fetch_tree_files_resolves_and_lists() {
        let base = "https://gh.test";
        let http = MockHttpClient::new()
            .with(
                &format!("{base}/repos/o/r/commits/v1.0.0"),
                200,
                br#"{"sha": "abc123"}"#.to_vec(),
            )
            .with(
                &format!("{base}/repos/o/r/git/trees/abc123?recursive=1"),
                200,
                br#"{"sha":"abc123","truncated":false,"tree":[
                    {"path":"src/index.js","type":"blob"},
                    {"path":"src","type":"tree"},
                    {"path":"package.json","type":"blob"}
                ]}"#
                .to_vec(),
            );
        let files = fetch_tree_files(&http, base, None, "o", "r", "v1.0.0").unwrap();
        assert_eq!(files, vec!["src/index.js", "package.json"]); // trees excluded
    }

    #[test]
    fn fetch_repo_files_tries_candidates() {
        let base = "https://gh.test";
        // v2.0.0 tag 404s; bare 2.0.0 resolves.
        let http = MockHttpClient::new()
            .with(
                &format!("{base}/repos/o/r/commits/2.0.0"),
                200,
                br#"{"sha":"deadbeef"}"#.to_vec(),
            )
            .with(
                &format!("{base}/repos/o/r/git/trees/deadbeef?recursive=1"),
                200,
                br#"{"tree":[{"path":"a.js","type":"blob"}]}"#.to_vec(),
            );
        let files = fetch_repo_files(&http, base, None, "github:o/r", "r", "2.0.0").unwrap();
        assert_eq!(files, vec!["a.js"]);
    }

    #[test]
    fn fetch_repo_files_non_github_none() {
        let http = MockHttpClient::new();
        assert!(fetch_repo_files(
            &http,
            "https://gh.test",
            None,
            "https://gitlab.com/a/b",
            "b",
            "1.0.0"
        )
        .is_none());
    }

    #[test]
    fn missing_tree_returns_none() {
        let http = MockHttpClient::new(); // everything 404
        assert!(fetch_tree_files(&http, "https://gh.test", None, "o", "r", "v1.0.0").is_none());
    }
}
