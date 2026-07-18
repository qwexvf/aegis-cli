//! Package-source fetch: download a dependency's published tarball from its
//! registry and extract it to an in-memory file map for the AST + heuristics
//! scanners. Port of `jspkgsource` (npm) — the input to the enrich pipeline
//! that gives `ci` a per-dependency verdict.
//!
//! npm flow: GET the (abbreviated) packument, read
//! `versions[<v>].dist.tarball`, download that `.tgz`, then gunzip + untar.
//! npm tarballs wrap everything under a top-level `package/` directory, which
//! is stripped so paths match a normal source tree. Bounded on tarball size,
//! per-file size, and entry count so a hostile registry can't exhaust memory;
//! path-traversal (`..`) entries are dropped.

use std::io::Read;

use aegis_net::HttpClient;
use serde_json::Value;

/// Cap on the compressed tarball we'll read into memory (npm tarballs are
/// well under this; the ceiling just bounds a hostile response).
const MAX_TARBALL_BYTES: u64 = 128 * 1024 * 1024;
/// Cap on a single extracted file.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Cap on the number of entries extracted from one tarball.
const MAX_ENTRIES: usize = 20_000;

/// Fetch and extract an npm package's published tarball. `registry_base` is
/// e.g. `https://registry.npmjs.org` (injectable for tests). Returns
/// `(relative_path, bytes)` pairs with the `package/` prefix stripped, in the
/// shape the scanners consume. Any transport / parse / extract failure is an
/// `Err(String)` — never panics.
pub fn fetch_npm_source(
    http: &dyn HttpClient,
    registry_base: &str,
    name: &str,
    version: &str,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    if name.is_empty() || version.is_empty() {
        return Err("pkgsource: empty name/version".to_string());
    }
    let url = format!(
        "{}/{}",
        registry_base.trim_end_matches('/'),
        encode_pkg(name)
    );
    let resp = http
        .get(&url, &[("Accept", "application/vnd.npm.install-v1+json")])
        .map_err(|e| format!("pkgsource: packument GET: {e}"))?;
    if !resp.is_ok() {
        return Err(format!("pkgsource: packument HTTP {}", resp.status));
    }
    let doc: Value = serde_json::from_slice(&resp.body)
        .map_err(|e| format!("pkgsource: parse packument: {e}"))?;
    let tarball = doc
        .get("versions")
        .and_then(|v| v.get(version))
        .and_then(|v| v.get("dist"))
        .and_then(|d| d.get("tarball"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("pkgsource: no tarball for {name}@{version}"))?;

    let tb = http
        .get(tarball, &[])
        .map_err(|e| format!("pkgsource: tarball GET: {e}"))?;
    if !tb.is_ok() {
        return Err(format!("pkgsource: tarball HTTP {}", tb.status));
    }
    if tb.body.len() as u64 > MAX_TARBALL_BYTES {
        return Err("pkgsource: tarball exceeds size cap".to_string());
    }
    extract_tgz(&tb.body)
}

/// URL-escape a scoped package name (`@scope/name` → `@scope%2fname`); bare
/// names pass through. Mirrors npm's registry path convention.
fn encode_pkg(name: &str) -> String {
    match name.strip_prefix('@').and_then(|rest| rest.split_once('/')) {
        Some((scope, pkg)) => format!("@{scope}%2f{pkg}"),
        None => name.to_string(),
    }
}

/// True when a tarball entry path is safe to materialize: relative, no `..`
/// segment, no absolute root. Mirrors jspkgsource's `isSafeRel`.
fn is_safe_rel(p: &str) -> bool {
    !p.is_empty() && !p.starts_with('/') && !p.split(['/', '\\']).any(|seg| seg == "..")
}

/// Gunzip + untar `raw`, stripping the npm `package/` prefix.
fn extract_tgz(raw: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    extract_tgz_map(raw, |p| {
        Some(p.strip_prefix("package/").unwrap_or(p).to_string())
    })
}

/// Gunzip + untar `raw`, stripping the single top-level directory each entry
/// sits under (`<pkg>-<version>/…` → `…`). The convention for PyPI sdists and
/// crates.io `.crate` archives. Entries not under a top dir are kept as-is.
fn extract_tgz_first_dir(raw: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    extract_tgz_map(raw, strip_first_component)
}

/// Drop the leading path component: `foo-1.0/src/a.py` → `src/a.py`. Returns
/// `None` for a bare top-level file (no `/`) so it's skipped — sdists/crates
/// always nest under one root dir, so a rootless entry is noise.
fn strip_first_component(p: &str) -> Option<String> {
    p.split_once('/').map(|(_, rest)| rest.to_string())
}

/// Gunzip + untar `raw`, mapping each safe regular-file path through `map`
/// (return `None` to skip). Regular files only; bounded by [`MAX_FILE_BYTES`]
/// and [`MAX_ENTRIES`].
fn extract_tgz_map(
    raw: &[u8],
    map: impl Fn(&str) -> Option<String>,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let gz = flate2::read::GzDecoder::new(raw);
    let mut archive = tar::Archive::new(gz);
    let entries = archive
        .entries()
        .map_err(|e| format!("pkgsource: read tar: {e}"))?;

    let mut out = Vec::new();
    for entry in entries {
        if out.len() >= MAX_ENTRIES {
            break;
        }
        let mut entry = entry.map_err(|e| format!("pkgsource: tar entry: {e}"))?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let path = match entry.path() {
            Ok(p) => p.to_string_lossy().replace('\\', "/"),
            Err(_) => continue,
        };
        if !is_safe_rel(&path) {
            continue;
        }
        let Some(rel) = map(&path).filter(|s| !s.is_empty()) else {
            continue;
        };
        let mut buf = Vec::new();
        if entry
            .by_ref()
            .take(MAX_FILE_BYTES)
            .read_to_end(&mut buf)
            .is_err()
        {
            continue;
        }
        out.push((rel, buf));
    }
    if out.is_empty() {
        return Err("pkgsource: tarball had no extractable files".to_string());
    }
    Ok(out)
}

/// Fetch and extract a PyPI package's published **sdist** (source tarball).
/// `api_base` is e.g. `https://pypi.org` (injectable for tests). Reads the
/// per-version JSON (`{api_base}/pypi/{name}/{version}/json`), picks the
/// `sdist` URL, downloads the `.tar.gz`, and extracts it with the top
/// `<name>-<version>/` dir stripped. Wheel-only packages (no sdist) return an
/// `Err` — the caller degrades to advisory-only. Never panics.
pub fn fetch_pypi_source(
    http: &dyn HttpClient,
    api_base: &str,
    name: &str,
    version: &str,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    if name.is_empty() || version.is_empty() {
        return Err("pkgsource: empty name/version".to_string());
    }
    let url = format!(
        "{}/pypi/{}/{}/json",
        api_base.trim_end_matches('/'),
        name,
        version
    );
    let resp = http
        .get(&url, &[("Accept", "application/json")])
        .map_err(|e| format!("pkgsource: pypi GET: {e}"))?;
    if !resp.is_ok() {
        return Err(format!("pkgsource: pypi HTTP {}", resp.status));
    }
    let doc: Value = serde_json::from_slice(&resp.body)
        .map_err(|e| format!("pkgsource: parse pypi json: {e}"))?;
    let urls = doc
        .get("urls")
        .and_then(Value::as_array)
        .ok_or("pkgsource: pypi json has no urls[]")?;
    let sdist = urls
        .iter()
        .find(|u| u.get("packagetype").and_then(Value::as_str) == Some("sdist"))
        .and_then(|u| u.get("url"))
        .and_then(Value::as_str)
        .filter(|s| s.ends_with(".tar.gz"))
        .ok_or_else(|| format!("pkgsource: no sdist for {name}@{version}"))?;

    let tb = http
        .get(sdist, &[])
        .map_err(|e| format!("pkgsource: sdist GET: {e}"))?;
    if !tb.is_ok() {
        return Err(format!("pkgsource: sdist HTTP {}", tb.status));
    }
    if tb.body.len() as u64 > MAX_TARBALL_BYTES {
        return Err("pkgsource: sdist exceeds size cap".to_string());
    }
    extract_tgz_first_dir(&tb.body)
}

/// Fetch and extract a crates.io crate's source. `api_base` is e.g.
/// `https://crates.io` (injectable for tests). Downloads
/// `{api_base}/api/v1/crates/{name}/{version}/download` (which redirects to
/// the `.crate` gzip-tar) and extracts with the top `<name>-<version>/` dir
/// stripped. crates.io requires a `User-Agent`. Never panics.
pub fn fetch_crates_source(
    http: &dyn HttpClient,
    api_base: &str,
    name: &str,
    version: &str,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    if name.is_empty() || version.is_empty() {
        return Err("pkgsource: empty name/version".to_string());
    }
    let url = format!(
        "{}/api/v1/crates/{}/{}/download",
        api_base.trim_end_matches('/'),
        name,
        version
    );
    let tb = http
        .get(&url, &[("User-Agent", "aegis-cli (supply-chain scanner)")])
        .map_err(|e| format!("pkgsource: crate GET: {e}"))?;
    if !tb.is_ok() {
        return Err(format!("pkgsource: crate HTTP {}", tb.status));
    }
    if tb.body.len() as u64 > MAX_TARBALL_BYTES {
        return Err("pkgsource: crate exceeds size cap".to_string());
    }
    extract_tgz_first_dir(&tb.body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_net::MockHttpClient;
    use std::io::Write;

    fn make_tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, body) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            builder.append_data(&mut h, name, *body).unwrap();
        }
        let tar_bytes = builder.into_inner().unwrap();
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(&tar_bytes).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn fetches_and_strips_package_prefix() {
        let reg = "https://reg.test";
        let packument = r#"{"versions":{"1.0.0":{"dist":{"tarball":"https://reg.test/lodash/-/lodash-1.0.0.tgz"}}}}"#;
        let tgz = make_tgz(&[
            ("package/index.js", b"module.exports = 1;"),
            ("package/package.json", b"{\"name\":\"lodash\"}"),
        ]);
        let http = MockHttpClient::new()
            .with(&format!("{reg}/lodash"), 200, packument.as_bytes().to_vec())
            .with("https://reg.test/lodash/-/lodash-1.0.0.tgz", 200, tgz);

        let files = fetch_npm_source(&http, reg, "lodash", "1.0.0").expect("fetch");
        let names: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert!(names.contains(&"index.js"), "{names:?}");
        assert!(names.contains(&"package.json"), "{names:?}");
        // prefix stripped — no "package/" survives.
        assert!(!names.iter().any(|n| n.starts_with("package/")));
    }

    #[test]
    fn scoped_name_is_url_escaped() {
        assert_eq!(encode_pkg("@scope/pkg"), "@scope%2fpkg");
        assert_eq!(encode_pkg("lodash"), "lodash");
    }

    #[test]
    fn pypi_fetches_sdist_and_strips_top_dir() {
        let base = "https://pypi.test";
        let json = r#"{"urls":[
            {"packagetype":"bdist_wheel","url":"https://f.test/jinja2-2.10-py3-none-any.whl"},
            {"packagetype":"sdist","url":"https://f.test/jinja2-2.10.tar.gz"}
        ]}"#;
        let tgz = make_tgz(&[
            ("Jinja2-2.10/jinja2/__init__.py", b"__version__='2.10'"),
            ("Jinja2-2.10/setup.py", b"from setuptools import setup"),
        ]);
        let http = MockHttpClient::new()
            .with(
                &format!("{base}/pypi/jinja2/2.10/json"),
                200,
                json.as_bytes().to_vec(),
            )
            .with("https://f.test/jinja2-2.10.tar.gz", 200, tgz);

        let files = fetch_pypi_source(&http, base, "jinja2", "2.10").expect("fetch");
        let names: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert!(names.contains(&"jinja2/__init__.py"), "{names:?}");
        assert!(names.contains(&"setup.py"), "{names:?}");
        assert!(!names.iter().any(|n| n.starts_with("Jinja2-2.10/")));
    }

    #[test]
    fn pypi_wheel_only_errors() {
        let base = "https://pypi.test";
        let json = r#"{"urls":[{"packagetype":"bdist_wheel","url":"https://f.test/x-1.0-py3-none-any.whl"}]}"#;
        let http = MockHttpClient::new().with(
            &format!("{base}/pypi/x/1.0/json"),
            200,
            json.as_bytes().to_vec(),
        );
        assert!(fetch_pypi_source(&http, base, "x", "1.0").is_err());
    }

    #[test]
    fn crates_fetches_and_strips_top_dir() {
        let base = "https://crates.test";
        let tgz = make_tgz(&[
            ("cc-1.0.79/src/lib.rs", b"pub fn f() {}"),
            ("cc-1.0.79/Cargo.toml", b"[package]\nname='cc'"),
        ]);
        let http = MockHttpClient::new().with(
            &format!("{base}/api/v1/crates/cc/1.0.79/download"),
            200,
            tgz,
        );
        let files = fetch_crates_source(&http, base, "cc", "1.0.79").expect("fetch");
        let names: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert!(names.contains(&"src/lib.rs"), "{names:?}");
        assert!(names.contains(&"Cargo.toml"), "{names:?}");
        assert!(!names.iter().any(|n| n.starts_with("cc-1.0.79/")));
    }

    #[test]
    fn strip_first_component_drops_top_dir() {
        assert_eq!(
            strip_first_component("foo-1.0/src/a.py").as_deref(),
            Some("src/a.py")
        );
        assert_eq!(
            strip_first_component("foo-1.0/a.py").as_deref(),
            Some("a.py")
        );
        // bare top-level file → skipped
        assert_eq!(strip_first_component("README"), None);
    }

    #[test]
    fn path_traversal_entries_dropped() {
        assert!(!is_safe_rel("../evil"));
        assert!(!is_safe_rel("/etc/passwd"));
        assert!(!is_safe_rel("a/../b"));
        assert!(is_safe_rel("package/index.js"));
    }

    #[test]
    fn missing_version_errors() {
        let reg = "https://reg.test";
        let http =
            MockHttpClient::new().with(&format!("{reg}/x"), 200, br#"{"versions":{}}"#.to_vec());
        assert!(fetch_npm_source(&http, reg, "x", "9.9.9").is_err());
    }
}
