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

/// Gunzip + untar `raw`, stripping the npm `package/` prefix. Regular files
/// only; bounded by [`MAX_FILE_BYTES`] and [`MAX_ENTRIES`].
fn extract_tgz(raw: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
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
        // Strip the conventional top-level "package/" directory.
        let rel = path.strip_prefix("package/").unwrap_or(&path).to_string();
        if rel.is_empty() {
            continue;
        }
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
