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

/// Fetch and extract a PyPI package's published source. `api_base` is e.g.
/// `https://pypi.org` (injectable for tests). Reads the per-version JSON
/// (`{api_base}/pypi/{name}/{version}/json`) and prefers the `sdist`
/// (`.tar.gz`, top `<name>-<version>/` dir stripped); when the release is
/// wheel-only it falls back to a `bdist_wheel` (`.whl` = a zip with the
/// package modules at root, no prefix to strip), preferring a pure-python
/// `py3-none-any` wheel. Only when neither exists does it `Err` — the caller
/// then degrades to advisory-only. Never panics.
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

    // Prefer the sdist (real source); fall back to a wheel.
    if let Some(sdist) = urls
        .iter()
        .find(|u| u.get("packagetype").and_then(Value::as_str) == Some("sdist"))
        .and_then(|u| u.get("url"))
        .and_then(Value::as_str)
        .filter(|s| s.ends_with(".tar.gz"))
    {
        let tb = http
            .get(sdist, &[])
            .map_err(|e| format!("pkgsource: sdist GET: {e}"))?;
        if !tb.is_ok() {
            return Err(format!("pkgsource: sdist HTTP {}", tb.status));
        }
        if tb.body.len() as u64 > MAX_TARBALL_BYTES {
            return Err("pkgsource: sdist exceeds size cap".to_string());
        }
        return extract_tgz_first_dir(&tb.body);
    }

    let wheel = pick_wheel(urls)
        .ok_or_else(|| format!("pkgsource: no sdist/wheel for {name}@{version}"))?;
    let wb = http
        .get(wheel, &[])
        .map_err(|e| format!("pkgsource: wheel GET: {e}"))?;
    if !wb.is_ok() {
        return Err(format!("pkgsource: wheel HTTP {}", wb.status));
    }
    if wb.body.len() as u64 > MAX_TARBALL_BYTES {
        return Err("pkgsource: wheel exceeds size cap".to_string());
    }
    // Wheel files sit at the archive root (`pkg/…`, `pkg-ver.dist-info/…`),
    // so no prefix is stripped.
    extract_zip(&wb.body, "")
}

/// Pick a `bdist_wheel` URL from the PyPI `urls[]`, preferring a pure-python
/// `py3-none-any` (or `-none-any`) wheel over a platform-specific one.
fn pick_wheel(urls: &[Value]) -> Option<&str> {
    let wheels: Vec<&str> = urls
        .iter()
        .filter(|u| u.get("packagetype").and_then(Value::as_str) == Some("bdist_wheel"))
        .filter_map(|u| u.get("url").and_then(Value::as_str))
        .filter(|s| s.ends_with(".whl"))
        .collect();
    wheels
        .iter()
        .find(|s| s.contains("-none-any"))
        .or_else(|| wheels.first())
        .copied()
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

/// Fetch and extract a RubyGems gem's source. `api_base` is e.g.
/// `https://rubygems.org` (injectable for tests). Downloads
/// `{api_base}/downloads/{name}-{version}.gem` — a gem is an *uncompressed*
/// tar wrapping `data.tar.gz` (the real source, files at root) plus metadata;
/// this unwraps `data.tar.gz` and extracts it. Never panics.
pub fn fetch_rubygems_source(
    http: &dyn HttpClient,
    api_base: &str,
    name: &str,
    version: &str,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    if name.is_empty() || version.is_empty() {
        return Err("pkgsource: empty name/version".to_string());
    }
    let url = format!(
        "{}/downloads/{}-{}.gem",
        api_base.trim_end_matches('/'),
        name,
        version
    );
    let gem = http
        .get(&url, &[])
        .map_err(|e| format!("pkgsource: gem GET: {e}"))?;
    if !gem.is_ok() {
        return Err(format!("pkgsource: gem HTTP {}", gem.status));
    }
    if gem.body.len() as u64 > MAX_TARBALL_BYTES {
        return Err("pkgsource: gem exceeds size cap".to_string());
    }
    extract_gem(&gem.body)
}

/// Fetch and extract a Go module's source zip from the module proxy.
/// `proxy_base` is e.g. `https://proxy.golang.org` (injectable for tests).
/// Downloads `{proxy_base}/{escaped-module}/@v/{escaped-version}.zip` and
/// extracts it, stripping the `<module>@<version>/` prefix every entry carries.
/// Uppercase letters in the module path / version are `!`-escaped per the
/// proxy protocol. Never panics.
pub fn fetch_go_source(
    http: &dyn HttpClient,
    proxy_base: &str,
    name: &str,
    version: &str,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    if name.is_empty() || version.is_empty() {
        return Err("pkgsource: empty name/version".to_string());
    }
    let url = format!(
        "{}/{}/@v/{}.zip",
        proxy_base.trim_end_matches('/'),
        escape_go(name),
        escape_go(version)
    );
    let z = http
        .get(&url, &[])
        .map_err(|e| format!("pkgsource: go zip GET: {e}"))?;
    if !z.is_ok() {
        return Err(format!("pkgsource: go zip HTTP {}", z.status));
    }
    if z.body.len() as u64 > MAX_TARBALL_BYTES {
        return Err("pkgsource: go zip exceeds size cap".to_string());
    }
    let prefix = format!("{name}@{version}/");
    extract_zip(&z.body, &prefix)
}

/// Escape a Go module path / version for the proxy: each uppercase letter
/// becomes `!` + its lowercase form (the proxy is case-insensitive on disk).
/// Mirrors `golang.org/x/mod/module.EscapePath`.
fn escape_go(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Unzip `raw` (deflate), stripping `prefix` from each entry. Regular files
/// only; bounded by [`MAX_FILE_BYTES`] and [`MAX_ENTRIES`].
fn extract_zip(raw: &[u8], prefix: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    let reader = std::io::Cursor::new(raw);
    let mut zip = zip::ZipArchive::new(reader).map_err(|e| format!("pkgsource: open zip: {e}"))?;
    let mut out = Vec::new();
    for i in 0..zip.len() {
        if out.len() >= MAX_ENTRIES {
            break;
        }
        let mut f = match zip.by_index(i) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if !f.is_file() {
            continue;
        }
        let path = f.name().replace('\\', "/");
        if !is_safe_rel(&path) {
            continue;
        }
        let rel = path.strip_prefix(prefix).unwrap_or(&path).to_string();
        if rel.is_empty() {
            continue;
        }
        let mut buf = Vec::new();
        if f.by_ref()
            .take(MAX_FILE_BYTES)
            .read_to_end(&mut buf)
            .is_err()
        {
            continue;
        }
        out.push((rel, buf));
    }
    if out.is_empty() {
        return Err("pkgsource: go zip had no extractable files".to_string());
    }
    Ok(out)
}

/// Unwrap a `.gem` (uncompressed tar) → its inner `data.tar.gz` → the source
/// file map. Gem data files sit at the root (`lib/…`, `ext/…`), so no prefix
/// is stripped.
fn extract_gem(raw: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut archive = tar::Archive::new(raw);
    let entries = archive
        .entries()
        .map_err(|e| format!("pkgsource: read gem: {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("pkgsource: gem entry: {e}"))?;
        let path = entry
            .path()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        if path == "data.tar.gz" {
            let mut data = Vec::new();
            entry
                .by_ref()
                .take(MAX_TARBALL_BYTES)
                .read_to_end(&mut data)
                .map_err(|e| format!("pkgsource: read gem data: {e}"))?;
            return extract_tgz_map(&data, |p| Some(p.to_string()));
        }
    }
    Err("pkgsource: gem has no data.tar.gz".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_net::MockHttpClient;
    use std::io::Write;

    fn make_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, body) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            builder.append_data(&mut h, name, *body).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn make_tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let tar_bytes = make_tar(entries);
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(&tar_bytes).unwrap();
        enc.finish().unwrap()
    }

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(body).unwrap();
        }
        w.finish().unwrap().into_inner()
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
    fn pypi_wheel_only_falls_back_to_wheel() {
        let base = "https://pypi.test";
        let json = r#"{"urls":[
            {"packagetype":"bdist_wheel","url":"https://f.test/x-1.0-cp39-cp39-linux.whl"},
            {"packagetype":"bdist_wheel","url":"https://f.test/x-1.0-py3-none-any.whl"}
        ]}"#;
        // wheel files sit at the archive root (no top dir).
        let whl = make_zip(&[
            ("x/__init__.py", b"__version__='1.0'"),
            ("x-1.0.dist-info/METADATA", b"Name: x"),
        ]);
        let http = MockHttpClient::new()
            .with(
                &format!("{base}/pypi/x/1.0/json"),
                200,
                json.as_bytes().to_vec(),
            )
            // pure-python wheel is preferred over the platform one.
            .with("https://f.test/x-1.0-py3-none-any.whl", 200, whl);
        let files = fetch_pypi_source(&http, base, "x", "1.0").expect("fetch");
        let names: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert!(names.contains(&"x/__init__.py"), "{names:?}");
        assert!(names.contains(&"x-1.0.dist-info/METADATA"), "{names:?}");
    }

    #[test]
    fn pypi_no_dist_errors() {
        let base = "https://pypi.test";
        let json = r#"{"urls":[]}"#;
        let http = MockHttpClient::new().with(
            &format!("{base}/pypi/x/1.0/json"),
            200,
            json.as_bytes().to_vec(),
        );
        assert!(fetch_pypi_source(&http, base, "x", "1.0").is_err());
    }

    #[test]
    fn pick_wheel_prefers_pure_python() {
        let urls: Vec<Value> = serde_json::from_str(
            r#"[
                {"packagetype":"bdist_wheel","url":"https://f/x-1.0-cp39-cp39-manylinux.whl"},
                {"packagetype":"bdist_wheel","url":"https://f/x-1.0-py3-none-any.whl"},
                {"packagetype":"sdist","url":"https://f/x-1.0.tar.gz"}
            ]"#,
        )
        .unwrap();
        assert_eq!(pick_wheel(&urls), Some("https://f/x-1.0-py3-none-any.whl"));
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
    fn rubygems_unwraps_data_tar_gz() {
        let base = "https://gems.test";
        // A .gem is an uncompressed tar containing data.tar.gz (source at root).
        let data = make_tgz(&[("lib/rack.rb", b"module Rack; end"), ("README.md", b"rack")]);
        let gem = make_tar(&[
            ("metadata.gz", b"--- fake"),
            ("data.tar.gz", &data),
            ("checksums.yaml.gz", b"--- fake"),
        ]);
        let http =
            MockHttpClient::new().with(&format!("{base}/downloads/rack-2.0.5.gem"), 200, gem);
        let files = fetch_rubygems_source(&http, base, "rack", "2.0.5").expect("fetch");
        let names: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert!(names.contains(&"lib/rack.rb"), "{names:?}");
        assert!(names.contains(&"README.md"), "{names:?}");
    }

    #[test]
    fn go_unzips_and_strips_module_version_prefix() {
        let base = "https://proxy.test";
        let zip = make_zip(&[
            ("github.com/foo/bar@v1.2.3/bar.go", b"package bar"),
            (
                "github.com/foo/bar@v1.2.3/internal/x.go",
                b"package internal",
            ),
        ]);
        let http = MockHttpClient::new().with(
            &format!("{base}/github.com/foo/bar/@v/v1.2.3.zip"),
            200,
            zip,
        );
        let files = fetch_go_source(&http, base, "github.com/foo/bar", "v1.2.3").expect("fetch");
        let names: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert!(names.contains(&"bar.go"), "{names:?}");
        assert!(names.contains(&"internal/x.go"), "{names:?}");
        assert!(!names.iter().any(|n| n.contains("@v1.2.3")));
    }

    #[test]
    fn go_module_path_uppercase_escaped() {
        assert_eq!(
            escape_go("github.com/BurntSushi/toml"),
            "github.com/!burnt!sushi/toml"
        );
        assert_eq!(escape_go("github.com/foo/bar"), "github.com/foo/bar");
        assert_eq!(escape_go("v1.2.3"), "v1.2.3");
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
