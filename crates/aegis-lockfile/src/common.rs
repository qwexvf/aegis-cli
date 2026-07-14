//! Shared helpers used by more than one parser. Always compiled — the
//! TOML reader backs both the cargo and pypi (poetry/uv) parsers.

/// A (name, version) pair from a `[[package]]` TOML table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TomlPackage {
    pub name: String,
    pub version: String,
}

/// Scan a TOML document for `[[package]]` tables and pull `name` +
/// `version` from each. Hand-rolled (matching the Go original) to avoid
/// a full TOML dependency — handles the subset Poetry, uv, and Cargo
/// emit. Mirrors `parseTOMLPackages`.
#[cfg_attr(not(any(feature = "cargo", feature = "pypi")), allow(dead_code))]
pub(crate) fn parse_toml_packages(raw: &[u8]) -> Vec<TomlPackage> {
    let text = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    let mut cur: Option<TomlPackage> = None;

    // Flush the in-progress package if it's complete.
    fn flush(cur: &mut Option<TomlPackage>, out: &mut Vec<TomlPackage>) {
        if let Some(p) = cur.take() {
            if !p.name.is_empty() && !p.version.is_empty() {
                out.push(p);
            }
        }
    }

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[package]]" {
            flush(&mut cur, &mut out);
            cur = Some(TomlPackage {
                name: String::new(),
                version: String::new(),
            });
            continue;
        }
        // Any other table header ends the current package block.
        if line.starts_with('[') {
            flush(&mut cur, &mut out);
            continue;
        }
        let Some(p) = cur.as_mut() else { continue };
        if line.starts_with("name") {
            if let Some(v) = toml_string(line) {
                p.name = v;
            }
        } else if line.starts_with("version") {
            if let Some(v) = toml_string(line) {
                p.version = v;
            }
        }
    }
    flush(&mut cur, &mut out);
    out
}

/// Extract the quoted value from a `key = "value"` line. Double-quoted
/// only (Poetry/uv/Cargo don't use multi-line literal forms for
/// name/version). None on parse failure. Mirrors `tomlString`.
#[cfg_attr(not(any(feature = "cargo", feature = "pypi")), allow(dead_code))]
pub(crate) fn toml_string(line: &str) -> Option<String> {
    let (_, after) = line.split_once('=')?;
    let rhs = after.trim();
    let bytes = rhs.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' {
        return None;
    }
    let end = rhs.rfind('"')?;
    if end == 0 {
        return None;
    }
    Some(rhs[1..end].to_string())
}
