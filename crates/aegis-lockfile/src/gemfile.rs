//! Bundler `Gemfile.lock` parser. Port of `lockfile_gemfile.go`.
//!
//! Purpose-built format (not YAML/TOML). Two passes: read DEPENDENCIES
//! for direct-dep names, then collect GEM `specs:` (4-space-indented
//! `name (version)` lines; 6-space sub-deps skipped).

use aegis_domain::{Dependency, Ecosystem};

use crate::{DirectMap, LockfileParser, ParseError};

pub struct GemfileLock;

impl LockfileParser for GemfileLock {
    fn filename(&self) -> &'static str {
        "Gemfile.lock"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::RubyGems
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let text = String::from_utf8_lossy(raw);
        let direct = collect_direct(&text);
        Ok(collect_specs(&text, &direct))
    }
}

/// First pass: the DEPENDENCIES section lists user-declared gems by name.
fn collect_direct(text: &str) -> std::collections::HashSet<String> {
    let mut direct = std::collections::HashSet::new();
    let mut in_deps = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "DEPENDENCIES" {
            in_deps = true;
            continue;
        }
        if !in_deps {
            continue;
        }
        // Section ends at first non-indented or blank line.
        if trimmed.is_empty() || !line.starts_with("  ") {
            break;
        }
        // "rails (~> 7.1)" / "rails!" — cut at first space/!/(.
        let name = trimmed.split([' ', '!', '(']).next().unwrap_or("");
        if !name.is_empty() {
            direct.insert(name.to_string());
        }
    }
    direct
}

/// Second pass: collect GEM specs.
fn collect_specs(text: &str, direct: &std::collections::HashSet<String>) -> Vec<Dependency> {
    let mut out = Vec::new();
    let mut in_gem = false;
    let mut in_specs = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "GEM" {
            in_gem = true;
            in_specs = false;
            continue;
        }
        // New top-level (non-indented) section ends GEM.
        let is_new_section = !line.is_empty() && !line.starts_with(' ') && trimmed != "GEM";
        if in_gem && is_new_section {
            in_gem = false;
            in_specs = false;
            continue;
        }
        if !in_gem {
            continue;
        }
        if trimmed == "specs:" {
            in_specs = true;
            continue;
        }
        if !in_specs {
            continue;
        }
        // Spec lines are indented exactly 4 spaces; 6-space sub-deps skip.
        if !line.starts_with("    ") || line.starts_with("      ") {
            continue;
        }
        // "name (version)".
        let (Some(open), Some(close)) = (trimmed.find('('), trimmed.rfind(')')) else {
            continue;
        };
        if close <= open {
            continue;
        }
        let name = trimmed[..open].trim();
        let version = trimmed[open + 1..close].trim();
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.push(Dependency {
            ecosystem: Ecosystem::RubyGems,
            name: name.to_string(),
            version: version.to_string(),
            direct: direct.contains(name),
            ..Default::default()
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_specs_and_flags_direct() {
        let raw = b"GEM\n\
                    \x20\x20remote: https://rubygems.org/\n\
                    \x20\x20specs:\n\
                    \x20\x20\x20\x20actionpack (7.1.2)\n\
                    \x20\x20\x20\x20\x20\x20actionview (= 7.1.2)\n\
                    \x20\x20\x20\x20activerecord (7.1.2)\n\
                    \n\
                    PLATFORMS\n\
                    \x20\x20ruby\n\
                    \n\
                    DEPENDENCIES\n\
                    \x20\x20rails (~> 7.1)\n\
                    \x20\x20actionpack\n";
        let deps = GemfileLock.parse(raw, &DirectMap::new()).unwrap();
        let names: Vec<_> = deps.iter().map(|d| d.name.as_str()).collect();
        // sub-dep actionview (6-space) excluded.
        assert_eq!(names, ["actionpack", "activerecord"]);
        assert!(deps.iter().find(|d| d.name == "actionpack").unwrap().direct);
        assert!(
            !deps
                .iter()
                .find(|d| d.name == "activerecord")
                .unwrap()
                .direct
        );
    }
}
