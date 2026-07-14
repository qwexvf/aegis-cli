//! CocoaPods `Podfile.lock` parser. Port of `lockfile_cocoapods.go`.
//! Two passes: DEPENDENCIES for direct pod names, PODS for every
//! resolved pod + version. Subspec entries (with "/") are skipped.

use std::collections::HashSet;
use std::sync::OnceLock;

use aegis_domain::{Dependency, Ecosystem};
use regex::Regex;

use crate::{DirectMap, LockfileParser, ParseError};

pub struct PodfileLock;

fn pod_entry_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^  - ([\w/.-]+)\s+\(([^)]+)\)").unwrap())
}
fn dep_entry_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^  - ([\w/.-]+)\s+").unwrap())
}

impl LockfileParser for PodfileLock {
    fn filename(&self) -> &'static str {
        "Podfile.lock"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::CocoaPods
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let text = String::from_utf8_lossy(raw);

        // Pass 1: direct pod names from DEPENDENCIES.
        let mut direct_names: HashSet<String> = HashSet::new();
        let mut section = "";
        for line in text.lines() {
            match line.trim() {
                "PODS:" => section = "pods",
                "DEPENDENCIES:" => section = "deps",
                "SPEC CHECKSUMS:" | "EXTERNAL SOURCES:" | "CHECKOUT OPTIONS:" | "SPEC REPOS:" => {
                    section = ""
                }
                _ => {
                    if section == "deps" {
                        if let Some(m) = dep_entry_re().captures(line) {
                            let base = m[1].split('/').next().unwrap_or("").to_string();
                            direct_names.insert(base);
                        }
                    }
                }
            }
        }

        // Pass 2: resolved pods with exact versions.
        let mut out = Vec::new();
        section = "";
        for line in text.lines() {
            match line.trim() {
                "PODS:" => {
                    section = "pods";
                    continue;
                }
                "DEPENDENCIES:" | "SPEC CHECKSUMS:" | "EXTERNAL SOURCES:" | "CHECKOUT OPTIONS:"
                | "SPEC REPOS:" => {
                    section = "";
                    continue;
                }
                _ => {}
            }
            if section != "pods" {
                continue;
            }
            let Some(m) = pod_entry_re().captures(line) else {
                continue;
            };
            let pod_name = m[1].to_string();
            let version = m[2].to_string();
            // Skip subspecs — parent pod already listed at same version.
            if pod_name.contains('/') {
                continue;
            }
            let direct = direct_names.contains(&pod_name);
            out.push(Dependency {
                ecosystem: Ecosystem::CocoaPods,
                name: pod_name,
                version,
                direct,
                ..Default::default()
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pods_flags_direct_skips_subspec() {
        let raw = b"PODS:\n\
                    \x20\x20- Alamofire (5.8.0)\n\
                    \x20\x20- AFNetworking (4.0.1):\n\
                    \x20\x20\x20\x20- AFNetworking/NSURLSession (= 4.0.1)\n\
                    \n\
                    DEPENDENCIES:\n\
                    \x20\x20- Alamofire (~> 5.0)\n\
                    \n\
                    SPEC CHECKSUMS:\n\
                    \x20\x20Alamofire: abc123\n";
        let deps = PodfileLock.parse(raw, &DirectMap::new()).unwrap();
        let names: Vec<_> = deps.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["Alamofire", "AFNetworking"]);
        assert!(deps.iter().find(|d| d.name == "Alamofire").unwrap().direct);
        assert!(
            !deps
                .iter()
                .find(|d| d.name == "AFNetworking")
                .unwrap()
                .direct
        );
    }
}
