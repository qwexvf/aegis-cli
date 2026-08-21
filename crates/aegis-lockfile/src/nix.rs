//! Nix `flake.lock` parser.
//!
//! A flake lock is JSON: a `nodes` map keyed by input name, each carrying a
//! `locked` object with the pinned source (`rev` for git-ish inputs,
//! `narHash` otherwise). The `root` node is the flake itself and is skipped.
//! Name = the node key (the input name in the flake); version = the pinned
//! `rev`, falling back to `narHash`. Nodes with neither are skipped.

use std::collections::HashMap;

use aegis_domain::{Dependency, Ecosystem};
use serde::Deserialize;

use crate::{DirectMap, LockfileParser, ParseError};

pub struct FlakeLock;

#[derive(Deserialize, Default)]
struct Locked {
    #[serde(default)]
    rev: String,
    #[serde(rename = "narHash", default)]
    nar_hash: String,
}

#[derive(Deserialize, Default)]
struct NodeEntry {
    #[serde(default)]
    locked: Option<Locked>,
}

#[derive(Deserialize, Default)]
struct Doc {
    #[serde(default)]
    nodes: HashMap<String, NodeEntry>,
    #[serde(default)]
    root: String,
}

impl LockfileParser for FlakeLock {
    fn filename(&self) -> &'static str {
        "flake.lock"
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Nix
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let doc: Doc =
            serde_json::from_slice(raw).map_err(|e| ParseError(format!("flake.lock: {e}")))?;
        let root = if doc.root.is_empty() {
            "root"
        } else {
            &doc.root
        };
        let mut out = Vec::new();
        for (name, node) in &doc.nodes {
            if name == root {
                continue;
            }
            let Some(locked) = &node.locked else {
                continue;
            };
            let version = if !locked.rev.is_empty() {
                locked.rev.clone()
            } else if !locked.nar_hash.is_empty() {
                locked.nar_hash.clone()
            } else {
                continue;
            };
            out.push(Dependency {
                ecosystem: Ecosystem::Nix,
                name: name.clone(),
                version,
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
    fn parses_input_nodes_skipping_root() {
        let raw = br#"{
            "nodes": {
                "root": { "inputs": { "nixpkgs": "nixpkgs" } },
                "nixpkgs": {
                    "locked": {
                        "type": "github",
                        "owner": "NixOS",
                        "repo": "nixpkgs",
                        "rev": "a1b2c3d4e5f6",
                        "narHash": "sha256-xxxx",
                        "lastModified": 1700000000
                    }
                },
                "flake-utils": {
                    "locked": {
                        "type": "github",
                        "narHash": "sha256-yyyy"
                    }
                }
            },
            "root": "root",
            "version": 7
        }"#;
        let mut deps = FlakeLock.parse(raw, &DirectMap::new()).unwrap();
        deps.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(deps.len(), 2);
        let nixpkgs = deps.iter().find(|d| d.name == "nixpkgs").unwrap();
        assert_eq!(nixpkgs.ecosystem, Ecosystem::Nix);
        assert_eq!(nixpkgs.version, "a1b2c3d4e5f6");
        // falls back to narHash when there's no rev.
        let fu = deps.iter().find(|d| d.name == "flake-utils").unwrap();
        assert_eq!(fu.version, "sha256-yyyy");
    }

    #[test]
    fn empty_lockfile_is_ok() {
        let deps = FlakeLock.parse(b"{}", &DirectMap::new()).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn corrupt_input_errors() {
        assert!(FlakeLock.parse(b"[[[", &DirectMap::new()).is_err());
    }
}
