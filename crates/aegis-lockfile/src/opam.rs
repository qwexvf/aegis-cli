//! OCaml opam lockfile parser (`<project>.opam.locked`, written by
//! `opam lock`). The lockfile is an opam-syntax package file whose `depends:`
//! field pins every resolved dependency to an exact version:
//!
//! ```text
//! opam-version: "2.0"
//! depends: [
//!   "dune" {= "3.6.1"}
//!   "cmdliner" {= "1.1.1" & with-test}
//! ]
//! ```
//!
//! The lock name is project-prefixed, so this parser matches by the
//! `.opam.locked` suffix rather than an exact filename (see
//! [`LockfileParser::matches`]). Only equality pins (`{= "v"}`) are taken —
//! any range/other constraint is skipped, so a non-lock `.opam` with ranges
//! yields nothing rather than a bad version.

use std::collections::HashSet;
use std::sync::OnceLock;

use aegis_domain::{Dependency, Ecosystem};
use regex::Regex;

use crate::{DirectMap, LockfileParser, ParseError};

pub struct OpamLocked;

/// `"name" {= "version"` — an exact pin. Trailing filters (`& with-test`) and
/// the closing brace are outside the capture and ignored.
fn pin_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#""([A-Za-z0-9_.+-]+)"\s*\{\s*=\s*"([^"]+)""#).unwrap())
}

/// The contents of the `depends: [ ... ]` field (between the brackets), or
/// `None` if there is no depends field. Bracket-depth aware so nested `[]`
/// (rare in depends, common defensiveness) don't end the block early.
fn depends_block(text: &str) -> Option<&str> {
    let start = text.find("depends:")?;
    let rest = &text[start..];
    let open = rest.find('[')?;
    let mut depth = 0i32;
    for (j, c) in rest[open..].char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&rest[open + 1..open + j]);
                }
            }
            _ => {}
        }
    }
    None
}

impl LockfileParser for OpamLocked {
    fn filename(&self) -> &'static str {
        // Representative name; real matching is by suffix (see `matches`).
        "project.opam.locked"
    }
    fn matches(&self, filename: &str) -> bool {
        filename.ends_with(".opam.locked")
    }
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Opam
    }
    fn parse(&self, raw: &[u8], _direct: &DirectMap) -> Result<Vec<Dependency>, ParseError> {
        let text = String::from_utf8_lossy(raw);
        let Some(block) = depends_block(&text) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for m in pin_re().captures_iter(block) {
            let name = m[1].to_string();
            let ver = m[2].to_string();
            if !seen.insert(format!("{name}@{ver}")) {
                continue;
            }
            out.push(Dependency {
                ecosystem: Ecosystem::Opam,
                name,
                version: ver,
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
    fn matches_by_suffix() {
        assert!(OpamLocked.matches("myproj.opam.locked"));
        assert!(OpamLocked.matches("a.b.opam.locked"));
        assert!(!OpamLocked.matches("myproj.opam"));
        assert!(!OpamLocked.matches("opam.locked.txt"));
    }

    #[test]
    fn parses_exact_pins_from_depends() {
        let raw = br#"opam-version: "2.0"
name: "myproj"
depends: [
  "dune" {= "3.6.1"}
  "cmdliner" {= "1.1.1" & with-test}
  "ocaml" {>= "4.14.0"}
]
"#;
        let deps = OpamLocked.parse(raw, &DirectMap::new()).unwrap();
        // dune + cmdliner are exact pins; ocaml is a range → skipped.
        assert_eq!(deps.len(), 2, "{deps:?}");
        let dune = deps.iter().find(|d| d.name == "dune").unwrap();
        assert_eq!(dune.version, "3.6.1");
        assert_eq!(dune.ecosystem, Ecosystem::Opam);
        assert!(deps
            .iter()
            .any(|d| d.name == "cmdliner" && d.version == "1.1.1"));
        assert!(!deps.iter().any(|d| d.name == "ocaml"));
    }

    #[test]
    fn no_depends_field_is_empty() {
        let raw = br#"opam-version: "2.0"
name: "x"
"#;
        assert!(OpamLocked.parse(raw, &DirectMap::new()).unwrap().is_empty());
    }
}
