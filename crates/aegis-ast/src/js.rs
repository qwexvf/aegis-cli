//! JavaScript / TypeScript AST scanner. Port of `ast/js/scanner.go`.
//!
//! tree-sitter-javascript grammar (native Rust — no CGO) + the verbatim
//! `queries/js.scm`. `@cap.<name>` captures → [`Capability`]; `@env_var`
//! captures record env-var names. The Go second-pass taint/constant-fold
//! engine is a follow-up (see `taint.go`).

use std::sync::OnceLock;

use aegis_domain::{Capability, ALL_CAPABILITIES};
use streaming_iterator::StreamingIterator;
use tree_sitter::{Language, Parser, Query, QueryCursor};

use crate::{Findings, LanguageScanner};

const QUERY_SRC: &str = include_str!("../queries/js.scm");

/// Compiled JS analyzer. Cheap to clone-share; the heavy compile happens
/// once. Mirrors `js.Scanner`.
pub struct JsScanner {
    language: Language,
    query: Query,
    /// capture index → capability (pre-computed, hot-loop avoids lookups).
    capture_to_cap: Vec<Option<Capability>>,
    /// capture index of `@env_var`, if present.
    env_read_idx: Option<u32>,
}

impl JsScanner {
    pub fn new() -> Result<Self, String> {
        let language: Language = tree_sitter_javascript::LANGUAGE.into();
        let query = Query::new(&language, QUERY_SRC).map_err(|e| format!("js query: {e}"))?;

        let names = query.capture_names();
        let mut capture_to_cap = vec![None; names.len()];
        let mut env_read_idx = None;
        for (i, name) in names.iter().enumerate() {
            if let Some(suffix) = name.strip_prefix("cap.") {
                capture_to_cap[i] = capability_for(suffix);
            } else if *name == "env_var" {
                env_read_idx = Some(i as u32);
            }
        }

        Ok(JsScanner {
            language,
            query,
            capture_to_cap,
            env_read_idx,
        })
    }
}

impl LanguageScanner for JsScanner {
    fn analyze_file(&self, path: &str, body: &[u8], findings: &mut Findings) {
        let mut parser = Parser::new();
        if parser.set_language(&self.language).is_err() {
            return;
        }
        let Some(tree) = parser.parse(body, None) else {
            return;
        };

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&self.query, tree.root_node(), body);
        while let Some(m) = matches.next() {
            for cap in m.captures {
                let idx = cap.index as usize;
                if let Some(Some(c)) = self.capture_to_cap.get(idx) {
                    findings.add_capability(*c);
                    if findings.collect_evidence {
                        let line = cap.node.start_position().row + 1;
                        let snippet = cap.node.utf8_text(body).unwrap_or("").to_string();
                        findings.add_evidence(*c, path, line, snippet);
                    }
                } else if Some(cap.index) == self.env_read_idx {
                    if let Ok(name) = cap.node.utf8_text(body) {
                        findings.add_env_read(name);
                    }
                }
            }
        }
        // Go runs a second constant-fold + taint pass here (taint.go);
        // that's a follow-up.
    }
}

/// Map a `cap.<name>` suffix to a [`Capability`] by matching its
/// canonical name. Mirrors `capabilityFor`.
fn capability_for(suffix: &str) -> Option<Capability> {
    ALL_CAPABILITIES
        .iter()
        .copied()
        .find(|c| c.name() == suffix)
}

/// Convenience: a process-wide shared scanner (compiling the query is not
/// free). Returns None if the grammar/query fails to compile (a bug).
pub fn shared() -> Option<&'static JsScanner> {
    static S: OnceLock<Option<JsScanner>> = OnceLock::new();
    S.get_or_init(|| JsScanner::new().ok()).as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(src: &str) -> Vec<Capability> {
        let scanner = JsScanner::new().unwrap();
        let mut f = Findings::new(false);
        scanner.analyze_file("test.js", src.as_bytes(), &mut f);
        f.capabilities()
    }

    #[test]
    fn detects_eval() {
        assert!(scan("eval('x')").contains(&Capability::DynamicEval));
    }

    #[test]
    fn detects_new_function() {
        assert!(scan("const f = new Function('return 1')").contains(&Capability::DynamicEval));
    }

    #[test]
    fn detects_child_process_require() {
        assert!(scan("const cp = require('child_process')").contains(&Capability::ShellSpawn));
    }

    #[test]
    fn detects_execsync_member_call() {
        assert!(scan("cp.execSync('ls')").contains(&Capability::ShellSpawn));
    }

    #[test]
    fn detects_atob_base64() {
        assert!(scan("atob('aGk=')").contains(&Capability::Base64Decode));
    }

    #[test]
    fn bare_regex_exec_not_flagged() {
        // RegExp.prototype.exec must NOT trip shell-spawn (the query
        // deliberately excludes bare .exec).
        let caps = scan("const m = /foo/.exec(input);");
        assert!(!caps.contains(&Capability::ShellSpawn));
    }

    #[test]
    fn clean_code_no_capabilities() {
        assert!(scan("export const add = (a, b) => a + b;").is_empty());
    }

    #[test]
    fn evidence_records_line_and_snippet() {
        let scanner = JsScanner::new().unwrap();
        let mut f = Findings::new(true);
        scanner.analyze_file("m.js", b"\n\neval('x')", &mut f);
        let ev = f.evidence();
        assert!(!ev.is_empty());
        assert_eq!(ev[0].capability, Capability::DynamicEval);
        assert_eq!(ev[0].line, 3);
        assert_eq!(ev[0].path, "m.js");
    }
}
