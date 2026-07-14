//! Generic tree-sitter capability scanner shared by every language.
//! Port of the common logic in each `ast/<lang>/scanner.go` (the part
//! that's identical across languages — `@cap.<name>` → Capability and
//! `@env_var` → env-read). Language-specific extras (JS taint pass) live
//! in the per-language module.

use aegis_domain::{Capability, ALL_CAPABILITIES};
use streaming_iterator::StreamingIterator;
use tree_sitter::{Language, Parser, Query, QueryCursor};

use crate::{Findings, LanguageScanner};

/// An optional second pass run on the same parse tree after the query
/// pass (e.g. the JS constant-fold/taint analysis, which tree-sitter
/// queries alone can't express).
pub type PostPass = for<'a> fn(tree_sitter::Node<'a>, &[u8], &str, &mut Findings);

/// A compiled grammar + query. Cheap to share; the heavy compile is
/// one-time. Mirrors the common `Scanner` shape.
pub struct GrammarScanner {
    language: Language,
    query: Query,
    /// capture index → capability (pre-computed; hot loop avoids lookups).
    capture_to_cap: Vec<Option<Capability>>,
    /// capture index of `@env_var`, if present.
    env_read_idx: Option<u32>,
    /// optional language-specific second pass over the same tree.
    post_pass: Option<PostPass>,
}

impl GrammarScanner {
    /// Compile `query_src` against `language`. Errors on a malformed
    /// query (a developer bug — the query is embedded at build time).
    pub fn new(language: Language, query_src: &str) -> Result<Self, String> {
        Self::with_post_pass(language, query_src, None)
    }

    /// Like [`new`](Self::new) but attaches a second pass over the tree.
    pub fn with_post_pass(
        language: Language,
        query_src: &str,
        post_pass: Option<PostPass>,
    ) -> Result<Self, String> {
        let query = Query::new(&language, query_src).map_err(|e| format!("query: {e}"))?;
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
        Ok(GrammarScanner {
            language,
            query,
            capture_to_cap,
            env_read_idx,
            post_pass,
        })
    }
}

impl LanguageScanner for GrammarScanner {
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

        // Optional language-specific second pass over the same tree.
        if let Some(pp) = self.post_pass {
            pp(tree.root_node(), body, path, findings);
        }
    }
}

/// Map a `cap.<name>` suffix to a [`Capability`] by its canonical name.
/// Mirrors `capabilityFor`.
fn capability_for(suffix: &str) -> Option<Capability> {
    ALL_CAPABILITIES
        .iter()
        .copied()
        .find(|c| c.name() == suffix)
}
