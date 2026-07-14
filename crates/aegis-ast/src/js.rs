//! JavaScript / TypeScript AST scanner. Port of `ast/js/scanner.go`.
//!
//! tree-sitter-javascript grammar (native — no CGO) + verbatim
//! `queries/js.scm`. The Go second-pass taint/constant-fold engine
//! (`taint.go`) is a follow-up.

use crate::scanner::GrammarScanner;

const QUERY_SRC: &str = include_str!("../queries/js.scm");

/// Build the JS/TS scanner.
pub fn scanner() -> Result<GrammarScanner, String> {
    let language = tree_sitter_javascript::LANGUAGE.into();
    GrammarScanner::new(language, QUERY_SRC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findings, LanguageScanner};
    use aegis_domain::Capability;

    fn scan(src: &str) -> Vec<Capability> {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("test.js", src.as_bytes(), &mut f);
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
        assert!(!scan("const m = /foo/.exec(input);").contains(&Capability::ShellSpawn));
    }

    #[test]
    fn clean_code_no_capabilities() {
        assert!(scan("export const add = (a, b) => a + b;").is_empty());
    }

    #[test]
    fn evidence_records_line_and_snippet() {
        let s = scanner().unwrap();
        let mut f = Findings::new(true);
        s.analyze_file("m.js", b"\n\neval('x')", &mut f);
        let ev = f.evidence();
        assert!(!ev.is_empty());
        assert_eq!(ev[0].capability, Capability::DynamicEval);
        assert_eq!(ev[0].line, 3);
    }
}
