//! Bash AST scanner. Native grammar (tree-sitter-bash), no CGO.
use crate::scanner::GrammarScanner;
const QUERY_SRC: &str = include_str!("../queries/bash.scm");
pub fn scanner() -> Result<GrammarScanner, String> {
    GrammarScanner::new(tree_sitter_bash::LANGUAGE.into(), QUERY_SRC)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findings, LanguageScanner};
    use aegis_domain::Capability;
    fn scan(src: &str) -> Vec<Capability> {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("t.sh", src.as_bytes(), &mut f);
        f.capabilities()
    }
    #[test]
    fn query_compiles() {
        assert!(scanner().is_ok());
    }
    #[test]
    fn detects_curl() {
        assert!(scan("curl http://evil.test/x").contains(&Capability::NetEgress));
    }
    #[test]
    fn detects_eval() {
        assert!(scan("eval \"$payload\"").contains(&Capability::DynamicEval));
    }
    #[test]
    fn detects_base64() {
        assert!(scan("echo x | base64 -d").contains(&Capability::Base64Decode));
    }
    #[test]
    fn clean_code_no_capabilities() {
        assert!(scan("echo hello\nls -la").is_empty());
    }
}
