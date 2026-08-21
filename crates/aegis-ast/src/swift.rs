//! Swift AST scanner. Native grammar (tree-sitter-swift), no CGO.
use crate::scanner::GrammarScanner;
const QUERY_SRC: &str = include_str!("../queries/swift.scm");
pub fn scanner() -> Result<GrammarScanner, String> {
    GrammarScanner::new(tree_sitter_swift::LANGUAGE.into(), QUERY_SRC)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findings, LanguageScanner};
    use aegis_domain::Capability;
    fn scan(src: &str) -> Vec<Capability> {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("t.swift", src.as_bytes(), &mut f);
        f.capabilities()
    }
    #[test]
    fn query_compiles() {
        assert!(scanner().is_ok());
    }
    #[test]
    fn detects_system() {
        assert!(scan("system(\"ls\")").contains(&Capability::ShellSpawn));
    }
    #[test]
    fn detects_base64() {
        assert!(scan("let d = Data(base64Encoded: s)").contains(&Capability::Base64Decode));
    }
    #[test]
    fn clean_code_no_capabilities() {
        assert!(scan("func add(a: Int, b: Int) -> Int { return a + b }").is_empty());
    }
}
