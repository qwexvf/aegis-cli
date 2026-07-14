//! Ruby AST scanner. Port of `ast/ruby/scanner.go`. Native grammar, no CGO.
use crate::scanner::GrammarScanner;
const QUERY_SRC: &str = include_str!("../queries/ruby.scm");
pub fn scanner() -> Result<GrammarScanner, String> {
    GrammarScanner::new(tree_sitter_ruby::LANGUAGE.into(), QUERY_SRC)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findings, LanguageScanner};
    use aegis_domain::Capability;
    fn scan(src: &str) -> Vec<Capability> {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("t.rb", src.as_bytes(), &mut f);
        f.capabilities()
    }
    #[test]
    fn detects_eval() {
        assert!(scan("eval(payload)").contains(&Capability::DynamicEval));
    }
    #[test]
    fn clean_ok() {
        assert!(scan("def add(a, b)\n  a + b\nend\n").is_empty());
    }
}
