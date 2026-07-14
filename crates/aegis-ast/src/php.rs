//! PHP AST scanner. Port of `ast/php/scanner.go`. Native grammar, no CGO.
use crate::scanner::GrammarScanner;
const QUERY_SRC: &str = include_str!("../queries/php.scm");
pub fn scanner() -> Result<GrammarScanner, String> {
    GrammarScanner::new(tree_sitter_php::LANGUAGE_PHP.into(), QUERY_SRC)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findings, LanguageScanner};
    use aegis_domain::Capability;
    fn scan(src: &str) -> Vec<Capability> {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("t.php", src.as_bytes(), &mut f);
        f.capabilities()
    }
    #[test]
    fn detects_eval() {
        assert!(scan("<?php eval($payload); ?>").contains(&Capability::DynamicEval));
    }
}
