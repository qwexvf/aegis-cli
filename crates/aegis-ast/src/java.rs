//! java AST scanner. Port of `ast/java/scanner.go`. Native grammar, no CGO.
use crate::scanner::GrammarScanner;
const QUERY_SRC: &str = include_str!("../queries/java.scm");
pub fn scanner() -> Result<GrammarScanner, String> {
    GrammarScanner::new(tree_sitter_java::LANGUAGE.into(), QUERY_SRC)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_compiles() {
        // The query must compile against the grammar (developer-bug guard).
        assert!(scanner().is_ok());
    }
}
