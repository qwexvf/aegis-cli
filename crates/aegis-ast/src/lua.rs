//! lua AST scanner. Port of `ast/lua/scanner.go`. Native grammar, no CGO.
use crate::scanner::GrammarScanner;
const QUERY_SRC: &str = include_str!("../queries/lua.scm");
pub fn scanner() -> Result<GrammarScanner, String> {
    GrammarScanner::new(tree_sitter_lua::LANGUAGE.into(), QUERY_SRC)
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
