//! gleam AST scanner. Port of `ast/gleam/scanner.go`. Native grammar, no CGO.
use crate::scanner::GrammarScanner;
const QUERY_SRC: &str = include_str!("../queries/gleam.scm");
pub fn scanner() -> Result<GrammarScanner, String> {
    GrammarScanner::new(tree_sitter_gleam::LANGUAGE.into(), QUERY_SRC)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findings, LanguageScanner};
    use aegis_domain::Capability;
    fn scan(src: &str) -> Vec<Capability> {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("t.gleam", src.as_bytes(), &mut f);
        f.capabilities()
    }
    #[test]
    fn query_compiles() {
        assert!(scanner().is_ok());
    }
    #[test]
    fn external_ffi_is_dynamic_eval() {
        // @external(erlang, ...) bypasses Gleam's type safety.
        let caps = scan("@external(erlang, \"os\", \"cmd\")\npub fn run(c: String) -> String\n");
        assert!(caps.contains(&Capability::DynamicEval), "{caps:?}");
    }
    #[test]
    fn http_import_is_net_egress() {
        let caps = scan("import gleam/http\npub fn main() { Nil }\n");
        assert!(caps.contains(&Capability::NetEgress), "{caps:?}");
    }
}
