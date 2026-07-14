//! Rust AST scanner. Port of `ast/rust/scanner.go`. Native grammar, no CGO.
use crate::scanner::GrammarScanner;
const QUERY_SRC: &str = include_str!("../queries/rust.scm");
pub fn scanner() -> Result<GrammarScanner, String> {
    GrammarScanner::new(tree_sitter_rust::LANGUAGE.into(), QUERY_SRC)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findings, LanguageScanner};
    use aegis_domain::Capability;
    fn scan(src: &str) -> Vec<Capability> {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("t.rs", src.as_bytes(), &mut f);
        f.capabilities()
    }
    #[test]
    fn query_compiles_and_detects_command() {
        // std::process::Command → shell-spawn
        let caps = scan("fn main(){ std::process::Command::new(\"ls\").spawn(); }");
        assert!(caps.contains(&Capability::ShellSpawn));
    }
}
