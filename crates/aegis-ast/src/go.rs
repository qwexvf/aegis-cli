//! Go AST scanner. Port of `ast/golang/scanner.go`. Native grammar, no CGO.
use crate::scanner::GrammarScanner;
const QUERY_SRC: &str = include_str!("../queries/go.scm");
pub fn scanner() -> Result<GrammarScanner, String> {
    GrammarScanner::new(tree_sitter_go::LANGUAGE.into(), QUERY_SRC)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findings, LanguageScanner};
    use aegis_domain::Capability;
    fn scan(src: &str) -> Vec<Capability> {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("t.go", src.as_bytes(), &mut f);
        f.capabilities()
    }
    #[test]
    fn query_compiles_and_detects_exec() {
        // os/exec Command → shell-spawn
        let caps = scan("package main\nimport \"os/exec\"\nfunc main(){ exec.Command(\"ls\") }");
        assert!(caps.contains(&Capability::ShellSpawn));
    }
}
