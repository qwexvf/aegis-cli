//! Kotlin AST scanner. Native grammar (tree-sitter-kotlin-ng), no CGO.
use crate::scanner::GrammarScanner;
const QUERY_SRC: &str = include_str!("../queries/kotlin.scm");
pub fn scanner() -> Result<GrammarScanner, String> {
    GrammarScanner::new(tree_sitter_kotlin_ng::LANGUAGE.into(), QUERY_SRC)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findings, LanguageScanner};
    use aegis_domain::Capability;
    fn scan(src: &str) -> Vec<Capability> {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("t.kt", src.as_bytes(), &mut f);
        f.capabilities()
    }
    #[test]
    fn query_compiles() {
        assert!(scanner().is_ok());
    }
    #[test]
    fn detects_runtime_exec() {
        let caps = scan("fun main(){ Runtime.getRuntime().exec(\"ls\") }");
        assert!(caps.contains(&Capability::ShellSpawn));
    }
    #[test]
    fn detects_net_egress() {
        let caps = scan("fun f(){ URL(\"http://x\").openConnection() }");
        assert!(caps.contains(&Capability::NetEgress));
    }
    #[test]
    fn clean_code_no_capabilities() {
        assert!(scan("fun add(a: Int, b: Int): Int { return a + b }").is_empty());
    }

    #[test]
    fn detects_getenv() {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file(
            "t.kt",
            b"fun f() { val x = System.getenv(\"SECRET\") }",
            &mut f,
        );
        assert!(
            f.env_reads().contains(&"SECRET".to_string()),
            "env_reads={:?}",
            f.env_reads()
        );
    }
}
