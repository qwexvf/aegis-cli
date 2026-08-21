//! C AST scanner. Native grammar (tree-sitter-c), no CGO.
use crate::scanner::GrammarScanner;
const QUERY_SRC: &str = include_str!("../queries/c.scm");
pub fn scanner() -> Result<GrammarScanner, String> {
    GrammarScanner::new(tree_sitter_c::LANGUAGE.into(), QUERY_SRC)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findings, LanguageScanner};
    use aegis_domain::Capability;
    fn scan(src: &str) -> Vec<Capability> {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("t.c", src.as_bytes(), &mut f);
        f.capabilities()
    }
    #[test]
    fn query_compiles() {
        assert!(scanner().is_ok());
    }
    #[test]
    fn detects_system() {
        assert!(scan("int main(){ system(\"ls\"); }").contains(&Capability::ShellSpawn));
    }
    #[test]
    fn detects_dlopen() {
        assert!(scan("void f(){ dlopen(\"x.so\", 1); }").contains(&Capability::DynamicEval));
    }
    #[test]
    fn detects_getenv() {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("t.c", b"void f(){ getenv(\"SECRET\"); }", &mut f);
        assert!(f.env_reads().contains(&"SECRET".to_string()));
    }
    #[test]
    fn clean_code_no_capabilities() {
        assert!(scan("int add(int a, int b){ return a + b; }").is_empty());
    }
}
