//! C++ AST scanner. Native grammar (tree-sitter-cpp), no CGO.
use crate::scanner::GrammarScanner;
const QUERY_SRC: &str = include_str!("../queries/cpp.scm");
pub fn scanner() -> Result<GrammarScanner, String> {
    GrammarScanner::new(tree_sitter_cpp::LANGUAGE.into(), QUERY_SRC)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findings, LanguageScanner};
    use aegis_domain::Capability;
    fn scan(src: &str) -> Vec<Capability> {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("t.cpp", src.as_bytes(), &mut f);
        f.capabilities()
    }
    #[test]
    fn query_compiles() {
        assert!(scanner().is_ok());
    }
    #[test]
    fn detects_std_system() {
        assert!(scan("int main(){ std::system(\"ls\"); }").contains(&Capability::ShellSpawn));
    }
    #[test]
    fn detects_bare_system() {
        assert!(scan("int main(){ system(\"ls\"); }").contains(&Capability::ShellSpawn));
    }
    #[test]
    fn clean_code_no_capabilities() {
        assert!(scan("int add(int a, int b){ return a + b; }").is_empty());
    }
}
