//! Elixir AST scanner. Native grammar (tree-sitter-elixir), no CGO.
use crate::scanner::GrammarScanner;
const QUERY_SRC: &str = include_str!("../queries/elixir.scm");
pub fn scanner() -> Result<GrammarScanner, String> {
    GrammarScanner::new(tree_sitter_elixir::LANGUAGE.into(), QUERY_SRC)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findings, LanguageScanner};
    use aegis_domain::Capability;
    fn scan(src: &str) -> Vec<Capability> {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("t.ex", src.as_bytes(), &mut f);
        f.capabilities()
    }
    #[test]
    fn query_compiles() {
        assert!(scanner().is_ok());
    }
    #[test]
    fn detects_system_cmd() {
        assert!(scan("System.cmd(\"sh\", [\"-c\", \"ls\"])").contains(&Capability::ShellSpawn));
    }
    #[test]
    fn detects_code_eval() {
        assert!(scan("Code.eval_string(\"1 + 1\")").contains(&Capability::DynamicEval));
    }
    #[test]
    fn detects_base64() {
        assert!(scan("Base.decode64(\"aGk=\")").contains(&Capability::Base64Decode));
    }
    #[test]
    fn detects_get_env() {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("t.ex", b"System.get_env(\"SECRET\")", &mut f);
        assert!(f.env_reads().contains(&"SECRET".to_string()));
    }
    #[test]
    fn clean_code_no_capabilities() {
        assert!(scan("defmodule M do\n  def add(a, b), do: a + b\nend").is_empty());
    }
}
