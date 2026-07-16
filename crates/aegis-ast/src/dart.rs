//! dart AST scanner. Port of `ast/dart/scanner.go`. Native grammar, no CGO.
use crate::scanner::GrammarScanner;
const QUERY_SRC: &str = include_str!("../queries/dart.scm");
pub fn scanner() -> Result<GrammarScanner, String> {
    GrammarScanner::new(tree_sitter_dart::LANGUAGE.into(), QUERY_SRC)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findings, LanguageScanner};
    use aegis_domain::Capability;
    fn scan(src: &str) -> Vec<Capability> {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("t.dart", src.as_bytes(), &mut f);
        f.capabilities()
    }
    #[test]
    fn query_compiles() {
        assert!(scanner().is_ok());
    }
    #[test]
    fn process_run_is_shell_spawn() {
        let caps = scan("void main() { Process.run('ls', []); }");
        assert!(caps.contains(&Capability::ShellSpawn), "{caps:?}");
    }
    #[test]
    fn httpclient_is_net_egress() {
        let caps = scan("void main() { var c = HttpClient(); }");
        assert!(caps.contains(&Capability::NetEgress), "{caps:?}");
    }
}
