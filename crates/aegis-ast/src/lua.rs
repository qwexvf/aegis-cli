//! lua AST scanner. Port of `ast/lua/scanner.go`. Native grammar, no CGO.
use crate::scanner::GrammarScanner;
const QUERY_SRC: &str = include_str!("../queries/lua.scm");
pub fn scanner() -> Result<GrammarScanner, String> {
    GrammarScanner::new(tree_sitter_lua::LANGUAGE.into(), QUERY_SRC)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findings, LanguageScanner};
    use aegis_domain::Capability;
    fn scan(src: &str) -> Findings {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("t.lua", src.as_bytes(), &mut f);
        f
    }
    #[test]
    fn query_compiles() {
        // The query must compile against the grammar (developer-bug guard).
        assert!(scanner().is_ok());
    }
    #[test]
    fn records_env_var_names() {
        let f = scan(
            "local a = os.getenv(\"AWS_SECRET_ACCESS_KEY\")\n\
             local b = vim.env.GITHUB_TOKEN\n\
             local c = vim.env[\"NPM_TOKEN\"]\n\
             local d = vim.fn.getenv(\"GH_TOKEN\")\n\
             local e = vim.uv.os_getenv(\"SSH_AUTH_SOCK\")\n",
        );
        assert!(f.capabilities().contains(&Capability::EnvRead));
        for name in [
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "NPM_TOKEN",
            "GH_TOKEN",
            "SSH_AUTH_SOCK",
        ] {
            assert!(f.env_reads().iter().any(|n| n == name), "missing {name}");
        }
    }
    #[test]
    fn non_literal_getenv_still_reads_env() {
        let f = scan("local v = os.getenv(name)\n");
        assert!(f.capabilities().contains(&Capability::EnvRead));
        assert!(f.env_reads().is_empty());
    }
    #[test]
    fn detects_native_load() {
        for src in [
            "ffi.load(\"/tmp/x.so\")",
            "package.cpath = package.cpath .. \";/tmp/?.so\"",
            "package.loadlib(\"/tmp/x.so\", \"luaopen_x\")",
        ] {
            assert!(
                scan(src)
                    .capabilities()
                    .contains(&Capability::InstallHookExec),
                "{src}"
            );
        }
    }
    #[test]
    fn clean_ok() {
        assert!(scan("local function add(a, b) return a + b end\n")
            .capabilities()
            .is_empty());
    }
}
