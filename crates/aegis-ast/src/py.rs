//! Python AST scanner. Port of `ast/py/scanner.go`.
//!
//! tree-sitter-python grammar (native — no CGO) + verbatim
//! `queries/py.scm`. Same generic capture→capability logic as JS
//! (Python has no taint second pass).

use crate::scanner::GrammarScanner;

const QUERY_SRC: &str = include_str!("../queries/py.scm");

/// Build the Python scanner.
pub fn scanner() -> Result<GrammarScanner, String> {
    let language = tree_sitter_python::LANGUAGE.into();
    GrammarScanner::new(language, QUERY_SRC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findings, LanguageScanner};
    use aegis_domain::Capability;

    fn scan(src: &str) -> Vec<Capability> {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("test.py", src.as_bytes(), &mut f);
        f.capabilities()
    }

    #[test]
    fn detects_subprocess() {
        // subprocess.call / os.system → shell-spawn
        assert!(
            scan("import subprocess\nsubprocess.call(['ls'])").contains(&Capability::ShellSpawn)
        );
    }

    #[test]
    fn detects_os_system() {
        assert!(scan("import os\nos.system('rm -rf /')").contains(&Capability::ShellSpawn));
    }

    #[test]
    fn detects_eval_exec() {
        let caps = scan("eval(compile('1','<s>','eval'))");
        assert!(caps.contains(&Capability::DynamicEval));
    }

    #[test]
    fn detects_base64_decode() {
        assert!(scan("import base64\nbase64.b64decode(x)").contains(&Capability::Base64Decode));
    }

    #[test]
    fn clean_code_no_capabilities() {
        assert!(scan("def add(a, b):\n    return a + b\n").is_empty());
    }
}
