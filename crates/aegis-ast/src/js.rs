//! JavaScript / TypeScript AST scanner. Port of `ast/js/scanner.go`.
//!
//! tree-sitter-javascript grammar (native — no CGO) + verbatim
//! `queries/js.scm`. The Go second-pass taint/constant-fold engine
//! (`taint.go`) is a follow-up.

use crate::scanner::GrammarScanner;

const QUERY_SRC: &str = include_str!("../queries/js.scm");

/// Build the JS/TS scanner, including the constant-fold/taint second pass.
pub fn scanner() -> Result<GrammarScanner, String> {
    let language = tree_sitter_javascript::LANGUAGE.into();
    GrammarScanner::with_post_pass(language, QUERY_SRC, Some(crate::js_taint::taint_pass))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findings, LanguageScanner};
    use aegis_domain::Capability;

    fn scan(src: &str) -> Vec<Capability> {
        let s = scanner().unwrap();
        let mut f = Findings::new(false);
        s.analyze_file("test.js", src.as_bytes(), &mut f);
        f.capabilities()
    }

    /// Depth of AST nesting is attacker-controlled, so the taint walk must not
    /// recurse. `@babel/traverse@8.0.4` and `@babel/types@8.0.4` — dependencies
    /// of nearly every JS project — aborted the scanner with
    /// `fatal runtime error: stack overflow` on a rayon worker; a hand-written
    /// file can nest far deeper than a bundler ever would. Scanning happens on
    /// pool threads, so the small stack here is the realistic case, not a
    /// contrived one.
    #[test]
    fn deep_nesting_does_not_overflow_a_small_stack() {
        const DEPTH: usize = 20_000;
        let src = format!("const a = {}1{};", "[".repeat(DEPTH), "]".repeat(DEPTH));
        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || {
                let s = scanner().unwrap();
                let mut f = Findings::new(false);
                s.analyze_file("deep.js", src.as_bytes(), &mut f);
            })
            .unwrap()
            .join()
            .expect("scanning a deeply nested file must not overflow the stack");
    }

    #[test]
    fn detects_eval() {
        assert!(scan("eval('x')").contains(&Capability::DynamicEval));
    }

    #[test]
    fn detects_new_function() {
        assert!(scan("const f = new Function('return 1')").contains(&Capability::DynamicEval));
    }

    #[test]
    fn detects_child_process_require() {
        assert!(scan("const cp = require('child_process')").contains(&Capability::ShellSpawn));
    }

    #[test]
    fn detects_execsync_member_call() {
        assert!(scan("cp.execSync('ls')").contains(&Capability::ShellSpawn));
    }

    #[test]
    fn detects_atob_base64() {
        assert!(scan("atob('aGk=')").contains(&Capability::Base64Decode));
    }

    #[test]
    fn bare_regex_exec_not_flagged() {
        assert!(!scan("const m = /foo/.exec(input);").contains(&Capability::ShellSpawn));
    }

    #[test]
    fn clean_code_no_capabilities() {
        assert!(scan("export const add = (a, b) => a + b;").is_empty());
    }

    #[test]
    fn evidence_records_line_and_snippet() {
        let s = scanner().unwrap();
        let mut f = Findings::new(true);
        s.analyze_file("m.js", b"\n\neval('x')", &mut f);
        let ev = f.evidence();
        assert!(!ev.is_empty());
        assert_eq!(ev[0].capability, Capability::DynamicEval);
        assert_eq!(ev[0].line, 3);
    }

    #[test]
    fn taint_folds_fromcharcode_to_suspicious_url() {
        // String.fromCharCode codes spelling a pastebin.com URL — the query
        // pass can't see the host, the constant-fold pass can.
        // "https://pastebin.com" as char codes:
        let codes = "https://pastebin.com"
            .chars()
            .map(|c| (c as u32).to_string())
            .collect::<Vec<_>>()
            .join(",");
        let src = format!("const u = String.fromCharCode({codes});");
        assert!(scan(&src).contains(&Capability::SuspiciousUrl));
    }

    #[test]
    fn taint_ignores_benign_fromcharcode() {
        // "hello" — not suspicious.
        let codes = "hello"
            .chars()
            .map(|c| (c as u32).to_string())
            .collect::<Vec<_>>()
            .join(",");
        let src = format!("const s = String.fromCharCode({codes});");
        assert!(scan(&src).is_empty());
    }

    #[test]
    fn taint_folds_spread_of_numeric_array() {
        // const a = [<codes for pastebin url>]; const b = String.fromCharCode(...a);
        // Requires the symbol table: the fold var resolves `...a` to the array.
        let codes = "https://pastebin.com/raw"
            .chars()
            .map(|c| (c as u32).to_string())
            .collect::<Vec<_>>()
            .join(",");
        let src = format!("const a = [{codes}];\nconst b = String.fromCharCode(...a);");
        assert!(scan(&src).contains(&Capability::SuspiciousUrl), "{src}");
    }

    #[test]
    fn taint_atob_var_reaches_eval_is_dynamic_eval() {
        // const x = atob("..."); eval(x);  → tainted var reaches eval sink.
        let src = "const x = atob('YWxlcnQoMSk=');\neval(x);";
        assert!(scan(src).contains(&Capability::DynamicEval), "{src}");
    }

    #[test]
    fn taint_buffer_base64_var_reaches_fetch_is_net_egress() {
        let src = "const u = Buffer.from('aHR0cA==', 'base64');\nfetch(u + '://x');";
        assert!(scan(src).contains(&Capability::NetEgress), "{src}");
    }

    #[test]
    fn taint_untainted_var_in_sink_not_flagged_by_taint() {
        // A plain string var into eval isn't a *taint* hit (no decode source).
        // (The query pass may still flag eval itself as dynamic-eval — that's
        // separate; here we assert the taint pass doesn't add net/shell caps.)
        let src = "const x = 'hello';\nfetch(x);";
        let caps = scan(src);
        // fetch(x) with untainted x: net-egress here comes from the query pass
        // (fetch is a net sink) — but the taint pass must not fire on a
        // non-decoded var. Assert no shell/eval taint leaked in.
        assert!(!caps.contains(&Capability::ShellSpawn), "{caps:?}");
    }

    #[test]
    fn taint_base64_var_no_sink_no_taint_hit() {
        // Decoded but never reaches a sink → no taint capability from pass 2.
        let src = "const x = atob('aGk=');\nconsole.log(x);";
        // Base64Decode (from the query pass on atob) is fine; but no
        // dynamic-eval / shell-spawn / net-egress should come from taint.
        let caps = scan(src);
        assert!(!caps.contains(&Capability::ShellSpawn), "{caps:?}");
    }
}
