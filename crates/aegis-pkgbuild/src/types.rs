//! Input and output types for the PKGBUILD scanner. Ported from the Go
//! `internal/domain/aur.go`; the wire names (`rule`, `where`, severity and
//! verdict strings) are kept identical so the JSON contract does not move.

/// Ranks a finding. `Critical` maps to a hard block, `High` prompts,
/// `Medium`/`Low` are informational unless they stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn name(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Info => "info",
        }
    }
}

/// The gate decision for one package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Allow,
    Warn,
    Block,
}

impl Verdict {
    pub fn name(self) -> &'static str {
        match self {
            Verdict::Block => "block",
            Verdict::Warn => "warn",
            Verdict::Allow => "allow",
        }
    }
}

/// One suspicious pattern the scanner matched. `where_` is a
/// human-readable location (`PKGBUILD:build()`, `.install:post_install`,
/// `PKGBUILD:source[]`); `evidence` is the offending line, truncated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub rule: &'static str,
    pub where_: String,
    pub message: String,
    pub evidence: String,
}

/// A file committed into the package's own repository rather than fetched
/// from a URL.
///
/// The caller does the I/O and passes the bytes in, so the scanner stays
/// pure. `head` only needs enough leading bytes to identify the format —
/// 8 is sufficient for every magic number checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFile {
    pub name: String,
    pub head: Vec<u8>,
    pub size: u64,
    /// True when this file did not exist in the previous revision.
    pub added: bool,
}

/// The raw, fetched content of one AUR package.
///
/// `upstream` is the `url=` field when known — the scanner uses it as the
/// trusted-host anchor for source-drift checks. `prev_pkgbuild`, when
/// present, is the currently installed version's PKGBUILD, letting the
/// scanner flag the *change* rather than the package merely existing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub pkgbuild: Vec<u8>,
    /// Concatenated `.install` hook bodies. May be empty.
    pub install: Vec<u8>,
    pub upstream: String,
    pub prev_pkgbuild: Option<Vec<u8>>,
    pub local_files: Vec<LocalFile>,
}

/// Scanner output for one package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub package: String,
    pub findings: Vec<Finding>,
    pub verdict: Verdict,
}

impl ScanResult {
    /// Any Critical → Block, any High → Warn, otherwise Allow.
    pub(crate) fn derive_verdict(findings: &[Finding]) -> Verdict {
        let mut v = Verdict::Allow;
        for f in findings {
            match f.severity {
                Severity::Critical => return Verdict::Block,
                Severity::High => v = v.max(Verdict::Warn),
                _ => {}
            }
        }
        v
    }
}

/// Trim and cap evidence so a minified one-liner cannot flood the output.
/// Truncates on a char boundary — a PKGBUILD may contain UTF-8.
pub(crate) fn trunc(s: &str) -> String {
    const MAX: usize = 160;
    let s = s.trim();
    if s.chars().count() <= MAX {
        return s.to_string();
    }
    let cut: String = s.chars().take(MAX).collect();
    cut + "…"
}
