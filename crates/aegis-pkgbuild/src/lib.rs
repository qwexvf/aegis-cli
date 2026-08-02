//! Static PKGBUILD / AUR malware scanner.
//!
//! Clean-room Rust port of the Go `internal/domain/aur.go`, plus the
//! content rules from `AEGIS-PLAN.txt` §3.5 that the Go scanner lacks.
//!
//! Pure: no I/O, no network, no clock. Everything the rules need — file
//! bytes for the magic-number check, the previous revision for the diff
//! rules — is passed in by the caller.
//!
//! Two axes of detection, and both are needed:
//!
//! - **Provenance**: where the sources come from, whether the host drifted
//!   from the declared upstream, whether the name is a known IOC.
//! - **Content**: what the script actually does — escalates privilege,
//!   executes a committed blob, ships an unverifiable source.
//!
//! The pgadmin4-server compromise (`b7de293`, 2026-07-29) is why the second
//! axis exists: eight months of clean provenance, same maintainer, no host
//! change, and the entire signal was `sudo "$srcdir/parser"` plus a 43 KB
//! ELF committed into the package repo. See `tests::pgadmin4_*`.

mod builtpkg;
mod patterns;
mod types;

use patterns::*;
use types::trunc;
pub use types::{Finding, GitHistory, LocalFile, Package, ScanResult, Severity, Verdict};

pub use builtpkg::{inspect_package, PkgEntry};
pub use patterns::package_denied;

/// Statically scan an AUR package's PKGBUILD and `.install` hooks.
///
/// Catches the delivery vectors used in the real AUR campaigns: untrusted
/// source drift, download-and-exec, foreign-toolchain injection,
/// obfuscation, credential exfil, privilege escalation, committed
/// binaries, and known IOCs. It cannot see runtime behaviour — that is a
/// sandbox's job.
pub fn scan(pkg: &Package) -> ScanResult {
    let mut findings = Vec::new();

    // 0. denylist — hard block, independent of content.
    if package_denied(&pkg.name) {
        findings.push(Finding {
            severity: Severity::Critical,
            rule: "ioc-package",
            where_: "package".into(),
            message: "package name is on the confirmed-malicious AUR denylist".into(),
            evidence: String::new(),
        });
    }

    findings.extend(scan_bytes(&pkg.pkgbuild, "PKGBUILD", &pkg.upstream));
    findings.extend(scan_bytes(&pkg.install, ".install", &pkg.upstream));

    // Content rules (§3.5) — structural, not line-by-line.
    let text = String::from_utf8_lossy(&pkg.pkgbuild).into_owned();
    findings.extend(check_checksum_count(&text));
    findings.extend(check_binary_in_source(&text, &pkg.local_files));
    findings.extend(check_local_binary_added(&pkg.local_files));
    findings.extend(check_history(pkg));

    let verdict = ScanResult::derive_verdict(&findings);
    ScanResult {
        package: pkg.name.clone(),
        findings,
        verdict,
    }
}

/// Extract the PKGBUILD `url=` field, used to anchor source-drift
/// detection. Returns an empty string when absent.
pub fn parse_upstream_url(pkgbuild: &[u8]) -> String {
    let text = String::from_utf8_lossy(pkgbuild);
    for line in text.lines() {
        if let Some(c) = url_assign().captures(line) {
            return c[1].trim_matches(['"', '\'']).to_string();
        }
    }
    String::new()
}

fn scan_bytes(body: &[u8], file: &str, upstream: &str) -> Vec<Finding> {
    if body.is_empty() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(body).into_owned();
    let mut out = Vec::new();
    let mut cur_fn = file.to_string();

    // denylisted build deps — scan the whole body once.
    let low = text.to_ascii_lowercase();
    for dep in DENY_DEPS {
        if low.contains(&dep.to_ascii_lowercase()) {
            out.push(Finding {
                severity: Severity::Critical,
                rule: "ioc-dep",
                where_: file.into(),
                message: format!("references a package confirmed as a malware stager ({dep})"),
                evidence: (*dep).into(),
            });
        }
    }

    let mut scanned_source = false;
    // Metadata arrays span lines; a dependency named qtkeychain-qt6 sitting
    // on a continuation line is not credential access.
    let mut in_metadata = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if in_metadata {
            if line.contains(')') {
                in_metadata = false;
            }
            continue;
        }
        if is_metadata_line(line) {
            // Opens an array that does not close on the same line.
            if line.contains('(') && !line.contains(')') {
                in_metadata = true;
            }
            continue;
        }
        if let Some(c) = pkgbuild_funcs().captures(line) {
            cur_fn = format!("{file}:{}()", &c[1]);
        }

        if net_exec().is_match(line) || b64_exec().is_match(line) {
            out.push(Finding {
                severity: Severity::Critical,
                rule: "download-exec",
                where_: cur_fn.clone(),
                message: "downloads and pipes remote content directly into a shell".into(),
                evidence: trunc(line),
            });
        }
        // §3.5 privilege-escalation-in-build. makepkg refuses to run as
        // root, so there is no legitimate reason for a PKGBUILD to
        // escalate. Flagged at top level too, not just inside functions —
        // top-level code runs when the file is sourced, which is worse.
        if privilege_escalation().is_match(line) {
            out.push(Finding {
                severity: Severity::Critical,
                rule: "privilege-escalation-in-build",
                where_: cur_fn.clone(),
                message: "escalates privilege inside a build script — makepkg refuses to run \
                          as root, and paru holds a sudo loop open so this will not prompt"
                    .into(),
                evidence: trunc(line),
            });
        }
        // `eval "package_$_p() {` is the standard split-package idiom in
        // kernel PKGBUILDs, not obfuscation.
        if eval_sub().is_match(line) && !split_package_eval().is_match(line) {
            out.push(Finding {
                severity: Severity::High,
                rule: "eval-obfuscation",
                where_: cur_fn.clone(),
                message: "eval of dynamic/quoted content — common obfuscation".into(),
                evidence: trunc(line),
            });
        }
        if hex_esc().is_match(line) {
            out.push(Finding {
                severity: Severity::High,
                rule: "hex-obfuscation",
                where_: cur_fn.clone(),
                message: "hex-escaped string payload".into(),
                evidence: trunc(line),
            });
        }
        if foreign_tool().is_match(line) {
            out.push(Finding {
                // Medium, not high: 4 of 97 sampled packages invoke yarn or
                // pnpm legitimately during build. On its own this is
                // context, not a finding — it earns its keep only when it
                // stacks with something else.
                severity: Severity::Medium,
                rule: "foreign-toolchain",
                where_: cur_fn.clone(),
                message: "invokes a foreign package manager during build \
                          (unrelated-ecosystem dep pull)"
                    .into(),
                evidence: trunc(line),
            });
        }
        // Metadata arrays describe the package, they do not run. `optdepends`
        // mentioning "~/.ssh/config import", or a dep literally named
        // qtkeychain-qt6, are not credential access.
        if exfil_paths().is_match(line) {
            out.push(Finding {
                severity: Severity::High,
                rule: "credential-access",
                where_: cur_fn.clone(),
                message: "touches credential / secret / wallet paths".into(),
                evidence: trunc(line),
            });
        }
        // The URL scan walks the whole body, so run it once rather than
        // per source line. (The Go original re-scans per match, producing
        // duplicate findings for multi-line arrays.)
        if !scanned_source && source_line().is_match(line) {
            scanned_source = true;
            out.extend(scan_source(&text, upstream, file));
        }
    }
    out
}

/// Flag `source=()` entries pointing at hosts unrelated to the declared
/// upstream — the Chaos RAT "patches" vector. Scans the whole body so it
/// catches multi-line arrays.
fn scan_source(text: &str, upstream: &str, file: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    // URLs inside comments are documentation, not sources. The Go original
    // scanned the raw body and flagged a bug-tracker link in a comment.
    let text: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let text = text.as_str();
    let host = host_of(upstream);
    let where_ = format!("{file}:source[]");
    let mut seen: Vec<&str> = Vec::new();

    for m in url_token().find_iter(text) {
        let tok = m.as_str();
        if seen.contains(&tok) {
            continue;
        }
        seen.push(tok);

        if bare_ip().is_match(tok) {
            out.push(Finding {
                severity: Severity::High,
                rule: "source-bare-ip",
                where_: where_.clone(),
                message: "source fetched from a raw IP address".into(),
                evidence: trunc(tok),
            });
            continue;
        }
        let h = host_of(tok);
        if is_untrusted_host(&h) {
            out.push(Finding {
                severity: Severity::High,
                rule: "source-untrusted-host",
                where_: where_.clone(),
                message: "source fetched from a paste/shortener/anon host".into(),
                evidence: trunc(tok),
            });
        }
        // Only meaningful when the declared upstream is ITSELF a code host:
        // "url= says github.com/alice, source= pulls github.com/bob" is the
        // Chaos RAT shape. "url= is the project homepage, source= is GitHub
        // releases" is how most packages are written — 22 of 97 sampled
        // packages tripped the old form for exactly that reason.
        if !host.is_empty() && !h.is_empty() && h != host && is_code_host(&h) && is_code_host(&host)
        {
            out.push(Finding {
                severity: Severity::Medium,
                rule: "source-host-drift",
                where_: where_.clone(),
                message: format!("source host differs from declared upstream url ({host})"),
                evidence: trunc(tok),
            });
        }
    }
    out
}

// --- §3.5 content rules ---

/// True for PKGBUILD metadata assignments — declarative fields that
/// describe the package rather than code that executes.
fn is_metadata_line(line: &str) -> bool {
    const KEYS: &[&str] = &[
        "depends",
        "optdepends",
        "makedepends",
        "checkdepends",
        "provides",
        "conflicts",
        "replaces",
        "pkgdesc",
        "license",
        "groups",
        "backup",
        "options",
    ];
    let head = line.trim_start();
    KEYS.iter().any(|k| {
        head.strip_prefix(k)
            .is_some_and(|r| r.starts_with('=') || r.starts_with("+="))
    }) || head.starts_with('\'') && head.contains(": ")
}

/// Extract the elements of a bash array assignment `name=( ... )`,
/// spanning newlines. Returns `None` when the array is absent.
fn bash_array(text: &str, name: &str) -> Option<Vec<String>> {
    let key = format!("{name}=(");
    let mut open = None;
    let mut off = 0usize;
    for line in text.lines() {
        let indent = line.len() - line.trim_start().len();
        if line.trim_start().starts_with(&key) {
            open = Some(off + indent + key.len());
            break;
        }
        off += line.len() + 1; // +1 for the newline `lines()` stripped
    }
    let rest = &text[open?..];
    let close = rest.find(')')?;
    let body = &rest[..close];

    // Strip trailing comments; PKGBUILD arrays routinely annotate entries
    // ("config  # the main kernel config file").
    let body: String = body
        .lines()
        .map(|l| match l.find('#') {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let body = body.as_str();

    let mut items = Vec::new();
    for c in quoted_or_bare_word().captures_iter(body) {
        let raw = c
            .get(1)
            .or_else(|| c.get(2))
            .map(|m| m.as_str())
            .unwrap_or_default()
            .trim();
        if !raw.is_empty() {
            items.push(raw.to_string());
        }
    }
    Some(items)
}

/// True when the entry is a bare filename shipped in the package repo
/// rather than something fetched. Handles makepkg's `rename::url` syntax.
fn is_local_source(entry: &str) -> bool {
    let target = entry.rsplit("::").next().unwrap_or(entry);
    !target.contains("://") && !target.starts_with("git+")
}

/// Identify executables by magic number rather than by file extension.
///
/// The extension approach is what let the pgadmin4 payload through
/// elsewhere in this codebase — it was named `parser`, with no extension
/// at all. See the `binary_dropper` note in AEGIS-PLAN.txt §3.7.
fn executable_kind(head: &[u8]) -> Option<&'static str> {
    const MACHO: [[u8; 4]; 5] = [
        [0xfe, 0xed, 0xfa, 0xce],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xca, 0xfe, 0xba, 0xbe],
    ];
    if head.starts_with(b"\x7fELF") {
        return Some("ELF");
    }
    if head.starts_with(b"MZ") {
        return Some("PE/MZ");
    }
    if head.len() >= 4 && MACHO.iter().any(|m| head.starts_with(m)) {
        return Some("Mach-O");
    }
    // Deliberately NOT shebang scripts. A committed `.sh` launcher wrapper
    // is standard AUR practice — measured on 97 recently-updated packages,
    // every single binary-in-source hit was a two-line wrapper like
    // `exec /usr/bin/electron ... "$@"`. They are also human-readable, so
    // the "opaque blob with no URL to audit" rationale does not apply.
    None
}

/// `source=()` lists a file committed into the repo whose magic bytes say
/// it is executable. Fetched sources at least have a URL to audit; a blob
/// in the repo has none.
fn check_binary_in_source(text: &str, local: &[LocalFile]) -> Vec<Finding> {
    let Some(sources) = bash_array(text, "source") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, entry) in sources.iter().enumerate() {
        if !is_local_source(entry) {
            continue;
        }
        let target = entry.rsplit("::").next().unwrap_or(entry);
        let Some(f) = local.iter().find(|f| f.name == target) else {
            continue;
        };
        let Some(kind) = executable_kind(&f.head) else {
            continue;
        };
        out.push(Finding {
            severity: Severity::Critical,
            rule: "binary-in-source",
            where_: format!("PKGBUILD:source[{i}]"),
            message: "source entry is a file committed into the package repo with \
                      executable magic bytes, not a fetched artifact"
                .into(),
            evidence: format!("{} ({}, {} bytes)", f.name, kind, f.size),
        });
    }
    out
}

/// `source=()` and the integrity array disagree in length, so at least one
/// source has no checksum to verify against.
fn check_checksum_count(text: &str) -> Vec<Finding> {
    let Some(sources) = bash_array(text, "source") else {
        return Vec::new();
    };
    if sources.is_empty() {
        return Vec::new();
    }
    // makepkg expands braces, so `linux.tar.{xz,sign}` is TWO sources. We
    // do not implement brace expansion; counting entries would be wrong, so
    // say nothing rather than report a mismatch that is not there.
    if sources.iter().any(|s| s.contains('{') && s.contains(',')) {
        return Vec::new();
    }
    for algo in ["sha256sums", "sha512sums", "b2sums", "sha1sums", "md5sums"] {
        let Some(sums) = bash_array(text, algo) else {
            continue;
        };
        if sums.len() != sources.len() {
            return vec![Finding {
                severity: Severity::High,
                rule: "checksum-count-mismatch",
                where_: "PKGBUILD".into(),
                message: format!(
                    "{} sources but {} {algo} entries — at least one source has no \
                     integrity anchor",
                    sources.len(),
                    sums.len()
                ),
                evidence: sources.join(" "),
            }];
        }
    }
    Vec::new()
}

// --- git history integrity ---
//
// These work on a FIRST install, with no stored state, because they check
// the attacker-writable git history against a server-side value the
// attacker does not control (`FirstSubmitted`) or against internal
// consistency the attacker has to actively fake.
//
// They detect repository *takeover* — force-pushed or fabricated history —
// not a malicious commit pushed by a legitimate maintainer. The
// pgadmin4-server compromise trips none of them, because its history was
// never touched. Content rules cover that case; these cover a different one.
//
// Thresholds are calibrated against 35 real AUR clones: every rule below
// fires on 0 of them. See `tests::history_*`.

/// How far the oldest commit may sit after `FirstSubmitted` before the
/// history looks truncated.
const WIPE_DRIFT_DAYS: i64 = 365;
/// …and how recent that oldest commit must be for the truncation to look
/// deliberate rather than historical. The AUR3→AUR4 migration (2015) reset
/// history for many old packages while `FirstSubmitted` kept the original
/// date; 11 of the 35 sampled clones look "truncated" for that reason
/// alone. Requiring the oldest commit to be recent excludes all of them.
const WIPE_RECENT_DAYS: i64 = 730;

const DAY: i64 = 86_400;
/// How far out of order commit dates must be before it looks deliberate.
const NONMONOTONIC_MIN_SECS: i64 = DAY;

fn check_history(pkg: &Package) -> Vec<Finding> {
    let Some(h) = &pkg.history else {
        return Vec::new();
    };
    let mut out = Vec::new();

    // Walking `git log` order is walking backwards in time, so the
    // timestamps must be non-increasing. A commit that is newer than the
    // one after it means the dates were rewritten or forged.
    // Small inversions are ordinary git: a rebase, a cherry-pick, or clock
    // skew between contributors leaves author dates a few minutes out of
    // order. Two of 97 sampled packages invert by 168s and 974s. Only a
    // large inversion suggests the dates were actually rewritten.
    if let Some(i) = (0..h.commit_dates.len().saturating_sub(1))
        .find(|&i| h.commit_dates[i + 1] - h.commit_dates[i] > NONMONOTONIC_MIN_SECS)
    {
        out.push(Finding {
            severity: Severity::Medium,
            rule: "commit-date-nonmonotonic",
            where_: "git".into(),
            message: "commit timestamps move backwards through history — the dates were \
                      rewritten or forged"
                .into(),
            evidence: format!(
                "commit {} is dated before its own parent ({} < {})",
                i,
                h.commit_dates[i],
                h.commit_dates[i + 1]
            ),
        });
    }

    if h.root_count > 1 {
        out.push(Finding {
            severity: Severity::Medium,
            rule: "multiple-root-commits",
            where_: "git".into(),
            message: "repository has more than one root commit — two histories were \
                      spliced together"
                .into(),
            evidence: format!("{} root commits", h.root_count),
        });
    }

    // The strong one: the AUR says this package has existed since X, but
    // the git history only goes back to Y, and Y is recent. Someone
    // force-pushed over the history.
    if let (Some(first), Some(now), Some(&oldest)) =
        (pkg.first_submitted, pkg.now, h.commit_dates.last())
    {
        let drift_days = (oldest - first) / DAY;
        let oldest_age_days = (now - oldest) / DAY;
        if drift_days > WIPE_DRIFT_DAYS && oldest_age_days < WIPE_RECENT_DAYS {
            out.push(Finding {
                severity: Severity::High,
                rule: "history-recently-wiped",
                where_: "git".into(),
                message: "git history starts long after the AUR says the package was \
                          submitted, and starts recently — the history was force-pushed \
                          over. FirstSubmitted is server-side and cannot be forged by \
                          the maintainer"
                    .into(),
                evidence: format!(
                    "oldest commit is {drift_days} days after FirstSubmitted, and only \
                     {oldest_age_days} days old"
                ),
            });
        }
    }
    out
}

/// A non-text file appeared in the package repo since the previous
/// revision. Diff-aware: relies on the caller marking `added`.
fn check_local_binary_added(local: &[LocalFile]) -> Vec<Finding> {
    local
        .iter()
        .filter(|f| f.added)
        .filter_map(|f| executable_kind(&f.head).map(|k| (f, k)))
        .map(|(f, kind)| Finding {
            severity: Severity::High,
            rule: "local-binary-added",
            where_: "git".into(),
            message: "an executable file was added to the package repo since the \
                      previous revision"
                .into(),
            evidence: format!("{} ({}, {} bytes)", f.name, kind, f.size),
        })
        .collect()
}

#[cfg(test)]
mod tests;
