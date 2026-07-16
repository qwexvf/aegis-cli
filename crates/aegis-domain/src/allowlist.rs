//! Capability allowlist. Port of `internal/domain/allowlist.go`.
//!
//! A rule declares an `(ecosystem, name, version-range, capability)` tuple
//! whose contribution to risk scoring should be suppressed — packages whose
//! flagged behavior is part of their legitimate purpose (lodash compiling
//! templates via `Function()`, axios making HTTP calls, sharp running an
//! install hook, …).
//!
//! A rule matches a lookup when every populated field agrees:
//!  - **ecosystem** must be equal;
//!  - **name** must be equal, or `"*"` to match any package in the ecosystem;
//!  - **version** must satisfy the semver `version_range` — an empty range or
//!    `"*"` matches any version, and a constrained rule never matches an empty
//!    version input (nothing to check against);
//!  - **capability** must be equal, or `None` to suppress any capability for
//!    the matched package.
//!
//! Exact-name rules are indexed by `(ecosystem, name)` and probed first, so
//! the specific case wins over a `"*"` wildcard regardless of input order.
//!
//! The Go original leans on `Masterminds/semver` for range parsing; this crate
//! is deliberately dependency-free, so a small semver engine (caret, tilde,
//! comparison operators, x-ranges, `||`/comma composition) lives at the bottom
//! of this file. Pre-release-vs-range gating is simplified to plain ordering —
//! the risk engine only ever checks concrete release versions.

use std::cmp::Ordering;
use std::collections::HashMap;

use crate::{Capability, Ecosystem};

/// One `(ecosystem, name, version-range, capability)` tuple whose risk-flag
/// contribution should be suppressed. Rules come from three layers (builtin,
/// user, project) merged into a single [`AllowSet`] at the composition root.
///
/// Wildcards:
///  - `name == "*"` matches any package in the ecosystem;
///  - `version_range` empty or `"*"` matches any version;
///  - `capability == None` matches any capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowRule {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version_range: String,
    /// `None` suppresses any capability for the matched package (Go's
    /// `Capability == 0` sentinel).
    pub capability: Option<Capability>,
    pub reason: String,
    /// Which layer the rule came from ("builtin" | "user" | "project").
    pub source: String,
}

/// Index key for exact-name rules. Version/capability are intentionally left
/// out — rules that share `(ecosystem, name)` land in the same bucket and are
/// walked linearly (typically a 1-3 element list).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AllowKey {
    ecosystem: Ecosystem,
    name: String,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    rule: AllowRule,
    /// `None` when the rule matches any version.
    version: Option<Constraints>,
}

/// An immutable, pre-compiled rule list. Build with [`AllowSet::new`] (which
/// validates and pre-parses semver constraints) or [`AllowSet::empty`].
///
/// Rules are partitioned into an `index` keyed by `(ecosystem, name)` for
/// exact-name lookups and a `wildcards` list for `name == "*"` rules.
/// `compiled` preserves input order for [`AllowSet::rules`] and
/// [`AllowSet::match_all`] stability.
#[derive(Debug, Clone, Default)]
pub struct AllowSet {
    compiled: Vec<CompiledRule>,
    index: HashMap<AllowKey, Vec<CompiledRule>>,
    wildcards: Vec<CompiledRule>,
}

impl AllowSet {
    /// Validate and compile a list of rules. Returns the first error
    /// encountered; if any rule is missing a name or has an invalid
    /// `version_range`, the whole set is rejected so the user discovers the
    /// typo immediately rather than silently mismatching.
    ///
    /// Note: Go also rejects a missing ecosystem, but [`Ecosystem`] is a
    /// closed enum here and can never be absent, so that check is unnecessary.
    pub fn new(rules: Vec<AllowRule>) -> Result<AllowSet, String> {
        let mut out = AllowSet {
            compiled: Vec::with_capacity(rules.len()),
            index: HashMap::new(),
            wildcards: Vec::new(),
        };
        for (i, r) in rules.into_iter().enumerate() {
            if r.name.is_empty() {
                return Err(format!(
                    "allowlist rule {i}: name is required (use \"*\" for any)"
                ));
            }
            let version = if r.version_range.is_empty() || r.version_range == "*" {
                None
            } else {
                match parse_constraints(&r.version_range) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        return Err(format!(
                            "allowlist rule {i} ({}/{}): invalid version range {:?}: {e}",
                            r.ecosystem.as_str(),
                            r.name,
                            r.version_range,
                        ));
                    }
                }
            };
            let is_wild = r.name == "*";
            let key_name = r.name.clone();
            let eco = r.ecosystem;
            let c = CompiledRule { rule: r, version };
            if is_wild {
                out.wildcards.push(c.clone());
            } else {
                out.index
                    .entry(AllowKey {
                        ecosystem: eco,
                        name: key_name,
                    })
                    .or_default()
                    .push(c.clone());
            }
            out.compiled.push(c);
        }
        Ok(out)
    }

    /// A usable zero-rule set. Helpful when callers can't (or don't want to)
    /// supply rules.
    pub fn empty() -> AllowSet {
        AllowSet::default()
    }

    /// The rule list (decompiled), preserving input order.
    pub fn rules(&self) -> Vec<AllowRule> {
        self.compiled.iter().map(|c| c.rule.clone()).collect()
    }

    /// Number of rules.
    pub fn len(&self) -> usize {
        self.compiled.len()
    }

    /// True when the set holds no rules.
    pub fn is_empty(&self) -> bool {
        self.compiled.is_empty()
    }

    /// Reports whether any rule matches `(eco, name, version, c)`, returning
    /// the matched rule (so callers can show its reason) or `None`.
    ///
    /// Match order: exact-name rules (index lookup) first, then wildcard-name
    /// rules — the specific case wins early and avoids a full scan. `version`
    /// may be empty; a rule with a non-wildcard range then won't match.
    pub fn suppresses(
        &self,
        eco: Ecosystem,
        name: &str,
        version: &str,
        c: Capability,
    ) -> Option<&AllowRule> {
        if self.compiled.is_empty() {
            return None;
        }
        if let Some(rules) = self.index.get(&AllowKey {
            ecosystem: eco,
            name: name.to_string(),
        }) {
            for cr in rules {
                if rule_matches(cr, eco, name, version, c) {
                    return Some(&cr.rule);
                }
            }
        }
        for cr in &self.wildcards {
            if rule_matches(cr, eco, name, version, c) {
                return Some(&cr.rule);
            }
        }
        None
    }

    /// Every rule whose `(ecosystem, name, version)` matches the tuple,
    /// regardless of capability. Exact-name rules first (in input order), then
    /// wildcard-name rules — "more specific first", as the user expects.
    pub fn match_all(&self, eco: Ecosystem, name: &str, version: &str) -> Vec<Match> {
        let mut out = Vec::new();
        if self.compiled.is_empty() {
            return out;
        }
        if let Some(rules) = self.index.get(&AllowKey {
            ecosystem: eco,
            name: name.to_string(),
        }) {
            for cr in rules {
                if rule_matches_ignoring_capability(cr, eco, name, version) {
                    out.push(make_match(cr));
                }
            }
        }
        for cr in &self.wildcards {
            if rule_matches_ignoring_capability(cr, eco, name, version) {
                out.push(make_match(cr));
            }
        }
        out
    }
}

/// Distinguishes a rule targeting a specific [`Capability`] from one that
/// suppresses any capability (Go's `Capability == 0`). The presenter prints a
/// single "matches any capability" line for [`MatchKind::Any`] instead of one
/// line per capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    /// The rule targets exactly one capability.
    Specific,
    /// The rule suppresses any capability for the matched tuple.
    Any,
}

/// One rule's relevance to a `(eco, name, version)` tuple, returned by
/// [`AllowSet::match_all`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub kind: MatchKind,
    /// `None` when `kind == MatchKind::Any`.
    pub capability: Option<Capability>,
    pub rule: AllowRule,
}

fn make_match(cr: &CompiledRule) -> Match {
    match cr.rule.capability {
        Some(c) => Match {
            kind: MatchKind::Specific,
            capability: Some(c),
            rule: cr.rule.clone(),
        },
        None => Match {
            kind: MatchKind::Any,
            capability: None,
            rule: cr.rule.clone(),
        },
    }
}

fn rule_matches(
    cr: &CompiledRule,
    eco: Ecosystem,
    name: &str,
    version: &str,
    c: Capability,
) -> bool {
    if !rule_matches_ignoring_capability(cr, eco, name, version) {
        return false;
    }
    // A specific-capability rule only matches its capability; a `None` rule
    // matches anything.
    !matches!(cr.rule.capability, Some(rc) if rc != c)
}

/// Checks ecosystem, name, and version constraints. The capability check is
/// layered on top in [`rule_matches`].
fn rule_matches_ignoring_capability(
    cr: &CompiledRule,
    eco: Ecosystem,
    name: &str,
    version: &str,
) -> bool {
    let r = &cr.rule;
    if r.ecosystem != eco {
        return false;
    }
    if r.name != "*" && r.name != name {
        return false;
    }
    if let Some(constraints) = &cr.version {
        if version.is_empty() {
            return false;
        }
        match Version::parse(version) {
            Some(v) => constraints.matches(&v),
            None => false,
        }
    } else {
        true
    }
}

/// The curated default allowlist that ships with the binary. Entries are
/// well-known packages whose flagged capabilities are part of their legitimate
/// behavior. Port of `BuiltinAllowRules`.
///
/// Adding a rule here is an explicit assertion that the package legitimately
/// needs the capability — every entry weakens the gate, so curate carefully.
pub fn builtin_allow_rules() -> Vec<AllowRule> {
    let rule = |name: &str, cap: Capability, reason: &str| AllowRule {
        ecosystem: Ecosystem::Npm,
        name: name.to_string(),
        version_range: String::new(),
        capability: Some(cap),
        reason: reason.to_string(),
        source: "builtin".to_string(),
    };
    use Capability::*;
    vec![
        // Template compilers — every one uses the Function() constructor for
        // runtime template compilation, which dynamic-eval detection picks up.
        rule(
            "lodash",
            DynamicEval,
            "lodash._.template compiles templates via Function()",
        ),
        rule(
            "underscore",
            DynamicEval,
            "underscore.template uses Function() for template compilation",
        ),
        rule(
            "handlebars",
            DynamicEval,
            "handlebars compiles templates via Function()",
        ),
        rule(
            "ejs",
            DynamicEval,
            "ejs uses Function() for template compilation",
        ),
        // Build tools — legitimately spawn worker processes / native binaries.
        rule(
            "webpack",
            ShellSpawn,
            "webpack spawns worker processes and loaders",
        ),
        rule(
            "@babel/core",
            ShellSpawn,
            "babel spawns worker processes for parallel transforms",
        ),
        rule(
            "esbuild",
            ShellSpawn,
            "esbuild spawns its native Go binary as a child process",
        ),
        rule(
            "rollup",
            ShellSpawn,
            "rollup uses workers for parallel bundling",
        ),
        rule("vite", ShellSpawn, "vite spawns dev-server child processes"),
        rule("parcel", ShellSpawn, "parcel uses worker processes"),
        rule(
            "nodemon",
            ShellSpawn,
            "nodemon spawns the user's node process",
        ),
        // HTTP clients — net-egress is literally the package's purpose.
        rule(
            "node-fetch",
            NetEgress,
            "package's stated purpose is HTTP fetch",
        ),
        rule("axios", NetEgress, "package's stated purpose is HTTP"),
        rule("got", NetEgress, "package's stated purpose is HTTP"),
        rule(
            "undici",
            NetEgress,
            "package's stated purpose is HTTP (Node's reference HTTP client)",
        ),
        // Native-build packages — declare an install hook to compile or
        // download platform-specific binaries.
        rule(
            "fsevents",
            InstallHookExec,
            "macOS native fs watcher compiled at install time",
        ),
        rule(
            "node-sass",
            InstallHookExec,
            "compiles libsass binary at install time",
        ),
        rule(
            "sharp",
            InstallHookExec,
            "downloads libvips binary at install time",
        ),
        rule(
            "better-sqlite3",
            InstallHookExec,
            "compiles native sqlite3 at install time",
        ),
        rule(
            "bcrypt",
            InstallHookExec,
            "compiles native bcrypt at install time",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Minimal semver engine (stands in for Masterminds/semver).
// ---------------------------------------------------------------------------

/// A pre-release identifier: numeric or alphanumeric, ordered per semver §11.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PreId {
    Num(u64),
    Text(String),
}

impl Ord for PreId {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (PreId::Num(a), PreId::Num(b)) => a.cmp(b),
            (PreId::Text(a), PreId::Text(b)) => a.cmp(b),
            // numeric identifiers always compare lower than alphanumeric ones.
            (PreId::Num(_), PreId::Text(_)) => Ordering::Less,
            (PreId::Text(_), PreId::Num(_)) => Ordering::Greater,
        }
    }
}

impl PartialOrd for PreId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A parsed semantic version. Build metadata is discarded (ignored in
/// precedence, per semver §10).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Vec<PreId>,
}

impl Version {
    fn new(major: u64, minor: u64, patch: u64) -> Version {
        Version {
            major,
            minor,
            patch,
            pre: Vec::new(),
        }
    }

    /// Parse a concrete version string ("v1.2.3", "4.17.21", "0.0.1-rc.1").
    /// Missing minor/patch default to 0. Returns `None` on malformed input —
    /// callers treat that as "no match", never an error.
    fn parse(s: &str) -> Option<Version> {
        let (comps, pre) = parse_components(s).ok()?;
        Some(Version {
            major: comps.first().copied().flatten().unwrap_or(0),
            minor: comps.get(1).copied().flatten().unwrap_or(0),
            patch: comps.get(2).copied().flatten().unwrap_or(0),
            pre,
        })
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
            .then_with(|| cmp_pre(&self.pre, &other.pre))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Pre-release ordering: a version with a pre-release is *lower* than the same
/// core version without one; two pre-releases compare identifier-by-identifier.
fn cmp_pre(a: &[PreId], b: &[PreId]) -> Ordering {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => {
            for (x, y) in a.iter().zip(b.iter()) {
                let o = x.cmp(y);
                if o != Ordering::Equal {
                    return o;
                }
            }
            a.len().cmp(&b.len())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}

#[derive(Debug, Clone)]
struct Comparator {
    op: Op,
    ver: Version,
}

impl Comparator {
    fn matches(&self, v: &Version) -> bool {
        let ord = v.cmp(&self.ver);
        match self.op {
            Op::Eq => ord == Ordering::Equal,
            Op::Ne => ord != Ordering::Equal,
            Op::Gt => ord == Ordering::Greater,
            Op::Ge => ord != Ordering::Less,
            Op::Lt => ord == Ordering::Less,
            Op::Le => ord != Ordering::Greater,
        }
    }
}

/// A compiled version range: OR of AND-groups (`a,b || c`). A version satisfies
/// the range when it satisfies every comparator in at least one group.
#[derive(Debug, Clone)]
struct Constraints {
    or_groups: Vec<Vec<Comparator>>,
}

impl Constraints {
    fn matches(&self, v: &Version) -> bool {
        self.or_groups
            .iter()
            .any(|group| group.iter().all(|c| c.matches(v)))
    }
}

/// Parse a range string into [`Constraints`]. Supports `||` for OR, comma or
/// whitespace for AND, and per-comparator caret/tilde/comparison/x-range
/// operators. Empty and `"*"` ranges are handled by the caller (they compile
/// to `None`, not to a constraint).
fn parse_constraints(input: &str) -> Result<Constraints, String> {
    let mut or_groups = Vec::new();
    for or_part in input.split("||") {
        let normalized = or_part.replace(',', " ");
        let mut group: Vec<Comparator> = Vec::new();
        for tok in normalized.split_whitespace() {
            parse_comparator(tok, &mut group)?;
        }
        if group.is_empty() {
            // A bare `*`/`x`/whitespace group matches anything.
            group.push(Comparator {
                op: Op::Ge,
                ver: Version::new(0, 0, 0),
            });
        }
        or_groups.push(group);
    }
    if or_groups.is_empty() {
        return Err("empty version range".to_string());
    }
    Ok(Constraints { or_groups })
}

fn parse_comparator(tok: &str, out: &mut Vec<Comparator>) -> Result<(), String> {
    let (op_str, rest) = split_op(tok);
    match op_str {
        "^" => expand_caret(rest, out),
        "~" => expand_tilde(rest, out),
        "=" | "==" => {
            out.push(Comparator {
                op: Op::Eq,
                ver: parse_full(rest)?,
            });
            Ok(())
        }
        "!=" => {
            out.push(Comparator {
                op: Op::Ne,
                ver: parse_full(rest)?,
            });
            Ok(())
        }
        ">" => {
            out.push(Comparator {
                op: Op::Gt,
                ver: parse_full(rest)?,
            });
            Ok(())
        }
        ">=" => {
            out.push(Comparator {
                op: Op::Ge,
                ver: parse_full(rest)?,
            });
            Ok(())
        }
        "<" => {
            out.push(Comparator {
                op: Op::Lt,
                ver: parse_full(rest)?,
            });
            Ok(())
        }
        "<=" => {
            out.push(Comparator {
                op: Op::Le,
                ver: parse_full(rest)?,
            });
            Ok(())
        }
        // no operator: a bare version — exact when fully specified, otherwise
        // an x-range (partial / wildcard segments).
        _ => expand_bare(rest, out),
    }
}

/// Longest-prefix operator split. Returns `("", tok)` for a bare version.
fn split_op(tok: &str) -> (&str, &str) {
    for op in [">=", "<=", "!=", "=="] {
        if let Some(rest) = tok.strip_prefix(op) {
            return (op, rest);
        }
    }
    for op in [">", "<", "=", "^", "~"] {
        if let Some(rest) = tok.strip_prefix(op) {
            return (op, rest);
        }
    }
    ("", tok)
}

/// Parse a (possibly partial) version for a comparison operator, filling
/// missing/wildcard segments with 0.
fn parse_full(s: &str) -> Result<Version, String> {
    let (comps, pre) = parse_components(s)?;
    Ok(Version {
        major: comps.first().copied().flatten().unwrap_or(0),
        minor: comps.get(1).copied().flatten().unwrap_or(0),
        patch: comps.get(2).copied().flatten().unwrap_or(0),
        pre,
    })
}

/// `^`: compatible-within-leftmost-nonzero. `^1.2.3`→`>=1.2.3 <2.0.0`,
/// `^0.2.3`→`>=0.2.3 <0.3.0`, `^0.0.3`→`>=0.0.3 <0.0.4`, `^4`→`>=4.0.0 <5.0.0`.
fn expand_caret(rest: &str, out: &mut Vec<Comparator>) -> Result<(), String> {
    let (comps, pre) = parse_components(rest)?;
    let major = comps.first().copied().flatten();
    let minor = comps.get(1).copied().flatten();
    let patch = comps.get(2).copied().flatten();
    let Some(m) = major else {
        // `^*` — match anything.
        out.push(Comparator {
            op: Op::Ge,
            ver: Version::new(0, 0, 0),
        });
        return Ok(());
    };
    let n = minor.unwrap_or(0);
    let p = patch.unwrap_or(0);
    let lower = Version {
        major: m,
        minor: n,
        patch: p,
        pre,
    };
    let upper = if m > 0 {
        Version::new(m + 1, 0, 0)
    } else if n > 0 {
        Version::new(0, n + 1, 0)
    } else if p > 0 {
        Version::new(0, 0, p + 1)
    } else if minor.is_none() {
        // `^0` → <1.0.0
        Version::new(1, 0, 0)
    } else if patch.is_none() {
        // `^0.0` → <0.1.0
        Version::new(0, 1, 0)
    } else {
        // `^0.0.0` → <0.0.1
        Version::new(0, 0, 1)
    };
    out.push(Comparator {
        op: Op::Ge,
        ver: lower,
    });
    out.push(Comparator {
        op: Op::Lt,
        ver: upper,
    });
    Ok(())
}

/// `~`: allow patch (and minor when only major given). `~1.2.3`→`>=1.2.3
/// <1.3.0`, `~1.2`→`>=1.2.0 <1.3.0`, `~1`→`>=1.0.0 <2.0.0`.
fn expand_tilde(rest: &str, out: &mut Vec<Comparator>) -> Result<(), String> {
    let (comps, pre) = parse_components(rest)?;
    let major = comps.first().copied().flatten();
    let minor = comps.get(1).copied().flatten();
    let patch = comps.get(2).copied().flatten();
    let Some(m) = major else {
        out.push(Comparator {
            op: Op::Ge,
            ver: Version::new(0, 0, 0),
        });
        return Ok(());
    };
    let lower = Version {
        major: m,
        minor: minor.unwrap_or(0),
        patch: patch.unwrap_or(0),
        pre,
    };
    let upper = match minor {
        Some(n) => Version::new(m, n + 1, 0),
        None => Version::new(m + 1, 0, 0),
    };
    out.push(Comparator {
        op: Op::Ge,
        ver: lower,
    });
    out.push(Comparator {
        op: Op::Lt,
        ver: upper,
    });
    Ok(())
}

/// A bare token: exact equality when all three segments are numeric,
/// otherwise an x-range (`1`→`>=1.0.0 <2.0.0`, `1.2`→`>=1.2.0 <1.3.0`,
/// `1.x`→`>=1.0.0 <2.0.0`, `*`→any).
fn expand_bare(rest: &str, out: &mut Vec<Comparator>) -> Result<(), String> {
    let (comps, pre) = parse_components(rest)?;
    let major = comps.first().copied().flatten();
    let minor = comps.get(1).copied().flatten();
    let patch = comps.get(2).copied().flatten();
    if let (3, Some(major), Some(minor), Some(patch)) = (comps.len(), major, minor, patch) {
        out.push(Comparator {
            op: Op::Eq,
            ver: Version {
                major,
                minor,
                patch,
                pre,
            },
        });
        return Ok(());
    }
    let Some(m) = major else {
        // `*` / `x`
        out.push(Comparator {
            op: Op::Ge,
            ver: Version::new(0, 0, 0),
        });
        return Ok(());
    };
    let (lower, upper) = match minor {
        None => (Version::new(m, 0, 0), Version::new(m + 1, 0, 0)),
        Some(n) => (Version::new(m, n, 0), Version::new(m, n + 1, 0)),
    };
    out.push(Comparator {
        op: Op::Ge,
        ver: lower,
    });
    out.push(Comparator {
        op: Op::Lt,
        ver: upper,
    });
    Ok(())
}

/// Split a version core into up to three segments (`Some(n)` numeric, `None`
/// wildcard) plus its pre-release identifiers. Strips a leading `v`/`V` and any
/// `+build` metadata. Errors on non-numeric segments or the wrong shape.
type Components = (Vec<Option<u64>>, Vec<PreId>);

fn parse_components(s: &str) -> Result<Components, String> {
    let s = s.trim();
    let s = s.strip_prefix(['v', 'V']).unwrap_or(s);
    // drop +build metadata.
    let s = s.split('+').next().unwrap_or(s);
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, parse_pre(p)),
        None => (s, Vec::new()),
    };
    if core.is_empty() {
        return Err("empty version".to_string());
    }
    let mut comps = Vec::new();
    for part in core.split('.') {
        if part == "*" || part == "x" || part == "X" {
            comps.push(None);
        } else if !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()) {
            let n = part
                .parse::<u64>()
                .map_err(|_| format!("version segment out of range: {part:?}"))?;
            comps.push(Some(n));
        } else {
            return Err(format!("invalid version segment: {part:?}"));
        }
    }
    if comps.is_empty() || comps.len() > 3 {
        return Err(format!("version has {} segments (want 1-3)", comps.len()));
    }
    Ok((comps, pre))
}

fn parse_pre(p: &str) -> Vec<PreId> {
    p.split('.')
        .map(|id| {
            if !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) {
                match id.parse::<u64>() {
                    Ok(n) => PreId::Num(n),
                    Err(_) => PreId::Text(id.to_string()),
                }
            } else {
                PreId::Text(id.to_string())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Base rule with an npm ecosystem and empty fields; override with struct
    /// update syntax. ([`AllowRule`] can't derive `Default` — `Ecosystem` has
    /// no default.)
    fn base() -> AllowRule {
        AllowRule {
            ecosystem: Ecosystem::Npm,
            name: String::new(),
            version_range: String::new(),
            capability: None,
            reason: String::new(),
            source: String::new(),
        }
    }

    fn must_set(rules: Vec<AllowRule>) -> AllowSet {
        AllowSet::new(rules).expect("NewAllowSet")
    }

    #[test]
    fn rejects_missing_name() {
        let err = AllowSet::new(vec![base()]).unwrap_err();
        assert!(err.contains("name"), "got {err}");
    }

    #[test]
    fn rejects_bad_semver_constraint() {
        let err = AllowSet::new(vec![AllowRule {
            name: "lodash".into(),
            version_range: "not-a-range".into(),
            ..base()
        }])
        .unwrap_err();
        assert!(err.contains("version range"), "got {err}");
    }

    #[test]
    fn empty_set_never_matches() {
        let s = AllowSet::empty();
        assert!(s
            .suppresses(Ecosystem::Npm, "lodash", "4.17.21", Capability::DynamicEval)
            .is_none());
    }

    #[test]
    fn exact_name_matches_only_that_name() {
        let s = must_set(vec![AllowRule {
            name: "lodash".into(),
            capability: Some(Capability::DynamicEval),
            reason: "tpl".into(),
            ..base()
        }]);
        assert!(s
            .suppresses(Ecosystem::Npm, "lodash", "4.17.21", Capability::DynamicEval)
            .is_some());
        assert!(s
            .suppresses(Ecosystem::Npm, "react", "18.0.0", Capability::DynamicEval)
            .is_none());
    }

    #[test]
    fn wildcard_name_matches_any() {
        let s = must_set(vec![AllowRule {
            name: "*".into(),
            capability: Some(Capability::NetEgress),
            reason: "demo".into(),
            ..base()
        }]);
        for name in ["axios", "got", "node-fetch", "really-anything"] {
            assert!(
                s.suppresses(Ecosystem::Npm, name, "1.0.0", Capability::NetEgress)
                    .is_some(),
                "name=* should match {name}"
            );
        }
    }

    #[test]
    fn wildcard_capability_matches_any() {
        let s = must_set(vec![AllowRule {
            name: "demo".into(),
            reason: "trusted entirely".into(),
            ..base()
        }]);
        for c in [
            Capability::ShellSpawn,
            Capability::DynamicEval,
            Capability::NetEgress,
        ] {
            assert!(
                s.suppresses(Ecosystem::Npm, "demo", "1.0.0", c).is_some(),
                "capability=None should match {}",
                c.name()
            );
        }
    }

    #[test]
    fn ecosystem_must_equal() {
        let s = must_set(vec![AllowRule {
            name: "lodash".into(),
            capability: Some(Capability::DynamicEval),
            reason: "tpl".into(),
            ..base()
        }]);
        assert!(s
            .suppresses(Ecosystem::PyPI, "lodash", "1.0.0", Capability::DynamicEval)
            .is_none());
    }

    #[test]
    fn version_constraint() {
        let s = must_set(vec![AllowRule {
            name: "lodash".into(),
            version_range: "^4".into(),
            capability: Some(Capability::DynamicEval),
            reason: "tpl".into(),
            ..base()
        }]);
        assert!(s
            .suppresses(Ecosystem::Npm, "lodash", "4.17.21", Capability::DynamicEval)
            .is_some());
        assert!(s
            .suppresses(Ecosystem::Npm, "lodash", "5.0.0", Capability::DynamicEval)
            .is_none());
        assert!(s
            .suppresses(Ecosystem::Npm, "lodash", "3.10.0", Capability::DynamicEval)
            .is_none());
    }

    #[test]
    fn version_wildcard_equiv_to_empty() {
        for vr in ["", "*"] {
            let s = must_set(vec![AllowRule {
                name: "lodash".into(),
                version_range: vr.into(),
                capability: Some(Capability::DynamicEval),
                reason: "x".into(),
                ..base()
            }]);
            for ver in ["1.0.0", "4.17.21", "999.999.999", "0.0.1-rc.1"] {
                assert!(
                    s.suppresses(Ecosystem::Npm, "lodash", ver, Capability::DynamicEval)
                        .is_some(),
                    "version_range={vr:?} should match {ver}"
                );
            }
        }
    }

    #[test]
    fn empty_version_input_and_constrained_rule() {
        let s = must_set(vec![AllowRule {
            name: "lodash".into(),
            version_range: "^4".into(),
            capability: Some(Capability::DynamicEval),
            reason: "tpl".into(),
            ..base()
        }]);
        assert!(s
            .suppresses(Ecosystem::Npm, "lodash", "", Capability::DynamicEval)
            .is_none());
    }

    #[test]
    fn match_returns_rule_reason() {
        let want = AllowRule {
            name: "lodash".into(),
            capability: Some(Capability::DynamicEval),
            reason: "lodash._.template compiles via Function()".into(),
            source: "builtin".into(),
            ..base()
        };
        let s = must_set(vec![want.clone()]);
        let got = s
            .suppresses(Ecosystem::Npm, "lodash", "4.17.21", Capability::DynamicEval)
            .expect("expected match");
        assert_eq!(got.reason, want.reason);
        assert_eq!(got.source, want.source);
    }

    #[test]
    fn specific_name_wins_over_wildcard() {
        // Both match; the exact-name rule wins regardless of input order.
        let s = must_set(vec![
            AllowRule {
                name: "*".into(),
                capability: Some(Capability::DynamicEval),
                reason: "wide".into(),
                source: "user".into(),
                ..base()
            },
            AllowRule {
                name: "lodash".into(),
                capability: Some(Capability::DynamicEval),
                reason: "narrow".into(),
                source: "builtin".into(),
                ..base()
            },
        ]);
        let got = s
            .suppresses(Ecosystem::Npm, "lodash", "4.17.21", Capability::DynamicEval)
            .unwrap();
        assert_eq!(got.source, "builtin");
    }

    #[test]
    fn multiple_specific_rules_first_wins() {
        let s = must_set(vec![
            AllowRule {
                name: "lodash".into(),
                version_range: "^4".into(),
                capability: Some(Capability::DynamicEval),
                reason: "narrow".into(),
                source: "builtin".into(),
                ..base()
            },
            AllowRule {
                name: "lodash".into(),
                capability: Some(Capability::DynamicEval),
                reason: "broad".into(),
                source: "user".into(),
                ..base()
            },
        ]);
        let got = s
            .suppresses(Ecosystem::Npm, "lodash", "4.17.21", Capability::DynamicEval)
            .unwrap();
        assert_eq!(got.source, "builtin");
    }

    #[test]
    fn rules_preserves_input_order() {
        let names = ["a", "b", "c"];
        let s = must_set(
            names
                .iter()
                .map(|n| AllowRule {
                    name: (*n).into(),
                    ..base()
                })
                .collect(),
        );
        let out = s.rules();
        for (i, n) in names.iter().enumerate() {
            assert_eq!(out[i].name, *n);
        }
    }

    #[test]
    fn len_and_empty() {
        assert_eq!(AllowSet::empty().len(), 0);
        assert!(AllowSet::empty().is_empty());
        let s = must_set(vec![
            AllowRule {
                name: "a".into(),
                ..base()
            },
            AllowRule {
                name: "b".into(),
                ..base()
            },
        ]);
        assert_eq!(s.len(), 2);
        assert!(!s.is_empty());
    }

    #[test]
    fn match_all_empty() {
        assert!(AllowSet::empty()
            .match_all(Ecosystem::Npm, "lodash", "1.0.0")
            .is_empty());
    }

    #[test]
    fn match_all_no_match() {
        let s = must_set(vec![AllowRule {
            name: "react".into(),
            capability: Some(Capability::DynamicEval),
            reason: "x".into(),
            ..base()
        }]);
        assert!(s.match_all(Ecosystem::Npm, "lodash", "1.0.0").is_empty());
    }

    #[test]
    fn match_all_specific_capability() {
        let s = must_set(vec![AllowRule {
            name: "lodash".into(),
            capability: Some(Capability::DynamicEval),
            reason: "tpl".into(),
            ..base()
        }]);
        let matches = s.match_all(Ecosystem::Npm, "lodash", "1.0.0");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, MatchKind::Specific);
        assert_eq!(matches[0].capability, Some(Capability::DynamicEval));
    }

    #[test]
    fn match_all_any_capability_collapsed_to_single_entry() {
        let s = must_set(vec![AllowRule {
            name: "deploy-tool".into(),
            reason: "trusted".into(),
            ..base()
        }]);
        let matches = s.match_all(Ecosystem::Npm, "deploy-tool", "1.0.0");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, MatchKind::Any);
        assert_eq!(matches[0].capability, None);
    }

    #[test]
    fn match_all_mixes_specific_and_any() {
        let s = must_set(vec![
            AllowRule {
                name: "lodash".into(),
                capability: Some(Capability::DynamicEval),
                reason: "tpl".into(),
                ..base()
            },
            AllowRule {
                name: "*".into(),
                reason: "wildcard".into(),
                ..base()
            },
        ]);
        let matches = s.match_all(Ecosystem::Npm, "lodash", "4.17.21");
        assert_eq!(matches.len(), 2);
        // specific (lodash) first, wildcard second.
        assert_eq!(matches[0].kind, MatchKind::Specific);
        assert_eq!(matches[0].capability, Some(Capability::DynamicEval));
        assert_eq!(matches[1].kind, MatchKind::Any);
        assert_eq!(matches[1].rule.name, "*");
    }

    #[test]
    fn match_all_version_constraint_honoured() {
        let s = must_set(vec![AllowRule {
            name: "lodash".into(),
            version_range: "^4".into(),
            capability: Some(Capability::DynamicEval),
            reason: "v4".into(),
            ..base()
        }]);
        assert!(s.match_all(Ecosystem::Npm, "lodash", "5.0.0").is_empty());
    }

    #[test]
    fn builtin_rules_suppress_known_packages() {
        let s = must_set(builtin_allow_rules());
        assert!(s
            .suppresses(Ecosystem::Npm, "lodash", "4.17.21", Capability::DynamicEval)
            .is_some());
        assert!(s
            .suppresses(Ecosystem::Npm, "axios", "1.6.0", Capability::NetEgress)
            .is_some());
        assert!(s
            .suppresses(
                Ecosystem::Npm,
                "sharp",
                "0.33.0",
                Capability::InstallHookExec
            )
            .is_some());
        // wrong capability for the package → not suppressed.
        assert!(s
            .suppresses(Ecosystem::Npm, "lodash", "4.17.21", Capability::ShellSpawn)
            .is_none());
    }

    // --- semver engine ---

    #[test]
    fn tilde_and_comparison_ranges() {
        let mk = |vr: &str| {
            must_set(vec![AllowRule {
                name: "p".into(),
                version_range: vr.into(),
                ..base()
            }])
        };
        let hit = |s: &AllowSet, v: &str| {
            s.suppresses(Ecosystem::Npm, "p", v, Capability::ShellSpawn)
                .is_some()
        };

        let t = mk("~1.2.3");
        assert!(hit(&t, "1.2.9"));
        assert!(!hit(&t, "1.3.0"));
        assert!(!hit(&t, "1.2.2"));

        let ge = mk(">=2.0.0");
        assert!(hit(&ge, "2.0.0"));
        assert!(hit(&ge, "9.9.9"));
        assert!(!hit(&ge, "1.9.9"));

        let xr = mk("1.x");
        assert!(hit(&xr, "1.0.0"));
        assert!(hit(&xr, "1.99.0"));
        assert!(!hit(&xr, "2.0.0"));

        // OR of two exact versions.
        let or = mk("1.0.0 || 2.0.0");
        assert!(hit(&or, "1.0.0"));
        assert!(hit(&or, "2.0.0"));
        assert!(!hit(&or, "1.5.0"));
    }

    #[test]
    fn version_ordering_handles_prerelease() {
        assert!(Version::parse("1.2.3-rc.1") < Version::parse("1.2.3"));
        assert!(Version::parse("1.2.10") > Version::parse("1.2.9"));
        assert_eq!(Version::parse("v1.0.0"), Version::parse("1.0.0"));
        assert!(Version::parse("not-a-version").is_none());
    }
}
