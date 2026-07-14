//! Language-neutral observable behaviors of a package.
//!
//! Port of `internal/domain/capability.go`. AST scanners extract
//! [`Capability`] values from source; the risk engine reasons about them
//! without knowing the source language.
//!
//! To add a new behavior:
//!  1. Add a variant here (keep declaration order — it defines sort order).
//!  2. Add detection in each per-language scanner.
//!  3. Add a weight in `risk.rs`.

/// A language-neutral observable behavior of a package.
///
/// Declaration order matches the Go `iota + 1` ordering so that
/// `String`/serialization output and set sorting stay identical across
/// the two implementations. `derive(Ord)` on a fieldless enum orders by
/// declaration order, which is exactly the Go ordinal sort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// process/subprocess execution (child_process.exec, subprocess.run, …).
    ShellSpawn,
    /// runtime code construction (eval, new Function, exec/compile).
    DynamicEval,
    /// base64 decode — obfuscation primitive; benign on its own.
    Base64Decode,
    /// outbound network (any protocol).
    NetEgress,
    /// process env access (esp. credential names).
    EnvRead,
    /// file write outside the package's own install root.
    FsWriteOutsideRoot,
    /// string literal containing a raw IPv4 in a URL (C2 shape).
    RawIpLiteral,
    /// declares an install-time script the package manager runs automatically.
    InstallHookExec,
    /// install hook body matches a download-and-execute malware pattern.
    InstallHookSuspicious,
    /// decodes-then-executes (eval(atob(...)) / Function(decode(...))).
    ObfuscatedPayload,
    /// string literal points at a paste/chat-relay/tunnel host or IDN homoglyph.
    SuspiciousUrl,
    /// package ships an executable file (.exe/.dll/.so/.dylib/.scpt/.ps1/.bat).
    BinaryDropper,
    /// name within Levenshtein distance 2 of a top-1000 package.
    TyposquatRisk,
    /// fresh publish + long gap + low downloads (maintainer-handover shape).
    MaintainerHijackRisk,
    /// a patch bump gained capabilities the previous version lacked.
    PatchVersionDrift,
    /// publisher of this version differs from publisher of the previous version.
    MaintainerChanged,
    /// published tarball contains files absent from the upstream git tag.
    TarballDrift,
    /// optionalDependency pinned to a git URL/commit SHA (worm vector).
    GitDepInOptionalDep,
    /// tarball contains a >=512 KB code file not in the `files` allowlist.
    UnlistedLargeFile,
    /// version was published then yanked (installed during an incident window).
    VersionUnpublished,
    /// tarball contains a confirmed-malware filename IOC.
    KnownMalwareIoc,
    /// manifest pins a dependency to a VCS URL (bypasses registry immutability).
    VcsDependency,
    /// source contains a hardcoded credential (AWS/GitHub/PEM/Stripe/…).
    HardcodedSecret,
}

impl Capability {
    /// Canonical name. Stable across versions — used for serialization,
    /// logs, presenter output. Mirrors `Capability.String()`.
    pub fn name(self) -> &'static str {
        use Capability::*;
        match self {
            ShellSpawn => "shell-spawn",
            DynamicEval => "dynamic-eval",
            Base64Decode => "base64-decode",
            NetEgress => "net-egress",
            EnvRead => "env-read",
            FsWriteOutsideRoot => "fs-write-outside-root",
            RawIpLiteral => "raw-ip-literal",
            InstallHookExec => "install-hook-exec",
            InstallHookSuspicious => "install-hook-suspicious",
            ObfuscatedPayload => "obfuscated-payload",
            SuspiciousUrl => "suspicious-url",
            BinaryDropper => "binary-dropper",
            TyposquatRisk => "typosquat-risk",
            MaintainerHijackRisk => "maintainer-hijack-risk",
            PatchVersionDrift => "patch-version-drift",
            // note: TarballDrift serializes as "tarball-source-drift",
            // matching the Go String() exactly (not the variant name).
            TarballDrift => "tarball-source-drift",
            MaintainerChanged => "maintainer-changed",
            GitDepInOptionalDep => "git-dep-in-optional",
            UnlistedLargeFile => "unlisted-large-file",
            VersionUnpublished => "version-unpublished",
            KnownMalwareIoc => "known-malware-ioc",
            VcsDependency => "vcs-dependency",
            HardcodedSecret => "hardcoded-secret",
        }
    }

    /// One-line human-readable explanation (<=80 chars), used by
    /// `aegis explain`. Mirrors `Capability.Description()`.
    pub fn description(self) -> &'static str {
        use Capability::*;
        match self {
            ShellSpawn => "spawns subprocesses (e.g. child_process.exec, subprocess.run, system())",
            DynamicEval => "constructs and executes code at runtime (eval, new Function, exec)",
            Base64Decode => "decodes base64 — common obfuscation step when paired with eval/spawn",
            NetEgress => "makes outbound network connections (http, fetch, sockets)",
            EnvRead => "reads process environment variables (often secrets / credentials)",
            FsWriteOutsideRoot => "writes files outside its own install dir (touches user config / system)",
            RawIpLiteral => "contains a hard-coded IP literal (legitimate code uses hostnames)",
            InstallHookExec => "declares an install-time script the package manager runs automatically",
            InstallHookSuspicious => "install hook downloads-and-executes (curl|sh / wget|bash / node -e / base64|sh)",
            ObfuscatedPayload => "decodes-then-executes (eval(atob(...)) / Function(decode(...))) — packed-malware idiom",
            SuspiciousUrl => "string literal points at a paste / chat-relay / tunnel host or IDN homoglyph",
            BinaryDropper => "package ships an executable file (.exe/.dll/.so/.scpt) — unusual for a JS dep",
            TyposquatRisk => "name is within edit distance 2 of a top-1000 package — possible typosquat",
            MaintainerHijackRisk => "fresh publish + long gap from previous version + low downloads — classic maintainer-handover pattern",
            PatchVersionDrift => "this patch version gained capabilities the previous one didn't — semver violation",
            TarballDrift => "published tarball contains source files not present in the upstream git tag (payload smuggled past github review)",
            MaintainerChanged => "publisher of this version differs from publisher of previous version (maintainer-handover compromise shape)",
            GitDepInOptionalDep => "optionalDependency resolves to a git SHA commit — worm-propagation injection vector (Mini Shai-Hulud shape)",
            UnlistedLargeFile => "tarball contains a ≥512 KB code file not in package.json files field — smuggled payload shape",
            VersionUnpublished => "version was published then yanked — lockfile pins a package from an active incident window",
            KnownMalwareIoc => "tarball contains a confirmed-malware filename IOC (router_init.js / router_runtime.js / tanstack_runner.js)",
            VcsDependency => "manifest pins a dep to a git/VCS URL — bypasses registry immutability; invisible to security scans",
            HardcodedSecret => "source contains a hardcoded credential (AWS key, GitHub token, PEM private key, Stripe key, etc.)",
        }
    }
}

/// Every defined capability in declaration order. Mirrors `AllCapabilities()`.
pub const ALL_CAPABILITIES: [Capability; 23] = [
    Capability::ShellSpawn,
    Capability::DynamicEval,
    Capability::Base64Decode,
    Capability::NetEgress,
    Capability::EnvRead,
    Capability::FsWriteOutsideRoot,
    Capability::RawIpLiteral,
    Capability::InstallHookExec,
    Capability::InstallHookSuspicious,
    Capability::ObfuscatedPayload,
    Capability::SuspiciousUrl,
    Capability::BinaryDropper,
    Capability::TyposquatRisk,
    Capability::MaintainerHijackRisk,
    Capability::PatchVersionDrift,
    Capability::TarballDrift,
    Capability::MaintainerChanged,
    Capability::GitDepInOptionalDep,
    Capability::UnlistedLargeFile,
    Capability::VersionUnpublished,
    Capability::KnownMalwareIoc,
    Capability::VcsDependency,
    Capability::HardcodedSecret,
];

/// An ordered, deduplicated set of capabilities. Value type — clone
/// freely, no aliasing surprises. Mirrors `CapabilitySet`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilitySet(Vec<Capability>);

impl CapabilitySet {
    /// Build a deduped, sorted set from the input. Mirrors `NewCapabilitySet`.
    pub fn new(caps: impl IntoIterator<Item = Capability>) -> Self {
        let mut out: Vec<Capability> = Vec::new();
        for c in caps {
            if !out.contains(&c) {
                out.push(c);
            }
        }
        out.sort();
        CapabilitySet(out)
    }

    /// Reports whether `c` is in the set.
    pub fn has(&self, c: Capability) -> bool {
        self.0.contains(&c)
    }

    /// Number of capabilities in the set.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when the set holds no capabilities.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate in sorted order.
    pub fn iter(&self) -> std::slice::Iter<'_, Capability> {
        self.0.iter()
    }

    /// `self ∪ other` as a new set.
    pub fn union(&self, other: &CapabilitySet) -> CapabilitySet {
        if self.0.is_empty() {
            return other.clone();
        }
        if other.0.is_empty() {
            return self.clone();
        }
        CapabilitySet::new(self.0.iter().chain(other.0.iter()).copied())
    }

    /// `self − other` (capabilities in self but not other), preserving
    /// self's sort order. Mirrors `Difference`.
    pub fn difference(&self, other: &CapabilitySet) -> CapabilitySet {
        if self.0.is_empty() {
            return CapabilitySet::default();
        }
        if other.0.is_empty() {
            return self.clone();
        }
        CapabilitySet(self.0.iter().copied().filter(|c| !other.has(*c)).collect())
    }
}

impl<'a> IntoIterator for &'a CapabilitySet {
    type Item = &'a Capability;
    type IntoIter = std::slice::Iter<'a, Capability>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}
