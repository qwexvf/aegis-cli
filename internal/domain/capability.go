package domain

import "slices"

// Capability is a language-neutral observable behavior of a package.
// AST scanners (per-ecosystem) extract Capabilities from source; the
// risk engine reasons about them without knowing the source language.
//
// To add a new behavior:
//  1. Add a constant here.
//  2. Add detection in each per-language scanner under
//     internal/infra/astscan/<lang>/.
//  3. Add a weight to the risk engine in domain/risk.go.
//
// Order matters only for stable sort/serialization output; risk
// scoring uses set membership.
type Capability int

const (
	// CapShellSpawn — process/subprocess execution. Maps to:
	//   JS:     child_process.exec/execSync/spawn/fork
	//   Python: subprocess.{call,run,Popen}, os.system, os.popen
	//   Ruby:   Kernel#system, %x``, IO.popen, Process.spawn
	//   Rust:   std::process::Command
	CapShellSpawn Capability = iota + 1

	// CapDynamicEval — runtime code construction.
	//   JS:     eval, new Function, vm.runIn*
	//   Python: eval, exec, compile
	//   Ruby:   eval, instance_eval, class_eval, send
	CapDynamicEval

	// CapBase64Decode — common obfuscation primitive when paired with
	// dynamic eval or shell spawn. Benign on its own.
	//   JS:     atob, Buffer.from(_, 'base64')
	//   Python: base64.b64decode
	//   Ruby:   Base64.decode64
	CapBase64Decode

	// CapNetEgress — outbound network (any protocol).
	//   JS:     net.connect, http(s).request, fetch, dgram
	//   Python: urllib, requests, socket, http.client
	//   Ruby:   Net::HTTP, TCPSocket, open-uri
	CapNetEgress

	// CapEnvRead — process env access (esp. credential names).
	//   JS:     process.env.<X>
	//   Python: os.environ[<X>]
	//   Ruby:   ENV[<X>]
	CapEnvRead

	// CapFSWriteOutsideRoot — file write outside the package's own
	// install root. Benign for tools that write to ~/.config; risky
	// during install hooks.
	//   JS:     fs.writeFile/writeFileSync/createWriteStream/appendFile
	//   Python: open(..., 'w'/'a'), os.write
	//   Ruby:   File.write, File.open(..., 'w')
	CapFSWriteOutsideRoot

	// CapRawIPLiteral — string literal containing a raw IPv4 in a URL.
	// Common C2 server pattern (legitimate code uses hostnames).
	CapRawIPLiteral

	// CapInstallHookExec — declares an install-time script that the
	// package manager will run automatically. This is metadata, not
	// AST-derived; included as a Capability so risk scoring treats it
	// uniformly with the others.
	CapInstallHookExec

	// CapInstallHookSuspicious — install hook script body matches a
	// known malware-distribution pattern: `curl|sh`, `wget -O- | bash`,
	// `node -e`, base64 piped into shell, fetching from Pastebin etc.
	// A standalone install hook (CapInstallHookExec) is unfortunate but
	// often legitimate; this signal escalates that to "actively trying
	// to download and execute remote payload at install time".
	CapInstallHookSuspicious

	// CapObfuscatedPayload — source contains code that decodes-then-
	// executes (eval(atob(...)), Function(decodeURIComponent(...)),
	// new Function with hex string, ...). Distinct from CapBase64Decode
	// alone: this fires only when a decode result is fed into eval /
	// Function / require.
	CapObfuscatedPayload

	// CapSuspiciousURL — string literal contains a URL that points at
	// a known C2 / paste / chat-relay host (Pastebin, Discord webhook,
	// Telegram bot, ngrok tunnel, transfer.sh, ...) OR an IDN
	// homoglyph of a famous domain. Distinct from CapRawIPLiteral.
	CapSuspiciousURL

	// CapBinaryDropper — package ships an executable file
	// (.exe / .dll / .so / .dylib / .scpt / .ps1 / .bat) of a kind
	// that's not appropriate for an npm package's declared role.
	CapBinaryDropper

	// CapTyposquatRisk — package name is within Levenshtein distance
	// 2 of a top-1000 npm package. Catches `electron-stable` /
	// `lodahs` / `expresss` style attacks before any advisory is filed.
	CapTyposquatRisk

	// CapMaintainerHijackRisk — registry-side metadata combination
	// matches the canonical maintainer-handover-then-malware shape:
	// the version is freshly published (< 7 days), with a long gap
	// (≥ 180 days) since the previous publish, on a low-traffic
	// package (< 1000 weekly downloads). event-stream, ua-parser-js,
	// coa, rc all matched at least two of the three at compromise time.
	CapMaintainerHijackRisk

	// CapPatchVersionDrift — within a single patch-version bump
	// (x.y.z → x.y.z+1), this version GAINED capabilities the
	// previous one didn't have. SemVer says patch bumps are
	// behaviourally identical to the prior version; gaining
	// `child-process` or `net-egress` in a patch is a strong
	// "something changed that wasn't supposed to" signal.
	// Computed during snapshot diff against a baseline.
	CapPatchVersionDrift

	// CapMaintainerChanged — the npm user who published THIS version
	// is different from the user who published the previous version.
	// This is the canonical maintainer-handover compromise shape:
	// event-stream@3.3.6 was published by `right9ctrl` after the
	// original maintainer `dominictarr` handed off the package.
	// Distinct from CapMaintainerHijackRisk (which scores the
	// SHAPE — long gap + low downloads + fresh publish); this fires
	// on a concrete OWNERSHIP CHANGE between consecutive releases.
	CapMaintainerChanged

	// CapTarballDrift — the published npm tarball contains source
	// files that don't exist in the upstream git tag for the same
	// version, and aren't covered by the standard build-output
	// whitelist (dist/, lib/, build/, cjs/, mjs/, esm/, out/, umd/,
	// or anything listed in package.json `files`). This is the canonical
	// shape of "extra payload smuggled into the npm publish that
	// reviewers of the GitHub repo will never see". Skipped silently
	// when no upstream repo is resolvable.
	CapTarballDrift

	// CapGitDepInOptionalDep — the tarball's package.json contains an
	// optionalDependency whose version spec is a git URL or commit-SHA
	// pin (e.g. "github:org/repo#40hexsha"). No legitimate published
	// package ships git-SHA deps in optionalDependencies — this is the
	// canonical worm-propagation injection vector used in the 2026
	// Mini Shai-Hulud / TanStack attack. Catches both original packages
	// and any downstream package infected by the worm's updateTarball()
	// routine.
	CapGitDepInOptionalDep

	// CapUnlistedLargeFile — the tarball contains a code file (≥512 KB)
	// that is not declared in the package.json "files" allowlist and is
	// not under a standard build-output directory (dist/, lib/, etc.).
	// Canonical shape: router_init.js (2.3 MB obfuscated worm) smuggled
	// into 84 @tanstack/* packages without appearing in the repo or the
	// files field. Detects without requiring GitHub tree access.
	CapUnlistedLargeFile

	// CapVersionUnpublished — this version appears in the npm registry's
	// time map (i.e. was published) but is absent from the versions map
	// (i.e. was subsequently yanked). npm unpublishes under its security
	// policy; a lockfile pinning a yanked version means the package was
	// installed during an active incident window. Treat as block-tier.
	CapVersionUnpublished

	// CapKnownMalwareIOC — the tarball contains a file whose name is on
	// the confirmed-malware IOC list (router_init.js, router_runtime.js,
	// tanstack_runner.js). These filenames were confirmed malware in the
	// 2026 Mini Shai-Hulud campaign. Block immediately; no allowlist
	// exception is reasonable.
	CapKnownMalwareIOC

	// CapVCSDependency — the package manifest pins a dependency to a VCS
	// URL (git+https://, :git =>, git = "...") rather than a registry
	// version. Applies across ecosystems: PyPI (requirements.txt /
	// pyproject.toml), Cargo (Cargo.toml [dependencies]), RubyGems
	// (Gemfile). VCS deps bypass the registry's immutability guarantee:
	// the referenced commit can be force-pushed or the repo deleted,
	// making the exact installed code unpredictable and invisible to
	// registry security scans. In a *published* package this is highly
	// anomalous; in most ecosystems it is an outright anti-pattern.
	CapVCSDependency

	// CapHardcodedSecret — the package source contains what appears to be
	// a hardcoded credential: AWS access key, GitHub token, npm token,
	// PEM private key, Stripe key, SendGrid API key, Twilio auth ID.
	// Any of these in a published dep is immediately suspicious — package
	// code should never embed real credentials. Weight is high enough to
	// push to Block by itself; pair with allowlist for known false-positive
	// packages that embed test/example tokens.
	CapHardcodedSecret
)

// String returns the canonical name. Used for serialization, logs,
// presenter output. Stable across versions.
func (c Capability) String() string {
	switch c {
	case CapShellSpawn:
		return "shell-spawn"
	case CapDynamicEval:
		return "dynamic-eval"
	case CapBase64Decode:
		return "base64-decode"
	case CapNetEgress:
		return "net-egress"
	case CapEnvRead:
		return "env-read"
	case CapFSWriteOutsideRoot:
		return "fs-write-outside-root"
	case CapRawIPLiteral:
		return "raw-ip-literal"
	case CapInstallHookExec:
		return "install-hook-exec"
	case CapInstallHookSuspicious:
		return "install-hook-suspicious"
	case CapObfuscatedPayload:
		return "obfuscated-payload"
	case CapSuspiciousURL:
		return "suspicious-url"
	case CapBinaryDropper:
		return "binary-dropper"
	case CapTyposquatRisk:
		return "typosquat-risk"
	case CapMaintainerHijackRisk:
		return "maintainer-hijack-risk"
	case CapPatchVersionDrift:
		return "patch-version-drift"
	case CapTarballDrift:
		return "tarball-source-drift"
	case CapMaintainerChanged:
		return "maintainer-changed"
	case CapGitDepInOptionalDep:
		return "git-dep-in-optional"
	case CapUnlistedLargeFile:
		return "unlisted-large-file"
	case CapVersionUnpublished:
		return "version-unpublished"
	case CapKnownMalwareIOC:
		return "known-malware-ioc"
	case CapVCSDependency:
		return "vcs-dependency"
	case CapHardcodedSecret:
		return "hardcoded-secret"
	}
	return "unknown"
}

// Description returns a one-line human-readable explanation of what
// this capability means and why it's risky. Used by `aegis explain`
// to teach non-security users what the gate is flagging without them
// having to read source comments. Keep these short (≤ 80 chars).
func (c Capability) Description() string {
	switch c {
	case CapShellSpawn:
		return "spawns subprocesses (e.g. child_process.exec, subprocess.run, system())"
	case CapDynamicEval:
		return "constructs and executes code at runtime (eval, new Function, exec)"
	case CapBase64Decode:
		return "decodes base64 — common obfuscation step when paired with eval/spawn"
	case CapNetEgress:
		return "makes outbound network connections (http, fetch, sockets)"
	case CapEnvRead:
		return "reads process environment variables (often secrets / credentials)"
	case CapFSWriteOutsideRoot:
		return "writes files outside its own install dir (touches user config / system)"
	case CapRawIPLiteral:
		return "contains a hard-coded IP literal (legitimate code uses hostnames)"
	case CapInstallHookExec:
		return "declares an install-time script the package manager runs automatically"
	case CapInstallHookSuspicious:
		return "install hook downloads-and-executes (curl|sh / wget|bash / node -e / base64|sh)"
	case CapObfuscatedPayload:
		return "decodes-then-executes (eval(atob(...)) / Function(decode(...))) — packed-malware idiom"
	case CapSuspiciousURL:
		return "string literal points at a paste / chat-relay / tunnel host or IDN homoglyph"
	case CapBinaryDropper:
		return "package ships an executable file (.exe/.dll/.so/.scpt) — unusual for a JS dep"
	case CapTyposquatRisk:
		return "name is within edit distance 2 of a top-1000 package — possible typosquat"
	case CapMaintainerHijackRisk:
		return "fresh publish + long gap from previous version + low downloads — classic maintainer-handover pattern"
	case CapPatchVersionDrift:
		return "this patch version gained capabilities the previous one didn't — semver violation"
	case CapTarballDrift:
		return "published tarball contains source files not present in the upstream git tag (payload smuggled past github review)"
	case CapMaintainerChanged:
		return "publisher of this version differs from publisher of previous version (maintainer-handover compromise shape)"
	case CapGitDepInOptionalDep:
		return "optionalDependency resolves to a git SHA commit — worm-propagation injection vector (Mini Shai-Hulud shape)"
	case CapUnlistedLargeFile:
		return "tarball contains a ≥512 KB code file not in package.json files field — smuggled payload shape"
	case CapVersionUnpublished:
		return "version was published then yanked — lockfile pins a package from an active incident window"
	case CapKnownMalwareIOC:
		return "tarball contains a confirmed-malware filename IOC (router_init.js / router_runtime.js / tanstack_runner.js)"
	case CapVCSDependency:
		return "manifest pins a dep to a git/VCS URL — bypasses registry immutability; invisible to security scans"
	case CapHardcodedSecret:
		return "source contains a hardcoded credential (AWS key, GitHub token, PEM private key, Stripe key, etc.)"
	}
	return "no description available"
}

// AllCapabilities returns every defined Capability in declaration
// order. Useful for serialization and exhaustive iteration.
func AllCapabilities() []Capability {
	return []Capability{
		CapShellSpawn,
		CapDynamicEval,
		CapBase64Decode,
		CapNetEgress,
		CapEnvRead,
		CapFSWriteOutsideRoot,
		CapRawIPLiteral,
		CapInstallHookExec,
		CapInstallHookSuspicious,
		CapObfuscatedPayload,
		CapSuspiciousURL,
		CapBinaryDropper,
		CapTyposquatRisk,
		CapMaintainerHijackRisk,
		CapPatchVersionDrift,
		CapTarballDrift,
		CapMaintainerChanged,
		CapGitDepInOptionalDep,
		CapUnlistedLargeFile,
		CapVersionUnpublished,
		CapKnownMalwareIOC,
		CapVCSDependency,
		CapHardcodedSecret,
	}
}

// CapabilitySet is an ordered, deduplicated set of Capabilities.
// Treated as a value type — copy by value, no aliasing surprises.
type CapabilitySet []Capability

// NewCapabilitySet builds a deduped, sorted set from the input.
func NewCapabilitySet(caps ...Capability) CapabilitySet {
	if len(caps) == 0 {
		return nil
	}
	seen := make(map[Capability]struct{}, len(caps))
	out := make(CapabilitySet, 0, len(caps))
	for _, c := range caps {
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	slices.Sort(out)
	return out
}

// Has reports whether c is in the set.
func (s CapabilitySet) Has(c Capability) bool {
	return slices.Contains(s, c)
}

// Union returns s ∪ other as a new set.
func (s CapabilitySet) Union(other CapabilitySet) CapabilitySet {
	if len(s) == 0 {
		return append(CapabilitySet(nil), other...)
	}
	if len(other) == 0 {
		return append(CapabilitySet(nil), s...)
	}
	combined := make([]Capability, 0, len(s)+len(other))
	combined = append(combined, s...)
	combined = append(combined, other...)
	return NewCapabilitySet(combined...)
}

// Difference returns s − other (capabilities in s but not in other).
// Result preserves sort order of s.
func (s CapabilitySet) Difference(other CapabilitySet) CapabilitySet {
	if len(s) == 0 {
		return nil
	}
	if len(other) == 0 {
		return append(CapabilitySet(nil), s...)
	}
	out := make(CapabilitySet, 0, len(s))
	for _, c := range s {
		if !other.Has(c) {
			out = append(out, c)
		}
	}
	return out
}
