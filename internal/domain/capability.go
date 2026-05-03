package domain

import "sort"

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
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Has reports whether c is in the set.
func (s CapabilitySet) Has(c Capability) bool {
	for _, x := range s {
		if x == c {
			return true
		}
	}
	return false
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
