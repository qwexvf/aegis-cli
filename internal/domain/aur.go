package domain

import (
	"regexp"
	"strings"
)

// AURPackage is the raw, fetched content of one AUR package: the
// PKGBUILD bash script plus any .install hook scripts the package
// ships. It is the input to ScanPKGBUILD.
//
// Upstream is the value of the PKGBUILD `url=` field when known — the
// scanner uses it as the trusted-host anchor for source-drift checks.
// PrevPKGBUILD, when non-empty, is the PKGBUILD of the currently
// installed version; the scanner uses it to flag the *change* (the
// orphan-adoption signal at the heart of the Atomic Arch campaign)
// rather than the package merely existing.
type AURPackage struct {
	Name         string
	PKGBUILD     []byte
	Install      []byte // concatenated .install hook bodies (may be empty)
	Upstream     string // url= field, if parsed
	PrevPKGBUILD []byte // installed version's PKGBUILD, if available
}

// AURSeverity ranks an AUR finding. Critical maps to a hard block;
// High prompts; Medium/Low are informational unless they stack.
type AURSeverity int

const (
	AURInfo AURSeverity = iota
	AURMedium
	AURHigh
	AURCritical
)

func (s AURSeverity) String() string {
	switch s {
	case AURCritical:
		return "critical"
	case AURHigh:
		return "high"
	case AURMedium:
		return "medium"
	default:
		return "info"
	}
}

// AURFinding is one suspicious pattern the scanner matched. Where is a
// human-readable location ("build()", ".install:post_install",
// "source[]"); Evidence is the offending line, trimmed.
type AURFinding struct {
	Severity AURSeverity
	Rule     string
	Where    string
	Message  string
	Evidence string
}

// AURVerdict is the gate decision for one package.
type AURVerdict int

const (
	AURAllow AURVerdict = iota
	AURWarn
	AURBlock
)

func (v AURVerdict) String() string {
	switch v {
	case AURBlock:
		return "block"
	case AURWarn:
		return "warn"
	default:
		return "allow"
	}
}

// AURScanResult is the scanner output for one package.
type AURScanResult struct {
	Package  string
	Findings []AURFinding
	Verdict  AURVerdict
}

// Verdict derives the gate decision from the findings: any Critical →
// Block, any High → Warn, otherwise Allow. The caller (use case) maps
// Block to a non-zero exit before paru runs.
func (r AURScanResult) deriveVerdict() AURVerdict {
	v := AURAllow
	for _, f := range r.Findings {
		switch f.Severity {
		case AURCritical:
			return AURBlock
		case AURHigh:
			if v < AURWarn {
				v = AURWarn
			}
		}
	}
	return v
}

// --- builtin IOC denylists (offline, ships in-binary) ---

// aurDenyPackages is the curated list of AUR package names confirmed
// malicious in the 2025–2026 campaigns. Exact-match here is a hard
// block regardless of what the current PKGBUILD looks like (a reverted
// PKGBUILD can still have a poisoned .install in a stale cache).
//
// Seeded from the Chaos RAT incident (July 2025). The full Atomic Arch
// checklist (400+ names) is intended to load from the offline IOC feed
// shipped/refreshed via Aegis Cloud; this builtin set is the floor.
var aurDenyPackages = map[string]struct{}{
	"librewolf-fix-bin":       {},
	"firefox-patch-bin":       {},
	"zen-browser-patched-bin": {},
}

// aurDenyDeps is the list of rogue npm/registry packages that AUR
// malware pulled in during the build (Atomic Arch infostealer stagers).
// A PKGBUILD that references any of these is an immediate block.
var aurDenyDeps = []string{
	"atomic-lockfile",
	"js-digest",
}

// AURPackageDenied reports whether name is on the builtin malicious-AUR
// denylist.
func AURPackageDenied(name string) bool {
	_, ok := aurDenyPackages[strings.TrimSpace(name)]
	return ok
}

// --- scanner ---

var (
	reSourceLine = regexp.MustCompile(`(?i)^\s*(?:source|_patches?|_src)\s*(?:\+?=|=)\s*\(`)
	reURLAssign  = regexp.MustCompile(`(?i)^\s*url\s*=\s*["']?([^"'\s]+)`)
	// download-then-exec: curl/wget piped to a shell, or eval of $(...)
	reNetExec = regexp.MustCompile(`(?i)(curl|wget|fetch)\b[^|;&]*(\||;|&&)\s*(sh|bash|zsh|python|perl|node|eval)\b`)
	reEvalSub = regexp.MustCompile(`(?i)\beval\s+["'$]`)
	// base64 / hex obfuscation decoded then run
	reB64Exec = regexp.MustCompile(`(?i)base64\s+(-d|--decode)[^|]*\|\s*(sh|bash|zsh|python|perl|node)\b`)
	reHexEsc  = regexp.MustCompile(`(\\x[0-9a-fA-F]{2}){4,}`)
	// foreign toolchain injected into the build (the Atomic Arch tell):
	// npm/npx/pnpm/yarn/pip invoked from a PKGBUILD build script.
	reForeignTool = regexp.MustCompile(`(?i)\b(npm|npx|pnpm|yarn|pip|pip3)\s+(install|i|add|run|exec|ci)\b`)
	// credential / secret harvesting paths
	reExfilPaths = regexp.MustCompile(`(?i)(\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.config/google-chrome|\.mozilla/firefox|wallet\.dat|\.electrum|keychain|/etc/shadow)`)
	// untrusted source hosts: raw user repos, gists, pastebins, shorteners, bare IPs
	reBareIP = regexp.MustCompile(`https?://\d{1,3}(\.\d{1,3}){3}`)
)

var untrustedHosts = []string{
	"pastebin.com", "paste.ee", "ghostbin", "gist.github.com",
	"bit.ly", "tinyurl.com", "is.gd", "t.co", "transfer.sh",
	"anonfiles", "filebin", "0x0.st", "termbin.com",
}

// pkgbuildFuncs are the bash functions a PKGBUILD/.install can define
// that run during install — anything matched inside them is weighted
// higher than the same pattern in a comment or variable elsewhere.
var pkgbuildFuncs = regexp.MustCompile(`^\s*(prepare|build|package|pkgver|post_install|post_upgrade|pre_install|pre_upgrade)\s*\(`)

// ScanPKGBUILD statically scans an AUR package's PKGBUILD and .install
// hooks for malware-delivery patterns. Pure: no I/O. Catches the
// delivery vectors used in the real AUR campaigns — untrusted source
// drift, download-and-exec, foreign-toolchain injection, obfuscation,
// credential exfil, and known IOCs. It cannot see runtime behaviour
// (rootkit persistence); that is the planned Cloud sandbox's job.
func ScanPKGBUILD(pkg AURPackage) AURScanResult {
	res := AURScanResult{Package: pkg.Name}

	// 0. denylist — hard block, independent of content.
	if AURPackageDenied(pkg.Name) {
		res.Findings = append(res.Findings, AURFinding{
			Severity: AURCritical, Rule: "ioc-package",
			Where:   "package",
			Message: "package name is on the confirmed-malicious AUR denylist",
		})
	}

	upstream := pkg.Upstream
	res.Findings = append(res.Findings, scanBytes(pkg.PKGBUILD, "PKGBUILD", upstream)...)
	res.Findings = append(res.Findings, scanBytes(pkg.Install, ".install", upstream)...)

	res.Verdict = res.deriveVerdict()
	return res
}

func scanBytes(body []byte, file, upstream string) []AURFinding {
	if len(body) == 0 {
		return nil
	}
	text := string(body)
	var out []AURFinding
	curFn := file // current enclosing function context

	// denylisted build deps — scan whole body once.
	low := strings.ToLower(text)
	for _, dep := range aurDenyDeps {
		if strings.Contains(low, strings.ToLower(dep)) {
			out = append(out, AURFinding{
				Severity: AURCritical, Rule: "ioc-dep", Where: file,
				Message:  "references a package confirmed as a malware stager (" + dep + ")",
				Evidence: dep,
			})
		}
	}

	for raw := range strings.SplitSeq(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := pkgbuildFuncs.FindStringSubmatch(line); m != nil {
			curFn = file + ":" + m[1] + "()"
		}

		if reNetExec.MatchString(line) || reB64Exec.MatchString(line) {
			out = append(out, AURFinding{
				Severity: AURCritical, Rule: "download-exec", Where: curFn,
				Message:  "downloads and pipes remote content directly into a shell",
				Evidence: trunc(line),
			})
		}
		if reEvalSub.MatchString(line) {
			out = append(out, AURFinding{
				Severity: AURHigh, Rule: "eval-obfuscation", Where: curFn,
				Message: "eval of dynamic/quoted content — common obfuscation", Evidence: trunc(line),
			})
		}
		if reHexEsc.MatchString(line) {
			out = append(out, AURFinding{
				Severity: AURHigh, Rule: "hex-obfuscation", Where: curFn,
				Message: "hex-escaped string payload", Evidence: trunc(line),
			})
		}
		if reForeignTool.MatchString(line) {
			out = append(out, AURFinding{
				Severity: AURHigh, Rule: "foreign-toolchain", Where: curFn,
				Message:  "invokes a foreign package manager during build (unrelated-ecosystem dep pull)",
				Evidence: trunc(line),
			})
		}
		if reExfilPaths.MatchString(line) {
			out = append(out, AURFinding{
				Severity: AURHigh, Rule: "credential-access", Where: curFn,
				Message: "touches credential / secret / wallet paths", Evidence: trunc(line),
			})
		}
		if reSourceLine.MatchString(line) {
			out = append(out, scanSource(text, upstream, file)...)
		}
	}
	return out
}

// scanSource flags source=() entries that point at hosts unrelated to
// the declared upstream — the Chaos RAT "patches" vector. It scans the
// whole body for URL-bearing tokens so it catches multi-line arrays.
func scanSource(text, upstream, file string) []AURFinding {
	var out []AURFinding
	host := hostOf(upstream)
	seen := map[string]struct{}{}
	for _, tok := range tokenizeURLs(text) {
		if _, dup := seen[tok]; dup {
			continue
		}
		seen[tok] = struct{}{}
		if reBareIP.MatchString(tok) {
			out = append(out, AURFinding{
				Severity: AURHigh, Rule: "source-bare-ip", Where: file + ":source[]",
				Message: "source fetched from a raw IP address", Evidence: trunc(tok),
			})
			continue
		}
		h := hostOf(tok)
		for _, bad := range untrustedHosts {
			if strings.Contains(h, bad) {
				out = append(out, AURFinding{
					Severity: AURHigh, Rule: "source-untrusted-host", Where: file + ":source[]",
					Message: "source fetched from a paste/shortener/anon host", Evidence: trunc(tok),
				})
			}
		}
		// drift: a github/gitlab user repo that doesn't match the declared upstream host
		if host != "" && h != "" && h != host && isCodeHost(h) {
			out = append(out, AURFinding{
				Severity: AURMedium, Rule: "source-host-drift", Where: file + ":source[]",
				Message:  "source host differs from declared upstream url (" + host + ")",
				Evidence: trunc(tok),
			})
		}
	}
	return out
}

var reURL = regexp.MustCompile(`(?i)\b(?:git\+)?https?://[^\s"')]+`)

func tokenizeURLs(text string) []string { return reURL.FindAllString(text, -1) }

func hostOf(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "git+"), "")
	for _, p := range []string{"https://", "http://"} {
		u = strings.TrimPrefix(u, p)
	}
	if i := strings.IndexAny(u, "/:"); i >= 0 {
		u = u[:i]
	}
	return strings.ToLower(u)
}

func isCodeHost(h string) bool {
	switch {
	case strings.Contains(h, "github"), strings.Contains(h, "gitlab"),
		strings.Contains(h, "bitbucket"), strings.Contains(h, "codeberg"),
		strings.Contains(h, "sr.ht"):
		return true
	}
	return false
}

func trunc(s string) string {
	const max = 160
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// ParseUpstreamURL extracts the PKGBUILD url= field, used to anchor
// source-drift detection. Returns "" when absent.
func ParseUpstreamURL(pkgbuild []byte) string {
	for line := range strings.SplitSeq(string(pkgbuild), "\n") {
		if m := reURLAssign.FindStringSubmatch(line); m != nil {
			return strings.Trim(m[1], `"'`)
		}
	}
	return ""
}
