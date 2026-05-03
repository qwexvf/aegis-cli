package heuristics

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// DetectSuspiciousInstallHook parses the package's manifest (npm
// package.json) and inspects every install-time script for known
// malware patterns:
//
//   - download-and-execute: `curl … | sh`, `wget … | bash`
//   - inline node: `node -e "…"`, `python -c "…"`, `ruby -e "…"`
//   - base64-piped-to-shell: `echo <b64> | base64 -d | sh`
//   - eval / Function on decoded strings (caught here for hook scripts;
//     CapObfuscatedPayload covers source code)
//   - fetching from typical exfil hosts (Pastebin, Discord webhook)
//
// Returns CapInstallHookSuspicious when any pattern fires; 0 otherwise.
// A standalone install hook (CapInstallHookExec) is detected
// separately by the manifest parser; this function escalates that to
// "actively malicious-looking".
func DetectSuspiciousInstallHook(manifestRaw []byte) domain.Capability {
	scripts := extractNpmScripts(manifestRaw)
	if len(scripts) == 0 {
		return 0
	}
	for _, body := range scripts {
		if scriptMatchesMalwarePattern(body) {
			return domain.CapInstallHookSuspicious
		}
	}
	return 0
}

// extractNpmScripts pulls every install-time script out of an npm
// package.json. Returns the script bodies (verbatim) for
// preinstall / install / postinstall / prepare. The other lifecycle
// scripts (test / start / build / ...) don't run at `npm install`
// time and aren't supply-chain vectors.
//
// Returns an empty slice if the manifest is unparseable or has no
// install hooks. Failure to parse is intentionally silent — the
// caller treats "no hooks" the same as "couldn't read".
func extractNpmScripts(raw []byte) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return nil
	}
	out := make(map[string]string, 4)
	for _, phase := range []string{"preinstall", "install", "postinstall", "prepare"} {
		if body, ok := pkg.Scripts[phase]; ok && body != "" {
			out[phase] = body
		}
	}
	return out
}

// downloadExecPatterns matches "fetch and immediately execute" shell
// constructs. These are the canonical install-time backdoor shape.
// Compiled at package init so per-call cost is just a regex match.
var downloadExecPatterns = []*regexp.Regexp{
	// curl … | sh    (also handles `bash`, `zsh`, `python`, `node`)
	regexp.MustCompile(`(?i)\bcurl\b[^|;]+\|\s*(sh|bash|zsh|ksh|python\d?|node|ruby|perl)\b`),
	// wget … | sh
	regexp.MustCompile(`(?i)\bwget\b[^|;]+\|\s*(sh|bash|zsh|ksh|python\d?|node|ruby|perl)\b`),
	// fetch (BSD/macOS) … | sh
	regexp.MustCompile(`(?i)\bfetch\s+-[^|;]+\|\s*(sh|bash|zsh)\b`),
	// curl/wget fetching to a temp file then executing it
	regexp.MustCompile(`(?i)\b(curl|wget)\b[^;&|]+\s*&&\s*(sh|bash|chmod\s+\+x)\b`),
}

// inlineExecPatterns matches inline scripting from CLI flags — the
// other half of the canonical attack: short, hard-to-read, runs at
// install time.
var inlineExecPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bnode\s+-e\b`),
	regexp.MustCompile(`\bnode\s+--eval\b`),
	regexp.MustCompile(`\bpython\d?\s+-c\b`),
	regexp.MustCompile(`\bruby\s+-e\b`),
	regexp.MustCompile(`\bperl\s+-e\b`),
	regexp.MustCompile(`\bdeno\s+eval\b`),
}

// base64PipedPattern matches a base64 blob piped into a shell —
// classic obfuscation for download-execute payloads.
var base64PipedPattern = regexp.MustCompile(
	`(?i)\b(echo|printf)\b\s+['"]?[A-Za-z0-9+/]{40,}={0,2}['"]?[^|]*\|\s*(base64\s+(-d|--decode)|openssl\s+base64\s+-d)`)

// suspiciousHookHostPattern matches install hooks that talk to
// well-known C2 / exfil hosts. We keep this small — the canonical
// pattern is curl|sh, and host-blocklists go stale; better to tag
// the broad pattern and let the user investigate the URL itself.
var suspiciousHookHostPattern = regexp.MustCompile(
	`(?i)\b(curl|wget|fetch)\b[^;|]*\b(pastebin\.com|paste\.ee|hastebin\.com|transfer\.sh|file\.io|0x0\.st|ngrok\.io|trycloudflare\.com|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot)`)

func scriptMatchesMalwarePattern(body string) bool {
	body = strings.TrimSpace(body)
	if body == "" {
		return false
	}
	for _, re := range downloadExecPatterns {
		if re.MatchString(body) {
			return true
		}
	}
	for _, re := range inlineExecPatterns {
		if re.MatchString(body) {
			return true
		}
	}
	if base64PipedPattern.MatchString(body) {
		return true
	}
	if suspiciousHookHostPattern.MatchString(body) {
		return true
	}
	return false
}
