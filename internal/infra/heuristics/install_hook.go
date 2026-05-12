package heuristics

import (
	"encoding/json"
	"regexp"
	"strings"
)

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
// install time. Each pattern captures the inline script body (group 2)
// so we can inspect it; benign one-liners like
// `node --eval "if (process.env.CI) process.exit(0)"` (the standard
// husky-skip-in-CI pattern) shouldn't trip the alarm.
var inlineExecPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(node)\s+(?:-e|--eval)\s+(.+)$`),
	regexp.MustCompile(`\b(python\d?)\s+-c\s+(.+)$`),
	regexp.MustCompile(`\b(ruby|perl)\s+-e\s+(.+)$`),
	regexp.MustCompile(`\b(deno)\s+eval\s+(.+)$`),
}

// inlineBenignPattern matches inline scripts that, on inspection, are
// short control-flow one-liners — not download-and-execute payloads.
// Allows `node --eval "if (process.env.CI) process.exit(0)"` and similar
// CI-skip guards without flagging the whole prepare hook.
var inlineBenignPattern = regexp.MustCompile(
	`^[\s'"]*(?:if\s*\(?\s*)?process\.(?:env\.\w+|exit\s*\(\s*\d+\s*\)|argv|platform|version)`)

// inlineDangerSignals is a deny-list of substrings that, when found
// inside an inline -e/-c script body, indicate real risk: process
// spawning, dynamic require/import, network I/O, or filesystem writes.
var inlineDangerSignals = []string{
	"require(", "import(",
	"child_process", "execSync", "spawn", "exec(",
	"fetch(", "http.", "https.", "net.",
	"fs.write", "writeFileSync", "createWriteStream",
	"atob(", `Buffer.from`, "base64",
	"eval(", "Function(",
}

// inlineLengthThreshold — anything longer is treated as opaque enough
// to warrant a human look, even without a deny-list match.
const inlineLengthThreshold = 120

// inlineScriptIsSuspicious decides whether a captured inline body
// (the content after `-e` / `--eval` / `-c`) deserves a flag. Strips
// the surrounding quotes the shell would, then applies the deny-list.
// Short, deny-list-clean bodies pass.
func inlineScriptIsSuspicious(body string) bool {
	body = strings.TrimSpace(body)
	body = strings.TrimRight(body, "&|;")
	body = strings.TrimSpace(body)
	body = trimMatchingQuotes(body)
	if body == "" {
		return false
	}
	if len(body) > inlineLengthThreshold {
		return true
	}
	if inlineBenignPattern.MatchString(body) {
		return false
	}
	for _, sig := range inlineDangerSignals {
		if strings.Contains(body, sig) {
			return true
		}
	}
	return false
}

func trimMatchingQuotes(s string) string {
	if len(s) < 2 {
		return s
	}
	first, last := s[0], s[len(s)-1]
	if (first == '"' || first == '\'') && first == last {
		return s[1 : len(s)-1]
	}
	return s
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
		m := re.FindStringSubmatch(body)
		// Every pattern in inlineExecPatterns is shaped `(lang)…(body)`,
		// so a match always has m[0..2]. Guard anyway so a future
		// pattern edit can't silently turn a flag into a panic.
		if len(m) < 3 {
			continue
		}
		// Only the node case gets the benign carve-out — `node --eval
		// "if (process.env.CI) process.exit(0)"` is the standard
		// husky-skip-in-CI prepare hook and shouldn't trip us.
		// python/ruby/perl/deno -e payloads are rarely seen outside
		// of attacker payloads, so keep flagging them unconditionally.
		if m[1] != "node" {
			return true
		}
		if inlineScriptIsSuspicious(m[2]) {
			return true
		}
	}
	if base64PipedPattern.MatchString(body) {
		return true
	}
	if suspiciousHookHostPattern.MatchString(body) {
		return true
	}
	// Silent-exit runner: `bun run payload.js && exit 1`
	// The `&& exit N` construct in a prepare/postinstall hook is
	// specifically designed to suppress npm's error output after the
	// payload runs. No legitimate hook needs this.
	if silentExitRunnerPattern.MatchString(body) {
		return true
	}
	// Non-standard runtime: `bun run <localfile>` in an install hook.
	// bun is almost never a declared dep of published libraries; its
	// presence in a postinstall/prepare script is anomalous and was the
	// specific shape used in the 2026 Mini Shai-Hulud attack.
	if bunLocalRunPattern.MatchString(body) {
		return true
	}
	return false
}

// silentExitRunnerPattern matches a local-script runner followed by
// `&& exit N`. The forced exit after a script run is specifically used
// to make npm silently discard the hook's exit status, hiding the fact
// that malware ran. Pattern: (bun|npx|deno) [run] <file.ext> && exit N
var silentExitRunnerPattern = regexp.MustCompile(
	`(?i)\b(bun|npx|deno)\s+(run\s+)?\S+\.(js|ts|mjs|cjs|tsx|jsx)\s*&&\s*exit\s+[0-9]+`)

// bunLocalRunPattern matches `bun run <localfile>` in isolation (without
// the && exit N suffix). bun is not a standard dep of published packages;
// any postinstall referencing it as a script runner is unusual enough to
// warrant inspection, even without the silence trick.
var bunLocalRunPattern = regexp.MustCompile(
	`(?i)\bbun\s+run\s+\S+\.(js|ts|mjs|cjs)`)
