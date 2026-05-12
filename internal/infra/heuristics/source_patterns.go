package heuristics

import (
	"path"
	"regexp"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// DetectSourcePatterns scans the package source for two kinds of
// signal that the AST scanner doesn't pick up directly:
//
//   - Obfuscated payload: source contains `eval(atob(...))`,
//     `Function(decodeURIComponent(...))`, or similar
//     decode-then-execute idioms. AST sees the `eval` and the
//     `atob` separately; this detector recognises the *combination*
//     because that's the actual malware pattern.
//
//   - Suspicious URL targets: string literals pointing at C2 / paste
//     / chat-relay / tunnel hosts. Distinct from CapRawIPLiteral
//     (which catches numeric IPs); hostnames are far more common in
//     real-world malware.
//
// Implementation uses regex over the raw file bytes, scoped to JS-ish
// source (.js / .mjs / .cjs / .ts / .tsx / .jsx). Cheap, deterministic,
// and survives minification — minified malware still contains the
// `eval` token and the URL string verbatim.
func DetectSourcePatterns(src usecase.PackageSource) []domain.Capability {
	if len(src.Files) == 0 {
		return nil
	}
	var found struct {
		obfuscation  bool
		suspURL      bool
		shellFetcher bool // curl/wget piped to shell found in source
		malwareIOC   bool // known-bad filename present in tarball
	}
	for filename, body := range src.Files {
		// Known-malware IOC check runs before any other filter — if the
		// filename itself is a confirmed IOC we flag immediately and skip
		// the rest of the per-file analysis for this path.
		if !found.malwareIOC && isKnownMalwareFilename(filename) {
			found.malwareIOC = true
		}
		if !isAnalyzableSource(filename) {
			continue
		}
		// Cap per-file scan size — minified mega-bundles are a
		// malware-favourite hiding place, but checking the first
		// few hundred KB is enough to catch typical payloads
		// without OOM risk on pathological files.
		const scanCap = 256 * 1024
		if len(body) > scanCap {
			body = body[:scanCap]
		}
		// URL scan is language-agnostic — runs over any analyzable
		// source. Obfuscation regexes are language-shaped and gated
		// by per-language helpers below.
		if !found.suspURL && containsSuspiciousURL(body) {
			found.suspURL = true
		}
		if !found.obfuscation && isJSSource(filename) && obfuscatedPayloadPattern.Match(body) {
			found.obfuscation = true
		}
		if !found.obfuscation && isRubySource(filename) && rubyObfuscatedPayloadPattern.Match(body) {
			found.obfuscation = true
		}
		if !found.obfuscation && isPythonSource(filename) && pythonObfuscatedPayloadPattern.Match(body) {
			found.obfuscation = true
		}
		if !found.shellFetcher && shellFetcherPattern.Match(body) {
			found.shellFetcher = true
		}
		if found.obfuscation && found.suspURL && found.shellFetcher && found.malwareIOC {
			break
		}
	}
	var out []domain.Capability
	if found.malwareIOC {
		out = append(out, domain.CapKnownMalwareIOC)
	}
	if found.obfuscation {
		out = append(out, domain.CapObfuscatedPayload)
	}
	if found.suspURL {
		out = append(out, domain.CapSuspiciousURL)
	}
	if found.shellFetcher {
		out = append(out, domain.CapInstallHookSuspicious)
	}
	return out
}

// knownMalwareFilenames is the IOC filename blocklist. These filenames
// were confirmed malware in the 2026 Mini Shai-Hulud / TanStack campaign.
// Any tarball containing a file whose base name matches one of these
// entries is immediately flagged as CapKnownMalwareIOC regardless of
// where in the tarball tree the file appears.
var knownMalwareFilenames = map[string]struct{}{
	"router_init.js":     {},
	"router_runtime.js":  {},
	"tanstack_runner.js": {},
}

// isKnownMalwareFilename returns true when the base name of the file
// path matches a confirmed IOC from the knownMalwareFilenames set.
func isKnownMalwareFilename(filename string) bool {
	base := strings.ToLower(path.Base(filename))
	_, ok := knownMalwareFilenames[base]
	return ok
}

// obfuscatedPayloadPattern matches the canonical "decode then
// execute" idioms. The `\s*\(` lookahead-style construct keeps the
// match anchored to the call site so a benign comment containing the
// word `eval` doesn't fire.
//
// Patterns covered:
//
//	eval(atob(...))
//	eval(Buffer.from(... 'base64'))
//	Function(atob(...))()
//	new Function(decodeURIComponent(...))
//	require(atob(...))
//
// A more general AST-based detector lives in jsscan; this regex form
// is the cheap, source-agnostic fallback that also catches the
// pattern in JSON-embedded JS strings (which the AST scanner skips).
var obfuscatedPayloadPattern = regexp.MustCompile(
	`\b(?:eval|Function|require)\s*\(\s*` +
		`(?:` +
		`atob\s*\(|` +
		`Buffer\s*\.\s*from\s*\([^)]*['"]base64['"]|` +
		`decodeURIComponent\s*\(|` +
		`unescape\s*\(` +
		`)`)

// suspiciousHostPatterns is the host-substring blocklist for
// CapSuspiciousURL. Curated from observed npm malware C2 / exfil
// patterns. Substring match (not full URL parse) keeps it cheap and
// catches partial matches in minified strings.
var suspiciousHostPatterns = []string{
	// Pastebins / file dumps
	"pastebin.com",
	"hastebin.com",
	"paste.ee",
	"transfer.sh",
	"file.io",
	"0x0.st",
	"controlc.com",
	"justpaste.it",

	// Tunnels (used as ephemeral C2)
	"ngrok.io",
	"ngrok-free.app",
	"trycloudflare.com",
	"loca.lt", // localtunnel
	"serveo.net",

	// Chat-relay webhooks / bot APIs (common exfil target)
	"discord.com/api/webhooks",
	"discordapp.com/api/webhooks",
	"api.telegram.org/bot",
	"hooks.slack.com/services",

	// Public DNS-over-HTTPS endpoints used as C2 channels
	"cloudflare-dns.com/dns-query",

	// IP-grabber services (exfiltrate the victim's IP)
	"ipinfo.io",
	"ipify.org",
	"icanhazip.com",
	"ifconfig.me",

	// Session P2P network — used as C2 exfil channel in the 2026
	// Mini Shai-Hulud / TanStack attack. Traffic mimics encrypted
	// messaging app telemetry, making it hard to detect at the network
	// layer. Any package embedding getsession.org URLs should be treated
	// as a strong signal of credential-harvesting intent.
	"getsession.org",
}

// urlSchemePattern locates URLs inside source bytes. Loose — anything
// after `http(s)://` until whitespace / quote / paren / backtick
// counts. Match output is what we check against suspiciousHostPatterns.
var urlSchemePattern = regexp.MustCompile(`(?i)https?://[^\s"'` + "`" + `<>)]+`)

func containsSuspiciousURL(body []byte) bool {
	matches := urlSchemePattern.FindAll(body, -1)
	for _, raw := range matches {
		url := strings.ToLower(string(raw))
		for _, host := range suspiciousHostPatterns {
			if strings.Contains(url, host) {
				return true
			}
		}
		if containsIDNHomoglyph(url) {
			return true
		}
	}
	return false
}

// containsIDNHomoglyph reports whether the URL host contains
// Punycode-encoded non-ASCII characters (xn--prefix). These are
// the technical mechanism behind homoglyph attacks like `аррӏе.com`
// (Cyrillic) impersonating `apple.com`. A URL with `xn--` in any
// label is by definition Punycode and therefore worth a second look —
// legitimate IDN domains are rare in dependency code.
func containsIDNHomoglyph(url string) bool {
	return strings.Contains(url, "xn--")
}

// isJSSource returns true for filenames whose extension matches the
// AST scanner's input set. Used to scope source-pattern scanning to
// the same files the AST scanner walks; we don't want to flag a
// suspicious URL that lives in a README.md.
func isJSSource(filename string) bool {
	switch strings.ToLower(path.Ext(filename)) {
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".cts", ".mts":
		return true
	}
	return false
}

// isRubySource returns true for files the Ruby obfuscation regex
// should run over. Covers `.rb` (the canonical extension) and
// `.gemspec` (gem metadata that can also exec at install time).
func isRubySource(filename string) bool {
	switch strings.ToLower(path.Ext(filename)) {
	case ".rb", ".gemspec":
		return true
	}
	return false
}

// rubyObfuscatedPayloadPattern matches the canonical Ruby
// "fetch-then-execute" idioms. Shape mirrors the JS version but uses
// Ruby's stdlib HTTP / open-uri callees:
//
//	eval(Net::HTTP.get(URI("...")))
//	eval(Net::HTTP.post(...))
//	eval(open("https://..."))
//	eval(URI.open("..."))
//	eval(URI.read("..."))
//
// The require-side variant (`require(remote)`) is uncommon in Ruby —
// the real-world incidents (rest-client_2019, strong_password_2019)
// all used `eval`. Keeping the regex tight to that shape avoids
// false positives on benign HTTP fetches that aren't passed to eval.
// shellFetcherPattern detects `curl … | (ba)?sh` and `wget … | (ba)?sh`
// appearing as string literals inside source files. This is the canonical
// "fetch-and-execute" remote-install pattern:
//
//	curl -fsSL https://raw.githubusercontent.com/user/repo/main/install.sh | bash
//	wget -qO- https://example.com/setup.sh | sh
//
// Distinct from the install_hook detector (which looks at package.json
// `scripts`): this fires when a package dynamically constructs and runs
// such a command from within its JS/Python/Ruby/etc. source.
//
// Pattern notes:
//   - `[^|;\n]{0,300}` — allow flags and URL between curl/wget and the pipe,
//     bounded to 300 chars to avoid catastrophic backtracking on long strings.
//   - Shell list: sh, bash, zsh, ksh, dash — all meaningful targets.
//   - Case-insensitive so `CURL` (rare but seen in obfuscated payloads) fires.
var shellFetcherPattern = regexp.MustCompile(
	`(?i)\b(?:curl|wget)\b[^|;\n]{0,300}\|\s*(?:ba|da|z|k)?sh\b`)

var rubyObfuscatedPayloadPattern = regexp.MustCompile(
	`\beval\s*\(\s*` +
		`(?:` +
		`Net::HTTP\.(?:get|post)\s*\(|` +
		`open\s*\(\s*['"]https?:|` +
		`URI\.(?:open|read)\s*\(` +
		`)`)

// isPythonSource returns true for files the Python obfuscation regex
// should run over. `.py` is the canonical extension; `.pyi` (stubs)
// and `.pyx` (Cython) round it out — install-time payloads have been
// observed in all three.
func isPythonSource(filename string) bool {
	switch strings.ToLower(path.Ext(filename)) {
	case ".py", ".pyi", ".pyx":
		return true
	}
	return false
}

// pythonObfuscatedPayloadPattern matches Python's canonical
// "fetch-then-execute" idioms. Shape mirrors the JS / Ruby variants
// using Python stdlib + popular third-party HTTP callees:
//
//	exec(urllib.request.urlopen("...").read())
//	eval(urllib.request.urlopen("...").read())
//	exec(requests.get("...").text)
//	exec(httpx.get("...").content)
//	exec(base64.b64decode(payload))
//	exec(compile(base64.b64decode(...), ...))
//
// `exec` is used FAR more often than `eval` for malware in Python
// (eval is expression-only, exec runs full statements), but both
// are accepted to be safe.
var pythonObfuscatedPayloadPattern = regexp.MustCompile(
	`\b(?:exec|eval)\s*\(\s*` +
		`(?:` +
		`urllib\.request\.urlopen\s*\(|` +
		`urllib2\.urlopen\s*\(|` +
		`(?:requests|httpx|aiohttp)\.(?:get|post)\s*\(|` +
		`base64\.b64decode\s*\(|` +
		`codecs\.decode\s*\(|` +
		`compile\s*\(\s*base64\.` +
		`)`)

// isAnalyzableSource is the broader gate for language-agnostic scans
// (URL blocklist, IDN homoglyph). Covers every language the gate sees
// today; per-language obfuscation detectors gate on their own narrower
// helpers (isJSSource, isRubySource, isPythonSource).
func isAnalyzableSource(filename string) bool {
	if isJSSource(filename) {
		return true
	}
	switch strings.ToLower(path.Ext(filename)) {
	case ".py", ".pyi", ".pyx", ".rb", ".gemspec", ".rs", ".go",
		".java", ".php", ".phtml", ".cs", ".csx":
		return true
	}
	return false
}
