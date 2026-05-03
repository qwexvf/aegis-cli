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
		obfuscation bool
		suspURL     bool
	}
	for filename, body := range src.Files {
		if !isJSSource(filename) {
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
		if !found.obfuscation && obfuscatedPayloadPattern.Match(body) {
			found.obfuscation = true
		}
		if !found.suspURL && containsSuspiciousURL(body) {
			found.suspURL = true
		}
		if found.obfuscation && found.suspURL {
			break // both fired; no need to scan further
		}
	}
	var out []domain.Capability
	if found.obfuscation {
		out = append(out, domain.CapObfuscatedPayload)
	}
	if found.suspURL {
		out = append(out, domain.CapSuspiciousURL)
	}
	return out
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
