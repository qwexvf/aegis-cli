package heuristics

import (
	"regexp"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// checkSecrets scans package source files for hardcoded credentials:
// AWS access keys, GitHub tokens, npm tokens, PEM private keys, Stripe
// secret keys, SendGrid API keys, and Twilio auth IDs.
//
// Distinct from CapEnvRead (reading env vars at runtime) — this fires
// when the credential value itself is baked into the source. No
// legitimate published package should embed real credentials; false
// positives are mostly example/test tokens in documentation files,
// which can be suppressed via allowlist.
func checkSecrets(pkg NormalizedPackage) []domain.Capability {
	if len(pkg.Files) == 0 {
		return nil
	}
	for filename, body := range pkg.Files {
		if !isAnalyzableSource(filename) {
			continue
		}
		const scanCap = 256 * 1024
		if len(body) > scanCap {
			body = body[:scanCap]
		}
		if containsHardcodedSecret(body) {
			return []domain.Capability{domain.CapHardcodedSecret}
		}
	}
	return nil
}

// containsHardcodedSecret returns true when body matches any secret
// pattern. Vendor-documented placeholders (AWS AKIAIOSFODNN7EXAMPLE,
// GitHub all-a sample tokens, etc.) are excluded so tutorial snippets
// don't manufacture false positives.
func containsHardcodedSecret(body []byte) bool {
	for _, p := range secretPatterns {
		for _, m := range p.FindAll(body, -1) {
			if isKnownPlaceholder(m) {
				continue
			}
			return true
		}
	}
	return false
}

// knownPlaceholders is the set of vendor-published example tokens that
// must not trigger CapHardcodedSecret. Substrings are compared exactly
// (case-sensitive) — these are stable canonical examples, not user-
// typed identifiers.
var knownPlaceholders = [][]byte{
	[]byte("AKIAIOSFODNN7EXAMPLE"),  // AWS IAM docs canonical
	[]byte("AKIA0000000000000000"),  // all-zero placeholder
	[]byte("AKIAEXAMPLEAKIAEXAMPL"), // 20-char EXAMPLE variant
	[]byte("ASIAIOSFODNN7EXAMPLE"),  // AWS STS docs canonical
}

func isKnownPlaceholder(match []byte) bool {
	for _, p := range knownPlaceholders {
		if len(match) == len(p) {
			same := true
			for i := range match {
				if match[i] != p[i] {
					same = false
					break
				}
			}
			if same {
				return true
			}
		}
	}
	return false
}

// secretPatterns is the set of compiled regexes for credential detection.
// Each pattern is conservative: it targets the structured prefix /
// format that distinguishes a real credential from a random string.
// High-entropy generic string detection is intentionally excluded —
// the false-positive rate is unacceptable at scale.
var secretPatterns = []*regexp.Regexp{
	// AWS access key ID — format documented by AWS; always starts AKIA
	// (long-term) or ASIA (temporary/STS). 20-char alphanumeric suffix.
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bASIA[0-9A-Z]{16}\b`),

	// GitHub tokens — all formats since the 2021 prefix rollout.
	//   ghp_  personal access token (classic)
	//   gho_  OAuth app token
	//   ghu_  GitHub App user-to-server token
	//   ghs_  GitHub App server-to-server token
	//   ghr_  refresh token
	//   github_pat_  fine-grained PAT (2022+)
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,251}\b`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{82}\b`),

	// npm publish / automation tokens (2021+ format)
	regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),

	// PEM private key headers — any key type that would give an
	// attacker signing or decryption capability.
	regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),

	// Stripe secret key (sk_live / sk_test) and restricted key (rk_live)
	regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b`),

	// SendGrid API key — always starts SG., 56-char base64url suffix
	regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b`),

	// Twilio account SID / auth token — AC + 32 hex for SID
	regexp.MustCompile(`\bAC[0-9a-fA-F]{32}\b`),

	// Slack bot token
	regexp.MustCompile(`\bxoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+\b`),

	// Generic "Bearer <long-token>" in source (e.g. embedded in fetch calls)
	// Only fire when the token is ≥ 40 chars to avoid matching short IDs.
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9+/\-_]{40,}={0,2}\b`),
}
