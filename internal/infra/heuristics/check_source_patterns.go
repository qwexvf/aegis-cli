package heuristics

import "github.com/qwexvf/aegis-cli/internal/domain"

// checkSourcePatterns scans package source files for obfuscated payloads,
// suspicious C2/exfil URLs, shell-fetcher patterns, and known malware IOC
// filenames. Runs over all analyzable source files in the package tarball.
func checkSourcePatterns(pkg NormalizedPackage) []domain.Capability {
	if len(pkg.Files) == 0 {
		return nil
	}
	var found struct {
		obfuscation  bool
		suspURL      bool
		shellFetcher bool
		malwareIOC   bool
	}
	for filename, body := range pkg.Files {
		if !found.malwareIOC && isKnownMalwareFilename(filename) {
			found.malwareIOC = true
		}
		if !isAnalyzableSource(filename) {
			continue
		}
		const scanCap = 256 * 1024
		if len(body) > scanCap {
			body = body[:scanCap]
		}
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
