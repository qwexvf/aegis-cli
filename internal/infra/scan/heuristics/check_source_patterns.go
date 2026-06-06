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
		// Scan both the raw body and a split-string-collapsed view so
		// obfuscation like "paste"+"bin"+".com" or eval('at'+'ob'(...))
		// can't hide a C2 host or decode-exec payload from the regex /
		// substring matchers. The collapsed view is only built when a
		// concat seam is present, so clean files pay nothing.
		for _, b := range concatVariants(body) {
			if !found.suspURL && containsSuspiciousURL(b) {
				found.suspURL = true
			}
			if !found.obfuscation && isJSSource(filename) && obfuscatedPayloadPattern.Match(b) {
				found.obfuscation = true
			}
			if !found.obfuscation && isRubySource(filename) && rubyObfuscatedPayloadPattern.Match(b) {
				found.obfuscation = true
			}
			if !found.obfuscation && isPythonSource(filename) && pythonObfuscatedPayloadPattern.Match(b) {
				found.obfuscation = true
			}
			if !found.obfuscation && isRSource(filename) && rObfuscatedPayloadPattern.Match(b) {
				found.obfuscation = true
			}
			if !found.obfuscation && isPerlSource(filename) && perlObfuscatedPayloadPattern.Match(b) {
				found.obfuscation = true
			}
			if !found.shellFetcher && shellFetcherPattern.Match(b) {
				found.shellFetcher = true
			}
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
