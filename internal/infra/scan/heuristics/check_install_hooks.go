package heuristics

import "github.com/qwexvf/aegis-cli/internal/domain"

// checkInstallHooks fires when any declared install-time or build-time
// hook script matches a known malware-distribution pattern.
// Covers npm lifecycle scripts, Cargo build.rs, and any future ecosystems
// whose parsers populate NormalizedPackage.Hooks.
func checkInstallHooks(pkg NormalizedPackage) []domain.Capability {
	for _, hook := range pkg.Hooks {
		if scriptMatchesMalwarePattern(hook.Body) {
			return []domain.Capability{domain.CapInstallHookSuspicious}
		}
	}
	return nil
}
