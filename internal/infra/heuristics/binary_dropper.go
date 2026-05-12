package heuristics

import (
	"path"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// isSuspiciousBinary returns true when the filename's extension is on
// the "native binary or platform script" list. Lowercase comparison
// against path.Ext for portability.
func isSuspiciousBinary(filename string) bool {
	ext := strings.ToLower(path.Ext(filename))
	switch ext {
	case ".exe", ".msi", ".bat", ".cmd",
		".dll", ".so", ".dylib",
		".scpt", ".applescript",
		".ps1":
		return true
	}
	return false
}

// isExpectedNativePath returns true when a (ecosystem, filename) pair
// matches the canonical "this is supposed to be a binary" packaging
// convention for that ecosystem — which means the binary-dropper
// heuristic should NOT fire on it.
//
// The carve-outs are intentionally tight: anything that doesn't match
// the documented packaging shape gets flagged.
func isExpectedNativePath(eco domain.Ecosystem, filename string) bool {
	lower := strings.ToLower(filename)
	switch eco {
	case domain.EcoPyPI:
		// CPython ABI-tagged extensions: .cpython-310-x86_64-linux-gnu.so,
		// .abi3.so, .pyd (Windows extension). These are how PyPI wheels
		// legitimately ship C extensions (numpy, pillow, lxml).
		if strings.Contains(lower, ".cpython-") && strings.HasSuffix(lower, ".so") {
			return true
		}
		if strings.HasSuffix(lower, ".abi3.so") {
			return true
		}
		if strings.HasSuffix(lower, ".pyd") {
			return true
		}
		// Bundled-library conventions used by manylinux wheels: <pkg>/.libs/
		// (auditwheel) and <pkg>/_vendor/.
		if strings.Contains(lower, "/.libs/") || strings.Contains(lower, "/_vendor/") {
			return true
		}
		return false
	case domain.EcoCrates:
		// Rust crates legitimately ship source. Native libraries that ARE
		// shipped (rare — typically by -sys crates) are static archives
		// (.a / .lib), which aren't on the suspiciousBinary list anyway.
		// Pre-compiled .so / .dll / .dylib in a crate is the malware
		// pattern (big_decimal_2024); no legitimate carve-out.
		return false
	case domain.EcoNpm:
		// npm has no convention that distinguishes "expected native"
		// from "stray native". Binaries belong to known-toolchain
		// packages handled by the user allowlist, not a builtin
		// pattern.
		return false
	}
	return false
}
