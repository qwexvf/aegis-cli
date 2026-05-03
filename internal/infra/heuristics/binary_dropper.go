package heuristics

import (
	"path"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// DetectBinaryDropper flags packages that ship a native executable
// or platform-specific script of a kind unusual for a JS package:
//
//   - .exe / .msi / .bat / .cmd          — Windows binary or batch
//   - .dll / .so / .dylib                  — native library
//   - .scpt / .applescript                 — macOS script
//   - .ps1                                 — PowerShell
//
// Why heuristic and not deny-list: legitimate npm packages do ship
// native binaries (esbuild, swc, sharp, ...). The signal is "investigate";
// pair with the allowlist for known-good toolchains. Weight in
// domain.WeightBinaryDropper is moderate, not overriding.
//
// Only fires for npm today — Python wheels (.whl) legitimately ship
// .so files; Go modules don't have a packaging story this catches.
// Extend once we have AST scanners for those ecosystems.
func DetectBinaryDropper(eco domain.Ecosystem, src usecase.PackageSource) domain.Capability {
	if eco != domain.EcoNpm {
		return 0
	}
	if len(src.Files) == 0 {
		return 0
	}
	for filename := range src.Files {
		if isSuspiciousBinary(filename) {
			return domain.CapBinaryDropper
		}
	}
	return 0
}

// isSuspiciousBinary returns true when the filename's extension is on
// the "doesn't belong in an npm tarball" list. Lowercase comparison
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
