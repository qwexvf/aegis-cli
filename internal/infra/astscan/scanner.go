// Package astscan dispatches to language-specific AST analyzers and
// merges their results into a single domain.Fingerprint per package.
//
// Layering:
//
//	ASTAnalyzer (interface in usecase/ports.go)
//	    ▲
//	Dispatcher (this file)
//	    ▼
//	┌── jsscan ── tdewolff/parse or tree-sitter-javascript queries
//	├── pyscan ── (later) tree-sitter-python
//	├── rbscan ── (later) tree-sitter-ruby
//	└── ...
//
// Per-language scanners produce a partial Fingerprint and a set of
// "extra" data (e.g. EnvReads names). The dispatcher folds them into
// the final domain.Fingerprint that the use case persists.
package astscan

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
	"github.com/qwexvf/aegis/services/cli/internal/usecase"
)

// LanguageScanner is the per-ecosystem analyzer interface. Today only
// JS exists; pyscan/rbscan/etc. drop into the same shape.
type LanguageScanner interface {
	// AnalyzeFile is called once per source file relevant to this
	// language. Implementations accumulate Capabilities and
	// language-specific signals (env names, file sizes) into the
	// passed *Findings.
	AnalyzeFile(path string, body []byte, f *Findings)
}

// Findings is the running accumulator a LanguageScanner writes into
// across all files of one package. Aggregated into a Fingerprint by
// Dispatcher.Analyze.
type Findings struct {
	Capabilities map[domain.Capability]struct{}
	EnvReads     map[string]struct{}
	SourceBytes  int
	FilesScanned int
}

// NewFindings returns an empty accumulator with maps initialized.
func NewFindings() *Findings {
	return &Findings{
		Capabilities: map[domain.Capability]struct{}{},
		EnvReads:     map[string]struct{}{},
	}
}

// AddCapability records a Capability detection.
func (f *Findings) AddCapability(c domain.Capability) {
	f.Capabilities[c] = struct{}{}
}

// AddEnvRead records a process.env name. Duplicates are deduplicated
// via the underlying set semantics.
func (f *Findings) AddEnvRead(name string) {
	if name == "" {
		return
	}
	f.EnvReads[name] = struct{}{}
}

// Dispatcher implements usecase.ASTAnalyzer by routing to per-language
// scanners. Construct via NewDispatcher then register scanners with
// Register.
type Dispatcher struct {
	scanners map[domain.Ecosystem]LanguageScanner
}

// NewDispatcher returns an empty Dispatcher; register scanners with
// Register.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{scanners: map[domain.Ecosystem]LanguageScanner{}}
}

// Register attaches a LanguageScanner to an ecosystem. Idempotent —
// re-registering replaces the previous scanner.
func (d *Dispatcher) Register(eco domain.Ecosystem, s LanguageScanner) {
	d.scanners[eco] = s
}

// Analyze implements usecase.ASTAnalyzer.
func (d *Dispatcher) Analyze(ctx context.Context, eco domain.Ecosystem, src usecase.PackageSource) (domain.Fingerprint, error) {
	scanner, ok := d.scanners[eco]
	if !ok {
		return domain.Fingerprint{}, fmt.Errorf("astscan: no scanner for ecosystem %q", eco)
	}

	findings := NewFindings()

	// Detect install hooks declaratively from the manifest first; the
	// language scanner may also flag them via the hook code itself.
	hooks := manifestHooks(eco, src.Manifest)
	if len(hooks) > 0 {
		findings.AddCapability(domain.CapInstallHookExec)
	}

	for path, body := range src.Files {
		if !isAnalyzable(eco, path) {
			continue
		}
		findings.SourceBytes += len(body)
		findings.FilesScanned++
		scanner.AnalyzeFile(path, body, findings)
	}

	return findingsToFingerprint(findings, hooks), nil
}

// findingsToFingerprint produces the final Fingerprint. Capabilities
// are sorted (via NewCapabilitySet); EnvReads are sorted
// alphabetically for stable output.
func findingsToFingerprint(f *Findings, hooks []domain.InstallHook) domain.Fingerprint {
	caps := make([]domain.Capability, 0, len(f.Capabilities))
	for c := range f.Capabilities {
		caps = append(caps, c)
	}
	envs := make([]string, 0, len(f.EnvReads))
	for n := range f.EnvReads {
		envs = append(envs, n)
	}
	sort.Strings(envs)
	return domain.Fingerprint{
		Analyzed:        true,
		Capabilities:    domain.NewCapabilitySet(caps...),
		Hooks:           hooks,
		EnvReads:        envs,
		SourceSizeBytes: f.SourceBytes,
	}
}

// isAnalyzable filters files by extension. Per-ecosystem rules.
func isAnalyzable(eco domain.Ecosystem, path string) bool {
	switch eco {
	case domain.EcoNpm:
		// JS/TS source. Skip .min.js/.bundle.js (already-mangled,
		// frequently false-positive) and .d.ts (type-only, no runtime).
		if strings.HasSuffix(path, ".min.js") {
			return false
		}
		if strings.HasSuffix(path, ".d.ts") {
			return false
		}
		return strings.HasSuffix(path, ".js") ||
			strings.HasSuffix(path, ".mjs") ||
			strings.HasSuffix(path, ".cjs") ||
			strings.HasSuffix(path, ".ts") ||
			strings.HasSuffix(path, ".tsx") ||
			strings.HasSuffix(path, ".jsx")
	}
	return false
}
