package astscan

import (
	"context"
	"strings"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// fakeLanguageScanner records which files it was asked to analyze and
// stamps a configurable Capability into the findings for each.
type fakeLanguageScanner struct {
	stampCap     domain.Capability
	stampEnv     string
	visitedPaths []string
}

func (f *fakeLanguageScanner) AnalyzeFile(path string, body []byte, fnd *Findings) {
	f.visitedPaths = append(f.visitedPaths, path)
	if f.stampCap != 0 {
		fnd.AddCapability(f.stampCap)
	}
	if f.stampEnv != "" {
		fnd.AddEnvRead(f.stampEnv)
	}
}

func TestDispatcher_RoutesByEcosystem(t *testing.T) {
	d := NewDispatcher()
	js := &fakeLanguageScanner{stampCap: domain.CapShellSpawn}
	d.Register(domain.EcoNpm, js)

	src := usecase.PackageSource{Files: map[string][]byte{"index.js": []byte("ignored")}}
	fp, err := d.Analyze(context.Background(), domain.EcoNpm, src)
	if err != nil {
		t.Fatal(err)
	}
	if !fp.Capabilities.Has(domain.CapShellSpawn) {
		t.Errorf("expected CapShellSpawn from registered scanner, got %v", fp.Capabilities)
	}
	if !fp.Analyzed {
		t.Error("Analyzed flag must be set")
	}
}

func TestDispatcher_UnsupportedEcosystemErrors(t *testing.T) {
	d := NewDispatcher()
	d.Register(domain.EcoNpm, &fakeLanguageScanner{})

	_, err := d.Analyze(context.Background(), domain.EcoPyPI, usecase.PackageSource{})
	if err == nil || !strings.Contains(err.Error(), "no scanner for ecosystem") {
		t.Errorf("expected no-scanner error, got %v", err)
	}
}

func TestDispatcher_FiltersFilesByExtension(t *testing.T) {
	js := &fakeLanguageScanner{}
	d := NewDispatcher()
	d.Register(domain.EcoNpm, js)

	src := usecase.PackageSource{Files: map[string][]byte{
		"index.js":           []byte("a"),
		"src/lib.ts":         []byte("a"),
		"src/lib.tsx":        []byte("a"),
		"src/lib.jsx":        []byte("a"),
		"src/lib.mjs":        []byte("a"),
		"src/lib.cjs":        []byte("a"),
		"types.d.ts":         []byte("a"), // skipped (type-only)
		"dist/bundle.min.js": []byte("a"), // skipped (minified)
		"README.md":          []byte("a"), // skipped (non-source)
		"package.json":       []byte("a"), // skipped (manifest, handled separately)
		"src/styles.css":     []byte("a"), // skipped
	}}
	if _, err := d.Analyze(context.Background(), domain.EcoNpm, src); err != nil {
		t.Fatal(err)
	}

	visited := map[string]bool{}
	for _, p := range js.visitedPaths {
		visited[p] = true
	}
	for _, want := range []string{"index.js", "src/lib.ts", "src/lib.tsx", "src/lib.jsx", "src/lib.mjs", "src/lib.cjs"} {
		if !visited[want] {
			t.Errorf("expected scanner to see %q, didn't", want)
		}
	}
	for _, skip := range []string{"types.d.ts", "dist/bundle.min.js", "README.md", "package.json", "src/styles.css"} {
		if visited[skip] {
			t.Errorf("scanner visited %q but should have skipped", skip)
		}
	}
}

func TestDispatcher_AccumulatesSourceSize(t *testing.T) {
	d := NewDispatcher()
	d.Register(domain.EcoNpm, &fakeLanguageScanner{})
	src := usecase.PackageSource{Files: map[string][]byte{
		"a.js": []byte("12345"),        // 5
		"b.js": []byte("123456789012"), // 12
		"r.md": []byte("ignored"),
	}}
	fp, _ := d.Analyze(context.Background(), domain.EcoNpm, src)
	if fp.SourceSizeBytes != 17 {
		t.Errorf("source size = %d, want 17", fp.SourceSizeBytes)
	}
}

func TestDispatcher_MergesManifestHooks(t *testing.T) {
	d := NewDispatcher()
	d.Register(domain.EcoNpm, &fakeLanguageScanner{})

	src := usecase.PackageSource{
		Files:    map[string][]byte{"index.js": []byte("noop")},
		Manifest: []byte(`{"scripts":{"postinstall":"node x.js"}}`),
	}
	fp, err := d.Analyze(context.Background(), domain.EcoNpm, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(fp.Hooks) != 1 || fp.Hooks[0].Phase != domain.PhasePostInstall {
		t.Errorf("manifest hooks not propagated: %+v", fp.Hooks)
	}
	// Manifest also adds CapInstallHookExec automatically.
	if !fp.Capabilities.Has(domain.CapInstallHookExec) {
		t.Error("manifest hooks should imply CapInstallHookExec")
	}
}

func TestDispatcher_NoFilesProducesAnalyzedFingerprint(t *testing.T) {
	d := NewDispatcher()
	d.Register(domain.EcoNpm, &fakeLanguageScanner{})

	fp, err := d.Analyze(context.Background(), domain.EcoNpm, usecase.PackageSource{})
	if err != nil {
		t.Fatal(err)
	}
	if !fp.Analyzed {
		t.Error("empty source should still produce Analyzed=true")
	}
	if len(fp.Capabilities) != 0 {
		t.Errorf("empty source should have no capabilities, got %v", fp.Capabilities)
	}
}

func TestFindings_AddCapabilityDedups(t *testing.T) {
	f := NewFindings()
	f.AddCapability(domain.CapShellSpawn)
	f.AddCapability(domain.CapShellSpawn)
	f.AddCapability(domain.CapNetEgress)
	if len(f.Capabilities) != 2 {
		t.Errorf("expected 2 unique capabilities, got %d", len(f.Capabilities))
	}
}

func TestFindings_AddEnvReadDedupsAndIgnoresEmpty(t *testing.T) {
	f := NewFindings()
	f.AddEnvRead("AWS_ACCESS_KEY_ID")
	f.AddEnvRead("AWS_ACCESS_KEY_ID")
	f.AddEnvRead("")
	f.AddEnvRead("NPM_TOKEN")
	if len(f.EnvReads) != 2 {
		t.Errorf("expected 2 unique env reads (empty ignored), got %v", f.EnvReads)
	}
}

func TestFindingsToFingerprint_StableEnvReadOrder(t *testing.T) {
	// Map iteration is unordered; we sort env reads on conversion.
	f := NewFindings()
	for _, n := range []string{"NPM_TOKEN", "AWS_ACCESS_KEY_ID", "GITHUB_TOKEN"} {
		f.AddEnvRead(n)
	}
	fp := findingsToFingerprint(f, nil)
	want := []string{"AWS_ACCESS_KEY_ID", "GITHUB_TOKEN", "NPM_TOKEN"}
	for i, w := range want {
		if fp.EnvReads[i] != w {
			t.Errorf("env reads[%d] = %q, want %q", i, fp.EnvReads[i], w)
		}
	}
}
