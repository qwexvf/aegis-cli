package locksnap

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// fakeParser is a minimal LockfileParser for the registration tests.
// Carries an Ecosystem and a fixed []Dependency to return.
type fakeParser struct {
	filename string
	eco      domain.Ecosystem
	deps     []domain.Dependency
	err      error
	calls    int
}

func (p *fakeParser) Filename() string            { return p.filename }
func (p *fakeParser) Ecosystem() domain.Ecosystem { return p.eco }
func (p *fakeParser) Parse(_ []byte, _ map[string]bool) ([]domain.Dependency, error) {
	p.calls++
	if p.err != nil {
		return nil, p.err
	}
	return p.deps, nil
}

// TestRegister_AddsAndDispatches verifies the public Register API
// works end-to-end: an external parser registered for a brand-new
// filename is picked up by ScanProject.
func TestRegister_AddsAndDispatches(t *testing.T) {
	// Snapshot + restore the registry so the test doesn't pollute
	// other tests' state.
	saved := registry
	defer func() { registry = saved }()

	tmp := t.TempDir()
	customFile := "Custom.lock"
	if err := os.WriteFile(filepath.Join(tmp, customFile), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	const myEco = domain.Ecosystem("my-eco")
	p := &fakeParser{
		filename: customFile,
		eco:      myEco,
		deps:     []domain.Dependency{{Ecosystem: myEco, Name: "foo", Version: "1.0.0"}},
	}
	Register(p)

	deps, err := (&Scanner{}).ScanProject(tmp)
	if err != nil {
		t.Fatalf("ScanProject: %v", err)
	}
	if p.calls != 1 {
		t.Errorf("custom parser should be called once, got %d", p.calls)
	}
	if len(deps) != 1 || deps[0].Name != "foo" {
		t.Errorf("expected foo dep from custom parser, got %v", deps)
	}
}

// TestRegister_ReplacesExisting confirms re-registering the same
// filename swaps out the previous parser. Useful for tests and for
// downstream forks that want to override a built-in.
func TestRegister_ReplacesExisting(t *testing.T) {
	saved := registry
	defer func() { registry = saved }()

	first := &fakeParser{filename: "X.lock", eco: domain.EcoNpm}
	second := &fakeParser{filename: "X.lock", eco: domain.EcoNpm}
	Register(first)
	Register(second)

	count := 0
	for _, p := range registry {
		if p.Filename() == "X.lock" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("X.lock should appear exactly once after replacement, got %d", count)
	}
}

// TestRegistered_IncludesBuiltins is a smoke test that the in-tree
// init() registrations all happened. Specific filename / ecosystem
// pairs are checked against the documented set.
func TestRegistered_IncludesBuiltins(t *testing.T) {
	want := map[string]domain.Ecosystem{
		"package-lock.json": domain.EcoNpm,
		"pnpm-lock.yaml":    domain.EcoNpm,
		"poetry.lock":       domain.EcoPyPI,
		"requirements.txt":  domain.EcoPyPI,
		"Cargo.lock":        domain.EcoCrates,
		"go.sum":            domain.EcoGo,
		"Gemfile.lock":      domain.EcoRubyGems,
		"pubspec.lock":      domain.EcoPub,
		"Package.resolved":  domain.EcoSwiftPM,
		"mix.lock":          domain.EcoGleam,
	}
	have := map[string]domain.Ecosystem{}
	for _, p := range Registered() {
		have[p.Filename()] = p.Ecosystem()
	}
	for fname, wantEco := range want {
		if got, ok := have[fname]; !ok {
			t.Errorf("built-in parser missing: %q", fname)
		} else if got != wantEco {
			t.Errorf("built-in %q has eco %v, want %v", fname, got, wantEco)
		}
	}
}

// TestScan_PropagatesParserError confirms a parser-side error
// (rather than a missing-file error) bubbles up.
func TestScan_PropagatesParserError(t *testing.T) {
	saved := registry
	defer func() { registry = saved }()

	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "Boom.lock"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	Register(&fakeParser{
		filename: "Boom.lock",
		eco:      domain.Ecosystem("boom-eco"),
		err:      errors.New("intentional"),
	})

	_, err := (&Scanner{}).ScanProject(tmp)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
