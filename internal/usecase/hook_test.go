package usecase

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// memFS is an in-memory HookFilesystem for tests. Tracks which paths
// "exist" — Stat returns os.ErrNotExist for paths not present.
type memFS struct {
	mu    sync.Mutex
	files map[string][]byte
	dirs  map[string]bool
}

func newMemFS() *memFS {
	return &memFS{
		files: map[string][]byte{},
		dirs:  map[string]bool{},
	}
}

type memFileInfo struct {
	name string
	dir  bool
}

func (i memFileInfo) Name() string       { return i.name }
func (i memFileInfo) Size() int64        { return 0 }
func (i memFileInfo) Mode() os.FileMode  { return 0o644 }
func (i memFileInfo) ModTime() time.Time { return time.Time{} }
func (i memFileInfo) IsDir() bool        { return i.dir }
func (i memFileInfo) Sys() any           { return nil }

func (m *memFS) Stat(path string) (os.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[path]; ok {
		return memFileInfo{name: path}, nil
	}
	if m.dirs[path] {
		return memFileInfo{name: path, dir: true}, nil
	}
	return nil, os.ErrNotExist
}

func (m *memFS) ReadFile(path string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.files[path]; ok {
		return append([]byte{}, b...), nil
	}
	return nil, os.ErrNotExist
}

func (m *memFS) WriteFile(path string, data []byte, _ os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[path] = append([]byte{}, data...)
	return nil
}

func (m *memFS) MkdirAll(path string, _ os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dirs[path] = true
	return nil
}

func (m *memFS) Remove(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.files, path)
	return nil
}

type hookCapturingPresenter struct {
	installed   []string
	uninstalled []string
	skipped     []string
	errors      []error
}

func (p *hookCapturingPresenter) OnHookInstalled(_, path string) {
	p.installed = append(p.installed, path)
}
func (p *hookCapturingPresenter) OnHookUninstalled(_, path string) {
	p.uninstalled = append(p.uninstalled, path)
}
func (p *hookCapturingPresenter) OnHookSkipped(reason string) {
	p.skipped = append(p.skipped, reason)
}
func (p *hookCapturingPresenter) OnHookError(err error) {
	p.errors = append(p.errors, err)
}

func TestHook_DetectsLefthookByPriority(t *testing.T) {
	fs := newMemFS()
	fs.dirs["/proj/.git"] = true
	fs.files["/proj/lefthook.yml"] = []byte("")
	fs.dirs["/proj/.husky"] = true // both present — lefthook wins

	hook := NewHook(fs, &hookCapturingPresenter{})
	framework, _ := hook.detectFramework("/proj")
	if framework != HookFrameworkLefthook {
		t.Errorf("framework = %v, want lefthook (priority over husky)", framework)
	}
}

func TestHook_DetectsHuskyWhenNoLefthook(t *testing.T) {
	fs := newMemFS()
	fs.dirs["/proj/.git"] = true
	fs.dirs["/proj/.husky"] = true

	hook := NewHook(fs, &hookCapturingPresenter{})
	framework, _ := hook.detectFramework("/proj")
	if framework != HookFrameworkHusky {
		t.Errorf("framework = %v, want husky", framework)
	}
}

func TestHook_DefaultsToNativeWhenNothingElse(t *testing.T) {
	fs := newMemFS()
	fs.dirs["/proj/.git"] = true

	hook := NewHook(fs, &hookCapturingPresenter{})
	framework, _ := hook.detectFramework("/proj")
	if framework != HookFrameworkNative {
		t.Errorf("framework = %v, want native", framework)
	}
}

func TestHook_NoGitRepoReturnsUnknown(t *testing.T) {
	fs := newMemFS()
	hook := NewHook(fs, &hookCapturingPresenter{})
	framework, _ := hook.detectFramework("/proj")
	if framework != HookFrameworkUnknown {
		t.Errorf("framework = %v, want unknown", framework)
	}
}

func TestHook_InstallNativeWritesPreCommit(t *testing.T) {
	fs := newMemFS()
	fs.dirs["/proj/.git"] = true
	pres := &hookCapturingPresenter{}
	hook := NewHook(fs, pres)

	if err := hook.Install("/proj"); err != nil {
		t.Fatal(err)
	}
	got, _ := fs.ReadFile("/proj/.git/hooks/pre-commit")
	if !strings.Contains(string(got), HookCommand) {
		t.Errorf("pre-commit missing command: %q", got)
	}
	if !strings.Contains(string(got), hookMarkerStart) {
		t.Errorf("pre-commit missing start marker")
	}
	if len(pres.installed) != 1 {
		t.Errorf("expected 1 OnHookInstalled, got %d", len(pres.installed))
	}
}

func TestHook_InstallIsIdempotent(t *testing.T) {
	fs := newMemFS()
	fs.dirs["/proj/.git"] = true
	hook := NewHook(fs, &hookCapturingPresenter{})

	for i := range 3 {
		if err := hook.Install("/proj"); err != nil {
			t.Fatalf("install %d: %v", i, err)
		}
	}
	got, _ := fs.ReadFile("/proj/.git/hooks/pre-commit")
	count := strings.Count(string(got), hookMarkerStart)
	if count != 1 {
		t.Errorf("expected exactly 1 marker block after 3 installs, got %d", count)
	}
}

func TestHook_UninstallRemovesOnlyOurBlock(t *testing.T) {
	fs := newMemFS()
	fs.dirs["/proj/.git"] = true
	// Pre-existing hook with user content.
	fs.files["/proj/.git/hooks/pre-commit"] = []byte(
		"#!/usr/bin/env sh\nset -e\necho user-step\n",
	)
	hook := NewHook(fs, &hookCapturingPresenter{})

	if err := hook.Install("/proj"); err != nil {
		t.Fatal(err)
	}
	if err := hook.Uninstall("/proj"); err != nil {
		t.Fatal(err)
	}
	got, _ := fs.ReadFile("/proj/.git/hooks/pre-commit")
	if strings.Contains(string(got), hookMarkerStart) {
		t.Errorf("uninstall left marker behind: %q", got)
	}
	if !strings.Contains(string(got), "echo user-step") {
		t.Errorf("uninstall destroyed user content: %q", got)
	}
}

func TestHook_InstallLefthookWritesYAML(t *testing.T) {
	fs := newMemFS()
	fs.dirs["/proj/.git"] = true
	fs.files["/proj/lefthook.yml"] = []byte("")
	hook := NewHook(fs, &hookCapturingPresenter{})

	if err := hook.Install("/proj"); err != nil {
		t.Fatal(err)
	}
	got, _ := fs.ReadFile("/proj/lefthook.yml")
	for _, want := range []string{"pre-commit:", "aegis-supply-chain-audit", HookCommand} {
		if !strings.Contains(string(got), want) {
			t.Errorf("lefthook.yml missing %q:\n%s", want, got)
		}
	}
}

func TestHook_InstallHuskyWritesShebang(t *testing.T) {
	fs := newMemFS()
	fs.dirs["/proj/.git"] = true
	fs.dirs["/proj/.husky"] = true
	hook := NewHook(fs, &hookCapturingPresenter{})

	if err := hook.Install("/proj"); err != nil {
		t.Fatal(err)
	}
	got, _ := fs.ReadFile("/proj/.husky/pre-commit")
	if !strings.HasPrefix(string(got), "#!/") {
		t.Errorf("husky pre-commit missing shebang: %q", got)
	}
	if !strings.Contains(string(got), HookCommand) {
		t.Errorf("husky pre-commit missing command")
	}
}

func TestInjectMarkedBlock_ReplacesExisting(t *testing.T) {
	original := "before\n" + hookMarkerStart + "\nold body\n" + hookMarkerEnd + "\nafter\n"
	got := injectMarkedBlock(original, "new body\n")
	if !strings.Contains(got, "new body") {
		t.Errorf("missing new body: %s", got)
	}
	if strings.Contains(got, "old body") {
		t.Errorf("old body still present: %s", got)
	}
	if strings.Count(got, hookMarkerStart) != 1 {
		t.Errorf("expected 1 marker, got %d", strings.Count(got, hookMarkerStart))
	}
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Errorf("user content destroyed: %s", got)
	}
}

func TestStripMarkedBlock_LeavesUserContent(t *testing.T) {
	original := "user line\n" + hookMarkerStart + "\nour body\n" + hookMarkerEnd + "\nmore user\n"
	got := stripMarkedBlock(original)
	if strings.Contains(got, "our body") {
		t.Errorf("our body still present: %s", got)
	}
	if !strings.Contains(got, "user line") || !strings.Contains(got, "more user") {
		t.Errorf("user content destroyed: %s", got)
	}
}

func TestStripMarkedBlock_NoMarkerNoOp(t *testing.T) {
	original := "no markers here\n"
	if got := stripMarkedBlock(original); got != original {
		t.Errorf("strip with no marker should be no-op, got %q", got)
	}
}

// Sanity check: detection that errors on Stat (other than ENOENT)
// surfaces an error instead of silently saying "no git repo".
func TestHook_StatErrorPropagates(t *testing.T) {
	fs := &erroringFS{err: errors.New("permission denied")}
	hook := NewHook(fs, &hookCapturingPresenter{})
	_, err := hook.detectFramework("/proj")
	if err == nil {
		t.Error("expected stat error to propagate")
	}
}

type erroringFS struct{ err error }

func (e *erroringFS) Stat(string) (os.FileInfo, error)            { return nil, e.err }
func (e *erroringFS) ReadFile(string) ([]byte, error)             { return nil, e.err }
func (e *erroringFS) WriteFile(string, []byte, os.FileMode) error { return e.err }
func (e *erroringFS) MkdirAll(string, os.FileMode) error          { return e.err }
func (e *erroringFS) Remove(string) error                         { return e.err }
