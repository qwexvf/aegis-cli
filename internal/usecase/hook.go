package usecase

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Hook is the use case for `aegis hook install` / `uninstall`. It
// detects the project's hook framework (lefthook → husky → native
// git hooks, in priority order) and installs an aegis-managed
// pre-commit step that runs `aegis ci --fail-on=block --no-enrich
// --quiet` whenever lockfiles change.
//
// "Adoption multiplier" feature: the install gate only protects users
// who type `aegis bun add`. A pre-commit hook makes it automatic —
// every commit that touches a lockfile gets audited before it lands.
//
// Idempotent: re-running install replaces our entry rather than
// stacking duplicates. uninstall removes only the entry we wrote;
// other hook config the user has stays intact.
type Hook struct {
	fs        HookFilesystem
	presenter HookPresenter
}

// HookFilesystem is the small surface of fs operations the use case
// needs. Tests substitute an in-memory implementation; production
// uses the on-disk adapter (NewHookFilesystem).
type HookFilesystem interface {
	Stat(path string) (os.FileInfo, error)
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, perm os.FileMode) error
	MkdirAll(path string, perm os.FileMode) error
	Remove(path string) error
}

// HookPresenter renders install / uninstall outcomes.
type HookPresenter interface {
	OnHookInstalled(framework, path string)
	OnHookUninstalled(framework, path string)
	OnHookSkipped(reason string)
	OnHookError(err error)
}

// NewHook wires the use case.
func NewHook(fs HookFilesystem, presenter HookPresenter) *Hook {
	return &Hook{fs: fs, presenter: presenter}
}

// HookFramework names the supported hook systems, in detection
// priority order. Higher value = preferred when multiple are present.
type HookFramework int

const (
	HookFrameworkUnknown  HookFramework = iota
	HookFrameworkNative                 // .git/hooks/pre-commit
	HookFrameworkHusky                  // .husky/pre-commit
	HookFrameworkLefthook               // lefthook.yml
)

// String returns the canonical name.
func (f HookFramework) String() string {
	switch f {
	case HookFrameworkLefthook:
		return "lefthook"
	case HookFrameworkHusky:
		return "husky"
	case HookFrameworkNative:
		return "native git hooks"
	}
	return "unknown"
}

// HookCommand is the command line we wire into the pre-commit step.
// Conservative defaults: --no-enrich (skip AST scan, fast), --quiet
// (summary only), --fail-on=block (don't fail commits on warnings).
const HookCommand = "aegis ci --fail-on=block --no-enrich --quiet"

// Sentinel markers — both install and uninstall match on these so we
// only touch our own lines, never the user's other hook config.
const (
	hookMarkerStart = "# >>> aegis-managed pre-commit (do not edit) >>>"
	hookMarkerEnd   = "# <<< aegis-managed pre-commit <<<"
)

// Install detects the project's hook framework and writes (or
// replaces) our managed pre-commit entry. Returns the framework used
// + the path of the file modified, so the presenter can show what
// happened.
func (h *Hook) Install(projectDir string) error {
	framework, err := h.detectFramework(projectDir)
	if err != nil {
		h.presenter.OnHookError(err)
		return err
	}
	if framework == HookFrameworkUnknown {
		h.presenter.OnHookSkipped("no git repo at " + projectDir + " (run `git init` first)")
		return fmt.Errorf("hook: not a git repo")
	}

	switch framework {
	case HookFrameworkLefthook:
		return h.installLefthook(projectDir)
	case HookFrameworkHusky:
		return h.installHusky(projectDir)
	case HookFrameworkNative:
		return h.installNative(projectDir)
	}
	return fmt.Errorf("hook: unsupported framework %s", framework)
}

// Uninstall removes our managed entry from whichever framework owns
// it. Idempotent — succeeds silently if no aegis entry is present.
func (h *Hook) Uninstall(projectDir string) error {
	framework, err := h.detectFramework(projectDir)
	if err != nil {
		h.presenter.OnHookError(err)
		return err
	}
	if framework == HookFrameworkUnknown {
		h.presenter.OnHookSkipped("no git repo at " + projectDir)
		return nil
	}

	switch framework {
	case HookFrameworkLefthook:
		return h.uninstallLefthook(projectDir)
	case HookFrameworkHusky:
		return h.uninstallHusky(projectDir)
	case HookFrameworkNative:
		return h.uninstallNative(projectDir)
	}
	return nil
}

// detectFramework inspects the project for hook framework markers in
// priority order. Returns Unknown when there's no git repo at all.
func (h *Hook) detectFramework(projectDir string) (HookFramework, error) {
	if _, err := h.fs.Stat(filepath.Join(projectDir, ".git")); err != nil {
		if os.IsNotExist(err) {
			return HookFrameworkUnknown, nil
		}
		return HookFrameworkUnknown, fmt.Errorf("stat .git: %w", err)
	}
	if _, err := h.fs.Stat(filepath.Join(projectDir, "lefthook.yml")); err == nil {
		return HookFrameworkLefthook, nil
	}
	if _, err := h.fs.Stat(filepath.Join(projectDir, ".lefthook.yml")); err == nil {
		return HookFrameworkLefthook, nil
	}
	if _, err := h.fs.Stat(filepath.Join(projectDir, ".husky")); err == nil {
		return HookFrameworkHusky, nil
	}
	return HookFrameworkNative, nil
}

// --- Lefthook -----------------------------------------------------------

const lefthookEntry = `pre-commit:
  commands:
    aegis-supply-chain-audit:
      glob: "{package.json,package-lock.json,bun.lock,bun.lockb,yarn.lock,pnpm-lock.yaml}"
      run: ` + HookCommand + `
      stage_fixed: false
`

func (h *Hook) installLefthook(projectDir string) error {
	path := filepath.Join(projectDir, "lefthook.yml")
	if _, err := h.fs.Stat(path); err != nil {
		path = filepath.Join(projectDir, ".lefthook.yml")
	}
	existing, _ := h.fs.ReadFile(path)
	updated := injectMarkedBlock(string(existing), lefthookEntry)
	if err := h.fs.WriteFile(path, []byte(updated), 0o644); err != nil {
		h.presenter.OnHookError(err)
		return err
	}
	h.presenter.OnHookInstalled("lefthook", path)
	return nil
}

func (h *Hook) uninstallLefthook(projectDir string) error {
	path := filepath.Join(projectDir, "lefthook.yml")
	if _, err := h.fs.Stat(path); err != nil {
		path = filepath.Join(projectDir, ".lefthook.yml")
	}
	existing, err := h.fs.ReadFile(path)
	if err != nil {
		h.presenter.OnHookSkipped("no lefthook config to clean")
		return nil
	}
	cleaned := stripMarkedBlock(string(existing))
	if err := h.fs.WriteFile(path, []byte(cleaned), 0o644); err != nil {
		h.presenter.OnHookError(err)
		return err
	}
	h.presenter.OnHookUninstalled("lefthook", path)
	return nil
}

// --- Husky --------------------------------------------------------------

func (h *Hook) installHusky(projectDir string) error {
	path := filepath.Join(projectDir, ".husky", "pre-commit")
	if err := h.fs.MkdirAll(filepath.Join(projectDir, ".husky"), 0o755); err != nil {
		h.presenter.OnHookError(err)
		return err
	}
	existing, _ := h.fs.ReadFile(path)
	if !strings.Contains(string(existing), "#!/") {
		// Husky pre-commit needs a shebang — write a minimal scaffold.
		existing = []byte("#!/usr/bin/env sh\n. \"$(dirname -- \"$0\")/_/husky.sh\"\n\n")
	}
	updated := injectMarkedBlock(string(existing), HookCommand+"\n")
	if err := h.fs.WriteFile(path, []byte(updated), 0o755); err != nil {
		h.presenter.OnHookError(err)
		return err
	}
	h.presenter.OnHookInstalled("husky", path)
	return nil
}

func (h *Hook) uninstallHusky(projectDir string) error {
	path := filepath.Join(projectDir, ".husky", "pre-commit")
	existing, err := h.fs.ReadFile(path)
	if err != nil {
		h.presenter.OnHookSkipped("no .husky/pre-commit to clean")
		return nil
	}
	cleaned := stripMarkedBlock(string(existing))
	if err := h.fs.WriteFile(path, []byte(cleaned), 0o755); err != nil {
		h.presenter.OnHookError(err)
		return err
	}
	h.presenter.OnHookUninstalled("husky", path)
	return nil
}

// --- Native git hooks ---------------------------------------------------

func (h *Hook) installNative(projectDir string) error {
	dir := filepath.Join(projectDir, ".git", "hooks")
	if err := h.fs.MkdirAll(dir, 0o755); err != nil {
		h.presenter.OnHookError(err)
		return err
	}
	path := filepath.Join(dir, "pre-commit")
	existing, _ := h.fs.ReadFile(path)
	if !strings.Contains(string(existing), "#!/") {
		existing = []byte("#!/usr/bin/env sh\nset -e\n\n")
	}
	updated := injectMarkedBlock(string(existing), HookCommand+"\n")
	if err := h.fs.WriteFile(path, []byte(updated), 0o755); err != nil {
		h.presenter.OnHookError(err)
		return err
	}
	h.presenter.OnHookInstalled("native git hooks", path)
	return nil
}

func (h *Hook) uninstallNative(projectDir string) error {
	path := filepath.Join(projectDir, ".git", "hooks", "pre-commit")
	existing, err := h.fs.ReadFile(path)
	if err != nil {
		h.presenter.OnHookSkipped("no .git/hooks/pre-commit to clean")
		return nil
	}
	cleaned := stripMarkedBlock(string(existing))
	if err := h.fs.WriteFile(path, []byte(cleaned), 0o755); err != nil {
		h.presenter.OnHookError(err)
		return err
	}
	h.presenter.OnHookUninstalled("native git hooks", path)
	return nil
}

// --- Marker block helpers ----------------------------------------------

// injectMarkedBlock replaces an existing aegis-managed block (between
// markers) with a fresh one. If no block exists, appends one. This
// is what makes install idempotent.
func injectMarkedBlock(existing, body string) string {
	body = ensureTrailingNewline(body)
	block := hookMarkerStart + "\n" + body + hookMarkerEnd + "\n"
	if start := strings.Index(existing, hookMarkerStart); start >= 0 {
		end := strings.Index(existing[start:], hookMarkerEnd)
		if end >= 0 {
			endAbs := start + end + len(hookMarkerEnd)
			// Strip trailing newline from the replaced region too.
			if endAbs < len(existing) && existing[endAbs] == '\n' {
				endAbs++
			}
			return existing[:start] + block + existing[endAbs:]
		}
	}
	if existing != "" && !strings.HasSuffix(existing, "\n") {
		existing += "\n"
	}
	return existing + block
}

// stripMarkedBlock removes the aegis-managed block, leaving the rest
// of the file untouched. No-op when no block is present.
func stripMarkedBlock(existing string) string {
	start := strings.Index(existing, hookMarkerStart)
	if start < 0 {
		return existing
	}
	end := strings.Index(existing[start:], hookMarkerEnd)
	if end < 0 {
		return existing
	}
	endAbs := start + end + len(hookMarkerEnd)
	if endAbs < len(existing) && existing[endAbs] == '\n' {
		endAbs++
	}
	return existing[:start] + existing[endAbs:]
}

func ensureTrailingNewline(s string) string {
	if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s
}
