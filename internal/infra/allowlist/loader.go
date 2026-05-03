package allowlist

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

// VerifyResult is one row in the per-file verification output.
// Path == "" indicates the (synthetic) builtin scope.
type VerifyResult struct {
	Source    string // "builtin" | "user" | "project"
	Path      string
	RuleCount int
	Err       error
}

// Verify parses each layer independently and reports per-file
// success/failure. Used by `aegis allowlist verify` to give the user
// a hard pass/fail per file rather than the merged-set view of Load.
//
// The builtin layer always succeeds (verified at compile time via
// builtin_allowlist_test.go) but is reported for completeness.
func (l *Loader) Verify() []VerifyResult {
	results := []VerifyResult{
		{Source: "builtin", RuleCount: len(domain.BuiltinAllowRules())},
	}
	results = append(results, l.verifyOne("user", l.UserPath()))
	if l.projectDir != "" {
		results = append(results, l.verifyOne("project", l.ProjectPath()))
	}
	return results
}

func (l *Loader) verifyOne(source, path string) VerifyResult {
	rules, err := l.readFile(path, source)
	if err != nil {
		return VerifyResult{Source: source, Path: path, Err: err}
	}
	return VerifyResult{Source: source, Path: path, RuleCount: len(rules)}
}

// Scope identifies which allowlist file an Add/Remove targets.
type Scope int

const (
	// ScopeUser writes to ~/.aegis/allowlist.yaml — personal, not
	// committed.
	ScopeUser Scope = iota + 1
	// ScopeProject writes to <projectDir>/.aegis-allowlist.yaml —
	// team-shared via git.
	ScopeProject
)

// String returns the canonical name for serialization / display.
func (s Scope) String() string {
	switch s {
	case ScopeUser:
		return "user"
	case ScopeProject:
		return "project"
	}
	return "unknown"
}

// ScopeFromString parses a scope name. Returns 0 + false on unknown.
func ScopeFromString(s string) (Scope, bool) {
	switch s {
	case "user":
		return ScopeUser, true
	case "project":
		return ScopeProject, true
	}
	return 0, false
}

// ProjectFileName is the canonical project-level allowlist filename
// (lives at the project root). Committed to git.
const ProjectFileName = ".aegis-allowlist.yaml"

// UserFileName lives under AEGIS_CONFIG_DIR (or ~/.aegis/).
const UserFileName = "allowlist.yaml"

// Loader resolves and merges allowlist sources. Construct via New.
type Loader struct {
	userDir    string // dir containing UserFileName
	projectDir string // dir containing ProjectFileName
	server     *ServerLoader
}

// WithServer attaches a ServerLoader so Load/LoadRaw layer in the
// org-fetched cache between the user and project files. When nil
// (the default), the server layer is skipped — same behavior as
// before this method existed. Returns the loader for chaining.
func (l *Loader) WithServer(s *ServerLoader) *Loader {
	l.server = s
	return l
}

// Server returns the attached ServerLoader (or nil). Used by the
// `aegis allowlist sync` subcommand to reach the network from a
// place that already has the loader.
func (l *Loader) Server() *ServerLoader { return l.server }

// New builds a Loader using AEGIS_CONFIG_DIR or ~/.aegis for the user
// scope and projectDir for the project scope. projectDir may be empty
// (e.g. for `aegis allowlist list` when not in a project) — in which
// case the project layer is skipped.
//
// If both AEGIS_CONFIG_DIR is unset AND os.UserHomeDir() fails (rare:
// no $HOME and no /etc/passwd entry, common in some container
// images), the user dir falls back to ".aegis" relative to cwd. We
// surface a one-line warning to stderr so the user sees the surprise
// rather than silently writing into their cwd.
func New(projectDir string) *Loader {
	user := os.Getenv("AEGIS_CONFIG_DIR")
	if user == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			slog.Warn("cannot determine user home directory; falling back to ./.aegis (set AEGIS_CONFIG_DIR to override)", "error", err)
			user = ".aegis"
		} else {
			user = filepath.Join(home, ".aegis")
		}
	}
	return &Loader{userDir: user, projectDir: projectDir}
}

// UserPath returns the user-scope file path.
func (l *Loader) UserPath() string { return filepath.Join(l.userDir, UserFileName) }

// ProjectPath returns the project-scope file path. Empty if the
// loader was constructed without a project dir.
func (l *Loader) ProjectPath() string {
	if l.projectDir == "" {
		return ""
	}
	return filepath.Join(l.projectDir, ProjectFileName)
}

// Load reads builtin + user + project rules and returns the merged,
// validated AllowSet. Missing files are not errors — they silently
// contribute zero rules. Malformed files DO error so the user sees
// the typo immediately.
//
// Order: builtin first, then user, then project. Earlier rules win
// for AllowSet.Suppresses (returns the first match), so the layering
// allows project to override user to override builtin via a wildcard.
// (More-specific rules earlier > broad later; users add specific ones
// to their layer to escape a builtin.)
func (l *Loader) Load() (domain.AllowSet, error) {
	all := []domain.AllowRule{}
	all = append(all, domain.BuiltinAllowRules()...)

	if rules, err := l.readFile(l.UserPath(), "user"); err != nil {
		return domain.AllowSet{}, fmt.Errorf("user allowlist: %w", err)
	} else {
		all = append(all, rules...)
	}

	// Server layer sits between user and project so org-wide rules
	// override personal ones (governance > individual choice) but
	// per-project files always win for repo-specific overrides.
	// A corrupt cache logs a warning and contributes zero rules
	// rather than failing the install.
	if l.server != nil {
		if rules, err := l.server.Load(); err != nil {
			slog.Warn("server allowlist cache load failed; skipping server layer", "error", err)
		} else {
			all = append(all, rules...)
		}
	}

	if l.projectDir != "" {
		if rules, err := l.readFile(l.ProjectPath(), "project"); err != nil {
			return domain.AllowSet{}, fmt.Errorf("project allowlist: %w", err)
		} else {
			all = append(all, rules...)
		}
	}

	return domain.NewAllowSet(all)
}

// LoadRaw returns the unmerged rule list (no AllowSet validation).
// Used by `aegis allowlist list` to display rules per source.
func (l *Loader) LoadRaw() ([]domain.AllowRule, error) {
	all := []domain.AllowRule{}
	all = append(all, domain.BuiltinAllowRules()...)
	if rules, err := l.readFile(l.UserPath(), "user"); err != nil {
		return nil, err
	} else {
		all = append(all, rules...)
	}
	if l.server != nil {
		if rules, err := l.server.Load(); err != nil {
			// Same defensive read as Load — `aegis allowlist list`
			// shouldn't blow up on a stale cache; surface a warning
			// and proceed.
			slog.Warn("server allowlist cache load failed; skipping server layer", "error", err)
		} else {
			all = append(all, rules...)
		}
	}
	if l.projectDir != "" {
		if rules, err := l.readFile(l.ProjectPath(), "project"); err != nil {
			return nil, err
		} else {
			all = append(all, rules...)
		}
	}
	return all, nil
}

func (l *Loader) readFile(path, source string) ([]domain.AllowRule, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return decodeFile(body, source)
}

// AddRule appends or replaces a rule in the user or project file.
// Existing rules in the file are preserved. The rule's Source field
// is overwritten with the scope name on the way out.
//
// Deduplication: if the file already contains a rule with the same
// (Ecosystem, Name, VersionRange, Capability) key, the existing rule
// is replaced (the second return value `replaced` is true). This
// prevents the file from accumulating duplicates as users iterate.
//
// Validation: the rule must satisfy NewAllowSet's checks (ecosystem
// non-empty, name non-empty, semver valid). The check uses a
// single-rule AllowSet so we get the same error path everywhere.
func (l *Loader) AddRule(scope Scope, r domain.AllowRule) (replaced bool, err error) {
	r.Source = scope.String()
	if _, verr := domain.NewAllowSet([]domain.AllowRule{r}); verr != nil {
		return false, verr
	}
	path, ok := l.pathFor(scope)
	if !ok {
		return false, fmt.Errorf("scope %s not available (no project dir)", scope)
	}

	existing, rerr := l.readFile(path, scope.String())
	if rerr != nil {
		return false, rerr
	}

	// Replace by key if present; else append.
	updated := make([]domain.AllowRule, 0, len(existing)+1)
	for _, e := range existing {
		if sameRuleKey(e, r) {
			replaced = true
			continue
		}
		updated = append(updated, e)
	}
	updated = append(updated, r)

	return replaced, l.writeFile(path, updated)
}

// sameRuleKey reports whether two rules collide on the dedup key
// (Ecosystem, Name, VersionRange, Capability). Reason and Source are
// not part of the key.
func sameRuleKey(a, b domain.AllowRule) bool {
	return a.Ecosystem == b.Ecosystem &&
		a.Name == b.Name &&
		a.VersionRange == b.VersionRange &&
		a.Capability == b.Capability
}

// RemoveRule deletes rules matching predicate from the scope's file.
// Returns the number of rules removed. Predicates run against the
// rule as it was loaded (Source field already set).
func (l *Loader) RemoveRule(scope Scope, predicate func(domain.AllowRule) bool) (int, error) {
	path, ok := l.pathFor(scope)
	if !ok {
		return 0, fmt.Errorf("scope %s not available", scope)
	}
	existing, err := l.readFile(path, scope.String())
	if err != nil {
		return 0, err
	}
	kept := make([]domain.AllowRule, 0, len(existing))
	removed := 0
	for _, r := range existing {
		if predicate(r) {
			removed++
			continue
		}
		kept = append(kept, r)
	}
	if removed == 0 {
		return 0, nil
	}
	if len(kept) == 0 {
		// File is now empty of rules. Remove the file entirely so a
		// fresh checkout doesn't carry around a stub.
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		return removed, nil
	}
	return removed, l.writeFile(path, kept)
}

// pathFor returns the on-disk path for a scope. ScopeProject errors
// when projectDir is empty.
func (l *Loader) pathFor(scope Scope) (string, bool) {
	switch scope {
	case ScopeUser:
		return l.UserPath(), true
	case ScopeProject:
		if l.projectDir == "" {
			return "", false
		}
		return l.ProjectPath(), true
	}
	return "", false
}

// writeFile serializes rules and writes them to path atomically.
func (l *Loader) writeFile(path string, rules []domain.AllowRule) error {
	body, err := encodeFile(rules)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".allowlist.*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}
