package allowlist

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

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
}

// New builds a Loader using AEGIS_CONFIG_DIR or ~/.aegis for the user
// scope and projectDir for the project scope. projectDir may be empty
// (e.g. for `aegis allowlist list` when not in a project) — in which
// case the project layer is skipped.
func New(projectDir string) *Loader {
	user := os.Getenv("AEGIS_CONFIG_DIR")
	if user == "" {
		home, _ := os.UserHomeDir()
		user = filepath.Join(home, ".aegis")
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

// AddRule appends a rule to the user or project file. Existing rules
// in the file are preserved. The rule's Source field is overwritten
// with the scope name on the way out.
//
// Validation: the rule must satisfy NewAllowSet's checks (ecosystem
// non-empty, name non-empty, semver valid). The check uses a
// single-rule AllowSet so we get the same error path everywhere.
func (l *Loader) AddRule(scope Scope, r domain.AllowRule) error {
	r.Source = scope.String()
	if _, err := domain.NewAllowSet([]domain.AllowRule{r}); err != nil {
		return err
	}
	path, ok := l.pathFor(scope)
	if !ok {
		return fmt.Errorf("scope %s not available (no project dir)", scope)
	}

	existing, err := l.readFile(path, scope.String())
	if err != nil {
		return err
	}
	updated := append(existing, r)

	return l.writeFile(path, updated)
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
