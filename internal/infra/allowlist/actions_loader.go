package allowlist

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// ActionsIgnoreFile is the project-level actions ignore filename.
const ActionsIgnoreFile = ".aegis-actions-allowlist.yaml"

type actionsIgnoreYAML struct {
	Version int `yaml:"version"`
	Rules   []struct {
		Kind   string `yaml:"kind"`
		File   string `yaml:"file"`
		Reason string `yaml:"reason"`
	} `yaml:"rules"`
}

// LoadActionsIgnore reads the actions ignore file from projectDir.
// Returns an empty (no-op) set when the file does not exist.
//
// File format (.aegis-actions-allowlist.yaml):
//
//	version: 1
//	rules:
//	  - kind: unpinned_ref
//	    file: .github/workflows/release.yml  # optional; omit to match all files
//	    reason: "audited, known pinned via dependabot"
//	  - kind: "*"                             # suppress all findings in one file
//	    file: .github/workflows/legacy.yml
//	    reason: "legacy workflow, not in production path"
func LoadActionsIgnore(projectDir string) (domain.ActionsIgnoreSet, error) {
	path := filepath.Join(projectDir, ActionsIgnoreFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return domain.NewActionsIgnoreSet(nil), nil
		}
		return domain.ActionsIgnoreSet{}, fmt.Errorf("read %s: %w", path, err)
	}
	var raw actionsIgnoreYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return domain.ActionsIgnoreSet{}, fmt.Errorf("parse %s: %w", path, err)
	}
	rules := make([]domain.ActionsIgnoreRule, 0, len(raw.Rules))
	for _, r := range raw.Rules {
		rules = append(rules, domain.ActionsIgnoreRule{
			Kind:   r.Kind,
			File:   r.File,
			Reason: r.Reason,
		})
	}
	return domain.NewActionsIgnoreSet(rules), nil
}
