// Package config loads the project-level aegis.yml configuration file.
// CLI flags always take precedence over config values — the config file
// sets defaults that can be overridden per-invocation.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ConfigFile is the canonical config filename. Also accepts .aegis.yml.
const ConfigFile = "aegis.yml"

// Config is the project-level configuration loaded from aegis.yml.
// All fields are optional; zero values mean "use the built-in CLI default".
type Config struct {
	Version int           `yaml:"version"`
	CI      CIConfig      `yaml:"ci"`
	Actions ActionsConfig `yaml:"actions"`
}

// CIConfig holds defaults for `aegis ci`.
type CIConfig struct {
	// FailOn sets the default --fail-on verdict threshold.
	// Values: safe|review|prompt|block  (default: block)
	FailOn string `yaml:"fail_on"`

	// ScanActions enables --scan-actions by default.
	ScanActions bool `yaml:"scan_actions"`

	// SARIF enables --sarif output by default.
	SARIF bool `yaml:"sarif"`

	// NoEnrich disables AST enrichment by default (--no-enrich).
	NoEnrich bool `yaml:"no_enrich"`

	// ActionsFailOn sets the --actions-fail-on severity when --scan-actions is used.
	// Values: low|medium|high|critical  (default: high)
	ActionsFailOn string `yaml:"actions_fail_on"`
}

// ActionsConfig holds defaults for `aegis actions scan`.
type ActionsConfig struct {
	// FailOn sets the default --fail-on severity for actions scan.
	// Values: low|medium|high|critical  (default: high)
	FailOn string `yaml:"fail_on"`

	// Repo sets the default --repo (owner/repo) for remote scanning.
	Repo string `yaml:"repo"`
}

// Load reads aegis.yml (or .aegis.yml) from projectDir.
// Returns an empty Config (no error) when no file is found — config is
// entirely optional.
func Load(projectDir string) (Config, error) {
	path, err := findConfigFile(projectDir)
	if err != nil {
		return Config{}, nil // no file → empty config, no error
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.Version != 0 && cfg.Version != 1 {
		return Config{}, fmt.Errorf("%s: unsupported version %d (want 1)", path, cfg.Version)
	}
	if err := cfg.validate(path); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// validate checks that enum fields contain recognised values.
// Called immediately after unmarshal so bad config fails loudly at startup.
func (c Config) validate(path string) error {
	if c.CI.FailOn != "" {
		switch c.CI.FailOn {
		case "safe", "review", "prompt", "block":
		default:
			return fmt.Errorf("%s: ci.fail_on %q invalid — want safe|review|prompt|block", path, c.CI.FailOn)
		}
	}
	if c.CI.ActionsFailOn != "" {
		switch c.CI.ActionsFailOn {
		case "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("%s: ci.actions_fail_on %q invalid — want low|medium|high|critical", path, c.CI.ActionsFailOn)
		}
	}
	if c.Actions.FailOn != "" {
		switch c.Actions.FailOn {
		case "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("%s: actions.fail_on %q invalid — want low|medium|high|critical", path, c.Actions.FailOn)
		}
	}
	return nil
}

func findConfigFile(dir string) (string, error) {
	for _, name := range []string{ConfigFile, ".aegis.yml"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("config file not found")
}
