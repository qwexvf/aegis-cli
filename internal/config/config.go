// Package config loads and exposes the user-level aegis configuration
// from ~/.aegis/config.yaml (or $AEGIS_CONFIG_DIR/config.yaml).
//
// The file is optional — all fields have sensible defaults that mirror
// the existing env-var behaviour. When the file is absent, Load returns
// a zero Config and nil error.
//
// Env vars always take precedence over file values so CI pipelines can
// override without touching the file.
package config

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is the top-level shape of ~/.aegis/config.yaml.
type Config struct {
	Version int        `yaml:"version"`
	Vuln    VulnConfig `yaml:"vuln"`
}

// VulnConfig controls which vulnerability providers are queried and
// in what order. All enabled providers are queried concurrently and
// their results merged (union, deduplicated by advisory ID).
type VulnConfig struct {
	// Sources lists the enabled providers in preference order.
	// When empty the runtime falls back to the env-var heuristic
	// (AEGIS_VULN_SOURCE / AEGIS_API_KEY) for backwards compat.
	Sources []SourceConfig `yaml:"sources"`
}

// SourceConfig configures one vulnerability provider.
type SourceConfig struct {
	// Name is the provider identifier: "osv", "github", "deps.dev", "aegis".
	Name string `yaml:"name"`

	// URL overrides the provider's default base URL.
	// Useful for self-hosted OSV mirrors.
	URL string `yaml:"url,omitempty"`

	// Token is the auth token for providers that need one.
	// For "github": a personal access token (public_repo scope is enough).
	// Env-var override: GITHUB_TOKEN.
	Token string `yaml:"token,omitempty"`

	// APIKey is the Aegis API key for the "aegis" provider.
	// Env-var override: AEGIS_API_KEY.
	APIKey string `yaml:"api_key,omitempty"`
}

// Load reads the config file from the standard location. Returns a
// zero Config (not an error) when the file does not exist.
func Load() (Config, error) {
	path := Path()
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, err
	}
	applyEnvOverrides(&cfg)
	return cfg, nil
}

// Path returns the canonical config file path.
func Path() string {
	if dir := os.Getenv("AEGIS_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "config.yaml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".aegis/config.yaml"
	}
	return filepath.Join(home, ".aegis", "config.yaml")
}

// applyEnvOverrides lets env vars win over file values. Token fields
// are only overridden when the env var is non-empty so an explicit
// empty string in the file isn't accidentally overwritten.
func applyEnvOverrides(cfg *Config) {
	for i := range cfg.Vuln.Sources {
		s := &cfg.Vuln.Sources[i]
		switch s.Name {
		case "github":
			if t := os.Getenv("GITHUB_TOKEN"); t != "" {
				s.Token = t
			}
		case "aegis":
			if k := os.Getenv("AEGIS_API_KEY"); k != "" {
				s.APIKey = k
			}
		case "osv":
			if u := os.Getenv("AEGIS_OSV_URL"); u != "" {
				s.URL = u
			}
		}
	}
}
