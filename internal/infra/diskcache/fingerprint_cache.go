package diskcache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
	"github.com/qwexvf/aegis/services/cli/internal/infra/atomicwrite"
)

// fingerprintDTO mirrors locksnap's wire-format for a Fingerprint but
// is duplicated here so each adapter owns its persistence shape.
// Conversions kept private to this package.
type fingerprintDTO struct {
	Analyzed        bool      `json:"analyzed,omitempty"`
	Capabilities    []string  `json:"capabilities,omitempty"`
	Hooks           []hookDTO `json:"hooks,omitempty"`
	EnvReads        []string  `json:"env_reads,omitempty"`
	SourceSizeBytes int       `json:"source_size_bytes,omitempty"`
	ASTSummaryHash  string    `json:"ast_summary_hash,omitempty"`
}

type hookDTO struct {
	Phase  string `json:"phase"`
	Source string `json:"source"`
	Sha256 string `json:"sha256,omitempty"`
}

func fpToDTO(fp domain.Fingerprint) fingerprintDTO {
	dto := fingerprintDTO{
		Analyzed:        fp.Analyzed,
		EnvReads:        fp.EnvReads,
		SourceSizeBytes: fp.SourceSizeBytes,
		ASTSummaryHash:  fp.ASTSummaryHash,
	}
	for _, c := range fp.Capabilities {
		dto.Capabilities = append(dto.Capabilities, c.String())
	}
	for _, h := range fp.Hooks {
		dto.Hooks = append(dto.Hooks, hookDTO{
			Phase: h.Phase.String(), Source: h.Source, Sha256: h.Sha256,
		})
	}
	return dto
}

func dtoToFp(dto fingerprintDTO) domain.Fingerprint {
	out := domain.Fingerprint{
		Analyzed:        dto.Analyzed,
		EnvReads:        dto.EnvReads,
		SourceSizeBytes: dto.SourceSizeBytes,
		ASTSummaryHash:  dto.ASTSummaryHash,
	}
	if len(dto.Capabilities) > 0 {
		caps := make([]domain.Capability, 0, len(dto.Capabilities))
		for _, n := range dto.Capabilities {
			for _, c := range domain.AllCapabilities() {
				if c.String() == n {
					caps = append(caps, c)
				}
			}
		}
		out.Capabilities = domain.NewCapabilitySet(caps...)
	}
	for _, h := range dto.Hooks {
		var phase domain.HookPhase
		switch h.Phase {
		case "preinstall":
			phase = domain.PhasePreInstall
		case "postinstall":
			phase = domain.PhasePostInstall
		case "build":
			phase = domain.PhaseBuild
		}
		out.Hooks = append(out.Hooks, domain.InstallHook{Phase: phase, Source: h.Source, Sha256: h.Sha256})
	}
	return out
}

// FingerprintCache stores AST scan results keyed by
// (ecosystem, name, version), one JSON file per (eco, name, version)
// at <cacheDir>/fingerprints/<eco>/<name>/<version>.json.
//
// Why JSON-per-file rather than a single decisions-style file:
// fingerprints are independent (one bad version's JSON corruption
// shouldn't poison the rest), and they can be inspected with `cat`.
// Atomic writes via temp+rename. Reads tolerate missing/corrupt files
// (treated as cache miss).
type FingerprintCache struct {
	dir string
}

// NewFingerprintCache returns a cache rooted at AEGIS_CACHE_DIR/
// fingerprints (default ~/.aegis/cache/fingerprints).
func NewFingerprintCache() *FingerprintCache {
	dir := os.Getenv("AEGIS_CACHE_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".aegis", "cache")
	}
	return &FingerprintCache{dir: filepath.Join(dir, "fingerprints")}
}

// NewFingerprintCacheAt builds a cache at an explicit dir. Tests.
func NewFingerprintCacheAt(dir string) *FingerprintCache {
	return &FingerprintCache{dir: dir}
}

// Get implements usecase.FingerprintCache.
func (c *FingerprintCache) Get(eco domain.Ecosystem, name, version string) (domain.Fingerprint, bool) {
	path := c.path(eco, name, version)
	body, err := os.ReadFile(path)
	if err != nil {
		return domain.Fingerprint{}, false
	}
	var dto fingerprintDTO
	if err := json.Unmarshal(body, &dto); err != nil {
		return domain.Fingerprint{}, false
	}
	return dtoToFp(dto), true
}

// Put implements usecase.FingerprintCache.
func (c *FingerprintCache) Put(eco domain.Ecosystem, name, version string, fp domain.Fingerprint) error {
	path := c.path(eco, name, version)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(fpToDTO(fp), "", "  ")
	if err != nil {
		return fmt.Errorf("fingerprint encode: %w", err)
	}
	return atomicwrite.WriteFile(path, body, 0o644)
}

// Path returns the on-disk file path for a given key. Useful for
// presenter / debug output.
func (c *FingerprintCache) Path(eco domain.Ecosystem, name, version string) string {
	return c.path(eco, name, version)
}

func (c *FingerprintCache) path(eco domain.Ecosystem, name, version string) string {
	return filepath.Join(c.dir, string(eco), filepath.FromSlash(name), version+".json")
}

// Clear removes the entire fingerprint cache. Missing-dir is fine.
func (c *FingerprintCache) Clear() error {
	if err := os.RemoveAll(c.dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
