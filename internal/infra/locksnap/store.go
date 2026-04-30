// Package locksnap is the snapshot persistence + lockfile-scanning
// adapter. It satisfies usecase.SnapshotStore and
// usecase.LockfileScanner.
//
// On-disk format: zstd-compressed JSON at <projectDir>/aegis.lock.
// Single file, atomic write via temp+rename. The JSON shape is
// documented in fileSchema below; readers ignore unknown fields so
// new optional fields don't bump SchemaVersion.
package locksnap

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/qwexvf/aegis/services/cli/internal/domain"
	"github.com/qwexvf/aegis/services/cli/internal/infra/atomicwrite"
)

// LockfileName is the canonical project-root snapshot filename. It is
// committed to the repository (like Cargo.lock).
const LockfileName = "aegis.lock"

// Store is a SnapshotStore implementation backed by a zstd-compressed
// JSON file at <projectDir>/aegis.lock.
type Store struct {
	encoder *zstd.Encoder
	decoder *zstd.Decoder
}

// NewStore builds a Store with shared encoder/decoder instances.
// They are safe for concurrent use across goroutines.
func NewStore() (*Store, error) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
	if err != nil {
		return nil, err
	}
	dec, err := zstd.NewReader(nil)
	if err != nil {
		enc.Close()
		return nil, err
	}
	return &Store{encoder: enc, decoder: dec}, nil
}

// Path returns the canonical snapshot path for projectDir.
func (s *Store) Path(projectDir string) string {
	return filepath.Join(projectDir, LockfileName)
}

// Save implements usecase.SnapshotStore.
func (s *Store) Save(projectDir string, snap domain.Snapshot) error {
	dto := fromDomain(snap)
	rawJSON, err := json.MarshalIndent(dto, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	path := s.Path(projectDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return atomicwrite.WriteFileFunc(path, 0o644, func(w io.Writer) error {
		compressed := s.encoder.EncodeAll(rawJSON, nil)
		_, err := w.Write(compressed)
		return err
	})
}

// Load implements usecase.SnapshotStore. Missing-file returns
// (zero, false, nil).
func (s *Store) Load(projectDir string) (domain.Snapshot, bool, error) {
	snap, err := s.LoadFile(s.Path(projectDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return domain.Snapshot{}, false, nil
		}
		return domain.Snapshot{}, false, err
	}
	return snap, true, nil
}

// LoadFile reads a snapshot from an explicit path. Used for `aegis
// snapshot diff <a> <b>`.
func (s *Store) LoadFile(path string) (domain.Snapshot, error) {
	compressed, err := os.ReadFile(path)
	if err != nil {
		return domain.Snapshot{}, err
	}
	rawJSON, err := s.decoder.DecodeAll(compressed, nil)
	if err != nil {
		// Tolerate plain JSON files for tests / debugging.
		if isPlainJSON(compressed) {
			rawJSON = compressed
		} else {
			return domain.Snapshot{}, fmt.Errorf("decompress %s: %w", path, err)
		}
	}
	var dto fileSchema
	if err := json.Unmarshal(rawJSON, &dto); err != nil {
		return domain.Snapshot{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return dto.toDomain(), nil
}

// Close releases the encoder/decoder. Optional — at process exit they
// are GC'd anyway.
func (s *Store) Close() {
	_ = s.encoder.Close()
	s.decoder.Close()
}

func isPlainJSON(b []byte) bool {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// --- on-disk DTOs -----------------------------------------------------

type fileSchema struct {
	SchemaVersion int             `json:"schema_version"`
	CreatedAt     time.Time       `json:"created_at"`
	AegisVersion  string          `json:"aegis_version,omitempty"`
	Project       string          `json:"project,omitempty"`
	Deps          []dependencyDTO `json:"deps"`
}

type dependencyDTO struct {
	Ecosystem   string          `json:"ecosystem"`
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Integrity   string          `json:"integrity,omitempty"`
	Direct      bool            `json:"direct,omitempty"`
	Fingerprint *fingerprintDTO `json:"fp,omitempty"`
}

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

func fromDomain(s domain.Snapshot) fileSchema {
	out := fileSchema{
		SchemaVersion: s.SchemaVersion,
		CreatedAt:     s.CreatedAt,
		AegisVersion:  s.AegisVersion,
		Project:       s.Project,
		Deps:          make([]dependencyDTO, len(s.Deps)),
	}
	for i, d := range s.Deps {
		out.Deps[i] = dependencyDTO{
			Ecosystem: string(d.Ecosystem),
			Name:      d.Name,
			Version:   d.Version,
			Integrity: d.Integrity,
			Direct:    d.Direct,
		}
		if d.Fingerprint != nil {
			out.Deps[i].Fingerprint = fpToDTO(*d.Fingerprint)
		}
	}
	return out
}

func fpToDTO(fp domain.Fingerprint) *fingerprintDTO {
	dto := &fingerprintDTO{
		Analyzed:        fp.Analyzed,
		EnvReads:        fp.EnvReads,
		SourceSizeBytes: fp.SourceSizeBytes,
		ASTSummaryHash:  fp.ASTSummaryHash,
	}
	if len(fp.Capabilities) > 0 {
		dto.Capabilities = make([]string, len(fp.Capabilities))
		for i, c := range fp.Capabilities {
			dto.Capabilities[i] = c.String()
		}
	}
	if len(fp.Hooks) > 0 {
		dto.Hooks = make([]hookDTO, len(fp.Hooks))
		for i, h := range fp.Hooks {
			dto.Hooks[i] = hookDTO{Phase: h.Phase.String(), Source: h.Source, Sha256: h.Sha256}
		}
	}
	return dto
}

func (s fileSchema) toDomain() domain.Snapshot {
	out := domain.Snapshot{
		SchemaVersion: s.SchemaVersion,
		CreatedAt:     s.CreatedAt,
		AegisVersion:  s.AegisVersion,
		Project:       s.Project,
		Deps:          make([]domain.Dependency, len(s.Deps)),
	}
	for i, d := range s.Deps {
		out.Deps[i] = domain.Dependency{
			Ecosystem: domain.Ecosystem(d.Ecosystem),
			Name:      d.Name,
			Version:   d.Version,
			Integrity: d.Integrity,
			Direct:    d.Direct,
		}
		if d.Fingerprint != nil {
			fp := dtoToFp(*d.Fingerprint)
			out.Deps[i].Fingerprint = &fp
		}
	}
	return out
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
		for _, name := range dto.Capabilities {
			if c := capabilityFromString(name); c != 0 {
				caps = append(caps, c)
			}
		}
		out.Capabilities = domain.NewCapabilitySet(caps...)
	}
	if len(dto.Hooks) > 0 {
		out.Hooks = make([]domain.InstallHook, 0, len(dto.Hooks))
		for _, h := range dto.Hooks {
			out.Hooks = append(out.Hooks, domain.InstallHook{
				Phase:  hookPhaseFromString(h.Phase),
				Source: h.Source,
				Sha256: h.Sha256,
			})
		}
	}
	return out
}

func capabilityFromString(s string) domain.Capability {
	for _, c := range domain.AllCapabilities() {
		if c.String() == s {
			return c
		}
	}
	return 0
}

func hookPhaseFromString(s string) domain.HookPhase {
	switch s {
	case "preinstall":
		return domain.PhasePreInstall
	case "postinstall":
		return domain.PhasePostInstall
	case "build":
		return domain.PhaseBuild
	}
	return 0
}
