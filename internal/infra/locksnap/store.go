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
	"os"
	"path/filepath"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/qwexvf/aegis/services/cli/internal/domain"
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

	compressed := s.encoder.EncodeAll(rawJSON, nil)

	path := s.Path(projectDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".aegis.lock.*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(compressed); err != nil {
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
	HasInstallScript    bool     `json:"has_install_script,omitempty"`
	InstallScriptSHA256 string   `json:"install_script_sha256,omitempty"`
	ShellCalls          int      `json:"shell_calls,omitempty"`
	NetCalls            int      `json:"net_calls,omitempty"`
	EnvReads            []string `json:"env_reads,omitempty"`
	FSWrites            int      `json:"fs_writes,omitempty"`
	ObfuscationScore    float64  `json:"obfuscation_score,omitempty"`
	ASTSummaryHash      string   `json:"ast_summary_hash,omitempty"`
	SourceSizeBytes     int      `json:"source_size_bytes,omitempty"`
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
			out.Deps[i].Fingerprint = &fingerprintDTO{
				HasInstallScript:    d.Fingerprint.HasInstallScript,
				InstallScriptSHA256: d.Fingerprint.InstallScriptSHA256,
				ShellCalls:          d.Fingerprint.ShellCalls,
				NetCalls:            d.Fingerprint.NetCalls,
				EnvReads:            d.Fingerprint.EnvReads,
				FSWrites:            d.Fingerprint.FSWrites,
				ObfuscationScore:    d.Fingerprint.ObfuscationScore,
				ASTSummaryHash:      d.Fingerprint.ASTSummaryHash,
				SourceSizeBytes:     d.Fingerprint.SourceSizeBytes,
			}
		}
	}
	return out
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
			out.Deps[i].Fingerprint = &domain.Fingerprint{
				HasInstallScript:    d.Fingerprint.HasInstallScript,
				InstallScriptSHA256: d.Fingerprint.InstallScriptSHA256,
				ShellCalls:          d.Fingerprint.ShellCalls,
				NetCalls:            d.Fingerprint.NetCalls,
				EnvReads:            d.Fingerprint.EnvReads,
				FSWrites:            d.Fingerprint.FSWrites,
				ObfuscationScore:    d.Fingerprint.ObfuscationScore,
				ASTSummaryHash:      d.Fingerprint.ASTSummaryHash,
				SourceSizeBytes:     d.Fingerprint.SourceSizeBytes,
			}
		}
	}
	return out
}
