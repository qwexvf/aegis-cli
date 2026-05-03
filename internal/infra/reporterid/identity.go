// Package reporterid provides a stable, per-machine identifier the
// CLI uses when submitting community reports to the Aegis API.
//
// v1: a UUID generated once and persisted to ~/.aegis/reporter.id.
// Future: ed25519 keypair with signed report bodies and a public-key
// reporter ID. Today we deliberately keep it simple — the API will
// rate-limit by IP + reporter_id, and reputation accrues per-id.
package reporterid

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Identity satisfies usecase.ReporterIdentity.
type Identity struct {
	mu     sync.Mutex
	path   string
	cached string
}

// New returns an Identity. The location can be overridden by
// AEGIS_CONFIG_DIR (used in tests / per-user installs).
func New() *Identity {
	dir := os.Getenv("AEGIS_CONFIG_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		dir = filepath.Join(home, ".aegis")
	}
	return &Identity{path: filepath.Join(dir, "reporter.id")}
}

// ID returns the stable reporter id, generating + persisting one on
// first call. Cached in-memory after the first read.
func (i *Identity) ID() (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.cached != "" {
		return i.cached, nil
	}
	if data, err := os.ReadFile(i.path); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "" {
			i.cached = s
			return s, nil
		}
	}
	id, err := generate()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(i.path), 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", filepath.Dir(i.path), err)
	}
	if err := os.WriteFile(i.path, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", i.path, err)
	}
	i.cached = id
	return id, nil
}

// generate produces a UUIDv4-shaped 32-hex string (without dashes for
// transport simplicity). Crypto-strong via crypto/rand.
func generate() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	// Set the variant + version bits (RFC 4122 §4.4)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[:]), nil
}
