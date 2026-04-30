// Package ndjsonaudit satisfies usecase.AuditWriter by appending one
// NDJSON record per outcome. The on-disk shape is defined here so the
// rest of the codebase doesn't carry JSON-tagged domain types.
package ndjsonaudit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
	"github.com/qwexvf/aegis/services/cli/internal/infra/flock"
)

// Writer appends NDJSON entries to a file.
type Writer struct {
	path string
	mu   sync.Mutex
	now  func() time.Time // injectable for tests

	// Provenance, set via WithProvenance. All optional — empty values
	// are simply omitted from the output (the JSON shape stays stable
	// for old readers).
	aegisVersion string
	invocationID string
	projectDir   string
}

// New returns a Writer at AEGIS_AUDIT_DIR/audit.jsonl (default
// ~/.aegis/audit.jsonl).
func New() *Writer {
	dir := os.Getenv("AEGIS_AUDIT_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".aegis")
	}
	return &Writer{
		path: filepath.Join(dir, "audit.jsonl"),
		now:  func() time.Time { return time.Now().UTC() },
	}
}

// NewAt builds a Writer at an explicit path. For tests.
func NewAt(path string) *Writer {
	return &Writer{
		path: path,
		now:  func() time.Time { return time.Now().UTC() },
	}
}

// WithProvenance attaches per-process context that gets stamped on
// every audit entry. Additive: empty strings are omitted from the
// JSON, so callers may pass "" for fields they don't have. Returns
// the receiver for chaining at composition root.
func (w *Writer) WithProvenance(aegisVersion, invocationID, projectDir string) *Writer {
	w.aegisVersion = aegisVersion
	w.invocationID = invocationID
	w.projectDir = projectDir
	return w
}

// Path returns the on-disk audit file path.
func (w *Writer) Path() string { return w.path }

// Write implements usecase.AuditWriter. Best-effort — failures here
// must NOT abort an install (the caller logs and continues).
//
// Concurrency: the per-process mutex protects against in-process
// races; the per-file flock protects against parallel `aegis`
// invocations (e.g. CI matrix jobs) that would otherwise interleave
// NDJSON lines and corrupt the audit log.
func (w *Writer) Write(o domain.Outcome) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(w.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	unlock, err := flock.LockExclusive(f)
	if err != nil {
		return fmt.Errorf("audit flock: %w", err)
	}
	defer unlock()

	dto := w.fromDomain(o)
	b, err := json.Marshal(dto)
	if err != nil {
		return err
	}
	// Single Write call after flock — POSIX guarantees the append
	// reaches the file at the current end-of-file under O_APPEND, so
	// the lock + single write is sufficient for atomicity.
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

// Tail returns the last n entries, oldest first within the slice. If
// n <= 0 it returns everything. Used by `aegis audit tail`.
func (w *Writer) Tail(n int) ([]Entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	f, err := os.Open(w.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var all []Entry
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		var dto entryDTO
		if err := json.Unmarshal(s.Bytes(), &dto); err != nil {
			continue // skip a single bad line; one corrupt append shouldn't break tail
		}
		all = append(all, dto.toEntry())
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("audit scan: %w", err)
	}
	if n <= 0 || n >= len(all) {
		return all, nil
	}
	return all[len(all)-n:], nil
}

// Entry is the user-facing view of one audit row (what `aegis audit
// tail` shows). It mirrors entryDTO without JSON tags.
type Entry struct {
	Timestamp      time.Time
	Ecosystem      string
	Package        string
	Version        string
	Decision       string
	Severity       string
	Action         string
	Source         string
	OverrideUsed   bool
	OverrideReason string
	AdvisoryID     string
	AegisVersion   string
	InvocationID   string
	ProjectDir     string
}

// --- DTOs -------------------------------------------------------------

type entryDTO struct {
	Timestamp      time.Time `json:"ts"`
	Ecosystem      string    `json:"ecosystem"`
	Package        string    `json:"package"`
	Version        string    `json:"version"`
	Decision       string    `json:"decision,omitempty"`
	Severity       string    `json:"severity,omitempty"`
	Action         string    `json:"action"`
	Source         string    `json:"source,omitempty"`
	OverrideUsed   bool      `json:"override,omitempty"`
	OverrideReason string    `json:"override_reason,omitempty"`
	AdvisoryID     string    `json:"advisory_id,omitempty"`
	AegisVersion   string    `json:"aegis_version,omitempty"`
	InvocationID   string    `json:"cli_invocation_id,omitempty"`
	ProjectDir     string    `json:"project_dir,omitempty"`
}

func (w *Writer) fromDomain(o domain.Outcome) entryDTO {
	dto := entryDTO{
		Timestamp:      w.now(),
		Ecosystem:      string(o.Decision.Spec.Ecosystem),
		Package:        o.Decision.Spec.Name,
		Version:        o.Decision.Resolved,
		Decision:       string(o.Decision.Kind),
		Severity:       string(o.Decision.Severity),
		Action:         actionName(o.Action),
		Source:         string(o.Decision.Source),
		OverrideUsed:   o.OverrideUsed,
		OverrideReason: o.OverrideReason,
		AegisVersion:   w.aegisVersion,
		InvocationID:   w.invocationID,
		ProjectDir:     w.projectDir,
	}
	if o.Decision.Incident != nil {
		dto.AdvisoryID = o.Decision.Incident.AdvisoryID
	}
	return dto
}

func (d entryDTO) toEntry() Entry {
	// Field shapes are identical (entryDTO only adds json tags); a
	// direct conversion preserves all values without enumerating
	// fields. staticcheck S1016.
	return Entry(d)
}

func actionName(a domain.Action) string {
	switch a {
	case domain.ActionProceed:
		return "proceed"
	case domain.ActionBlock:
		return "block"
	case domain.ActionAskUser:
		return "ask"
	}
	return "unknown"
}
