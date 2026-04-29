// Package audit records every Aegis decision the CLI makes, so users
// can answer "what did I install last week and what did Aegis say
// about it?" without round-tripping to a server.
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one audit record. NDJSON-encoded, one per line.
type Entry struct {
	Timestamp      time.Time `json:"ts"`
	PM             string    `json:"pm"`
	Ecosystem      string    `json:"ecosystem"`
	Package        string    `json:"package"`
	Version        string    `json:"version"`
	Decision       string    `json:"decision"`
	Severity       string    `json:"severity"`
	Source         string    `json:"source,omitempty"`
	OverrideUsed   bool      `json:"override,omitempty"`
	OverrideReason string    `json:"override_reason,omitempty"`
	AdvisoryID     string    `json:"advisory_id,omitempty"`
}

// Logger appends NDJSON entries to a file. Safe for concurrent use
// within a process.
type Logger struct {
	path string
	mu   sync.Mutex
}

// New returns a Logger at AEGIS_AUDIT_DIR/audit.jsonl (default
// ~/.aegis/audit.jsonl).
func New() *Logger {
	dir := os.Getenv("AEGIS_AUDIT_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".aegis")
	}
	return &Logger{path: filepath.Join(dir, "audit.jsonl")}
}

// NewAt builds a Logger at an explicit path. For tests.
func NewAt(path string) *Logger { return &Logger{path: path} }

// Path returns the on-disk audit file path.
func (l *Logger) Path() string { return l.path }

// Write appends one NDJSON entry. Errors here are NOT fatal to the
// caller — failing to write an audit row should not block an install.
// Callers commonly log-and-continue.
func (l *Logger) Write(e Entry) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

// Tail returns the last n entries, newest last. Used by `aegis audit
// tail`. If n <= 0 it returns everything.
func (l *Logger) Tail(n int) ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.Open(l.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var all []Entry
	s := bufio.NewScanner(f)
	// Audit lines can grow if reasons embed long detail strings; bump.
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		var e Entry
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			// Skip a single bad line rather than fail the whole tail —
			// otherwise one corrupted append breaks the audit forever.
			continue
		}
		all = append(all, e)
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("audit scan: %w", err)
	}
	if n <= 0 || n >= len(all) {
		return all, nil
	}
	return all[len(all)-n:], nil
}
