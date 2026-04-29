package audit

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func tmpLogger(t *testing.T) *Logger {
	t.Helper()
	dir := t.TempDir()
	return NewAt(filepath.Join(dir, "audit.jsonl"))
}

func TestAudit_WriteThenTail(t *testing.T) {
	l := tmpLogger(t)
	entries := []Entry{
		{PM: "npm", Package: "lodash", Version: "4.17.21", Decision: "allow", Severity: "info"},
		{PM: "bun", Package: "ua-parser-js", Version: "0.7.29", Decision: "block", Severity: "critical", AdvisoryID: "GHSA-pjwm-rvh2-c87w"},
		{PM: "yarn", Package: "node-ipc", Version: "10.1.2", Decision: "block", Severity: "high", OverrideUsed: true, OverrideReason: "audit"},
	}
	for _, e := range entries {
		if err := l.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	got, err := l.Tail(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(got))
	}
	if got[0].Package != "lodash" || got[1].AdvisoryID != "GHSA-pjwm-rvh2-c87w" {
		t.Errorf("entries lost data on roundtrip: %+v", got)
	}
	if got[2].OverrideUsed != true || got[2].OverrideReason != "audit" {
		t.Errorf("override fields lost: %+v", got[2])
	}
}

func TestAudit_TailLimitsCount(t *testing.T) {
	l := tmpLogger(t)
	for i := 0; i < 5; i++ {
		l.Write(Entry{PM: "npm", Package: "p", Version: string(rune('a' + i)), Decision: "allow"})
	}
	got, err := l.Tail(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	// Newest last — last should be version "e" (the 5th appended).
	if got[1].Version != "e" {
		t.Errorf("last entry was %q, want %q", got[1].Version, "e")
	}
}

func TestAudit_TailMissingFileReturnsEmpty(t *testing.T) {
	l := NewAt(filepath.Join(t.TempDir(), "no-such-file.jsonl"))
	got, err := l.Tail(10)
	if err != nil {
		t.Errorf("Tail on missing file errored: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty, got %d entries", len(got))
	}
}

func TestAudit_BadLineSkipped(t *testing.T) {
	l := tmpLogger(t)
	l.Write(Entry{PM: "npm", Package: "lodash"})
	// Append a malformed line — Tail must skip it, not bail.
	f, _ := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("this is not json\n")
	f.Close()
	l.Write(Entry{PM: "npm", Package: "react"})

	got, _ := l.Tail(0)
	if len(got) != 2 {
		t.Errorf("expected 2 valid entries (bad one skipped), got %d", len(got))
	}
}

func TestAudit_ConcurrentWrites(t *testing.T) {
	l := tmpLogger(t)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l.Write(Entry{PM: "npm", Package: "p", Version: string(rune('a' + i%26)), Decision: "allow"})
		}(i)
	}
	wg.Wait()
	got, err := l.Tail(0)
	if err != nil {
		t.Fatalf("audit corrupt: %v", err)
	}
	if len(got) != 50 {
		t.Errorf("expected 50 entries, got %d", len(got))
	}
}
