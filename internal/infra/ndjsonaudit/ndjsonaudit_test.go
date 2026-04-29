package ndjsonaudit

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

func tmpWriter(t *testing.T) *Writer {
	t.Helper()
	return NewAt(filepath.Join(t.TempDir(), "audit.jsonl"))
}

func outcome(name, ver string, kind domain.DecisionKind, action domain.Action) domain.Outcome {
	return domain.Outcome{
		Decision: domain.Decision{
			Spec: domain.PackageSpec{
				Ecosystem: domain.EcoNpm,
				Name:      name,
				Version:   ver,
				Raw:       name + "@" + ver,
			},
			Resolved: ver,
			Kind:     kind,
			Severity: domain.SevInfo,
			Source:   domain.SourceAPI,
		},
		Action: action,
	}
}

func TestWriter_RoundTrip(t *testing.T) {
	w := tmpWriter(t)
	w.Write(outcome("lodash", "4.17.21", domain.DecisionAllow, domain.ActionProceed))
	w.Write(outcome("ua-parser-js", "0.7.29", domain.DecisionBlock, domain.ActionBlock))

	got, err := w.Tail(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[0].Package != "lodash" || got[1].Decision != "block" {
		t.Errorf("entries: %+v", got)
	}
}

func TestWriter_PreservesIncidentMetadata(t *testing.T) {
	w := tmpWriter(t)
	o := outcome("ua-parser-js", "0.7.29", domain.DecisionBlock, domain.ActionBlock)
	o.Decision.Incident = &domain.Incident{AdvisoryID: "GHSA-pjwm-rvh2-c87w"}
	w.Write(o)

	got, _ := w.Tail(0)
	if got[0].AdvisoryID != "GHSA-pjwm-rvh2-c87w" {
		t.Errorf("advisory ID lost: %+v", got[0])
	}
}

func TestWriter_TailLimit(t *testing.T) {
	w := tmpWriter(t)
	for i := 0; i < 5; i++ {
		w.Write(outcome("p", string(rune('a'+i)), domain.DecisionAllow, domain.ActionProceed))
	}
	got, _ := w.Tail(2)
	if len(got) != 2 || got[1].Version != "e" {
		t.Errorf("tail(2): %+v", got)
	}
}

func TestWriter_TailMissingFile(t *testing.T) {
	w := NewAt(filepath.Join(t.TempDir(), "nope.jsonl"))
	got, err := w.Tail(10)
	if err != nil || len(got) != 0 {
		t.Errorf("missing file: %d entries, err=%v", len(got), err)
	}
}

func TestWriter_ConcurrentWrites(t *testing.T) {
	w := tmpWriter(t)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w.Write(outcome("p", string(rune('a'+i%26)), domain.DecisionAllow, domain.ActionProceed))
		}(i)
	}
	wg.Wait()
	got, err := w.Tail(0)
	if err != nil {
		t.Fatalf("audit corrupt: %v", err)
	}
	if len(got) != 50 {
		t.Errorf("expected 50 entries, got %d", len(got))
	}
}
