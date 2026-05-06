package vulnlookup

import (
	"context"
	"errors"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type stubLookup struct {
	out map[string][]domain.Advisory
	err error
}

func (s stubLookup) Lookup(_ context.Context, _ []domain.AdvisoryQuery) (map[string][]domain.Advisory, error) {
	return s.out, s.err
}

func key(eco, name, ver string) string {
	return domain.AdvisoryQuery{Ecosystem: domain.Ecosystem(eco), Name: name, Version: ver}.Key()
}

func TestFallback_BothNil(t *testing.T) {
	out, err := Fallback{}.Lookup(context.Background(), nil)
	if err != nil || out != nil {
		t.Errorf("both nil should be a no-op, got %v / %v", out, err)
	}
}

func TestFallback_PrimaryNilFallsToSecondary(t *testing.T) {
	want := map[string][]domain.Advisory{key("npm", "x", "1"): {{ID: "GHSA-1"}}}
	f := Fallback{Secondary: stubLookup{out: want}}
	out, err := f.Lookup(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Errorf("got %v, want %v", out, want)
	}
}

func TestFallback_PrimarySucceeds_NoSecondaryCall(t *testing.T) {
	want := map[string][]domain.Advisory{key("npm", "x", "1"): {{ID: "PRIMARY"}}}
	called := false
	f := Fallback{
		Primary:   stubLookup{out: want},
		Secondary: stubLookup{out: map[string][]domain.Advisory{key("npm", "x", "1"): {{ID: "WRONG"}}}},
		Logger:    func(string, ...any) { called = true },
	}
	out, err := f.Lookup(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := out[key("npm", "x", "1")][0].ID; got != "PRIMARY" {
		t.Errorf("got id=%q, want PRIMARY", got)
	}
	if called {
		t.Error("logger should not have fired (primary succeeded)")
	}
}

func TestFallback_PrimaryFailsSecondaryAnswers(t *testing.T) {
	want := map[string][]domain.Advisory{key("npm", "x", "1"): {{ID: "SECONDARY"}}}
	logged := ""
	f := Fallback{
		Primary:   stubLookup{err: errors.New("aegis api: 503")},
		Secondary: stubLookup{out: want},
		Logger:    func(format string, args ...any) { logged = format },
	}
	out, err := f.Lookup(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := out[key("npm", "x", "1")][0].ID; got != "SECONDARY" {
		t.Errorf("got id=%q, want SECONDARY", got)
	}
	if logged == "" {
		t.Error("logger should have fired on fallback")
	}
}

func TestFallback_BothFail_WrappedError(t *testing.T) {
	f := Fallback{
		Primary:   stubLookup{err: errors.New("PRIMARY-FAIL")},
		Secondary: stubLookup{err: errors.New("SECONDARY-FAIL")},
	}
	_, err := f.Lookup(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !contains(msg, "PRIMARY-FAIL") || !contains(msg, "SECONDARY-FAIL") {
		t.Errorf("expected both error messages in %q", msg)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
