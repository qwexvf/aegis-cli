package diskcache

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func tmpCache(t *testing.T) *Cache {
	t.Helper()
	return NewAt(filepath.Join(t.TempDir(), "decisions.json"), time.Minute)
}

func sampleDecision() domain.Decision {
	return domain.Decision{
		Kind:     domain.DecisionAllow,
		Severity: domain.SevInfo,
	}
}

func TestCache_GetMiss(t *testing.T) {
	c := tmpCache(t)
	if _, ok := c.Get("npm/lodash@4.17.21"); ok {
		t.Error("Get on empty cache should miss")
	}
}

func TestCache_PutThenGet(t *testing.T) {
	c := tmpCache(t)
	if err := c.Put("npm/lodash@4.17.21", sampleDecision()); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Get("npm/lodash@4.17.21")
	if !ok {
		t.Fatal("expected hit")
	}
	if got.Kind != domain.DecisionAllow {
		t.Errorf("got Kind=%q, want allow", got.Kind)
	}
}

func TestCache_Expiry(t *testing.T) {
	c := NewAt(filepath.Join(t.TempDir(), "decisions.json"), time.Millisecond)
	c.Put("k", sampleDecision())
	time.Sleep(5 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Error("expected miss after expiry")
	}
}

func TestCache_PreservesIncident(t *testing.T) {
	c := tmpCache(t)
	d := domain.Decision{
		Kind:     domain.DecisionBlock,
		Severity: domain.SevCritical,
		Reasons:  []domain.Reason{{Category: "credential-theft", Detail: "reads /etc/shadow"}},
		Incident: &domain.Incident{
			AdvisoryID: "GHSA-pjwm-rvh2-c87w",
			Date:       "2021-10",
			Summary:    "ua-parser-js compromise",
			References: []string{"https://github.com/advisories/GHSA-pjwm-rvh2-c87w"},
		},
	}
	c.Put("npm/ua-parser-js@0.7.29", d)
	got, ok := c.Get("npm/ua-parser-js@0.7.29")
	if !ok {
		t.Fatal("expected hit")
	}
	if got.Incident == nil || got.Incident.AdvisoryID != "GHSA-pjwm-rvh2-c87w" {
		t.Errorf("incident lost on roundtrip: %+v", got.Incident)
	}
	if len(got.Reasons) != 1 || got.Reasons[0].Category != "credential-theft" {
		t.Errorf("reasons lost: %+v", got.Reasons)
	}
}

func TestCache_Clear(t *testing.T) {
	c := tmpCache(t)
	c.Put("k", sampleDecision())
	if err := c.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("k"); ok {
		t.Error("expected miss after Clear")
	}
	if err := c.Clear(); err != nil {
		t.Errorf("Clear on missing file errored: %v", err)
	}
}

func TestCache_List(t *testing.T) {
	c := tmpCache(t)
	c.Put("npm/react@18.0.0", sampleDecision())
	c.Put("npm/lodash@4.17.21", sampleDecision())
	entries, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2, got %d", len(entries))
	}
	if entries[0].Key != "npm/lodash@4.17.21" {
		t.Errorf("not sorted: %v", entries)
	}
}

func TestCache_CorruptFileRecovers(t *testing.T) {
	c := tmpCache(t)
	os.MkdirAll(filepath.Dir(c.path), 0o700)
	os.WriteFile(c.path, []byte("not json"), 0o600)
	if _, ok := c.Get("k"); ok {
		t.Error("expected miss on corrupt file")
	}
	if err := c.Put("k", sampleDecision()); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("k"); !ok {
		t.Error("expected hit after recovery")
	}
}

func TestCache_ConcurrentPuts(t *testing.T) {
	c := tmpCache(t)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.Put("npm/p@"+string(rune('a'+i%26)), sampleDecision())
		}(i)
	}
	wg.Wait()
	if _, err := c.List(); err != nil {
		t.Fatalf("cache corrupt: %v", err)
	}
}
