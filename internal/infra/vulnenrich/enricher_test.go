package vulnenrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/epss"
	"github.com/qwexvf/aegis-cli/internal/infra/kev"
)

func TestEnrich_FillsEPSSAndKEV(t *testing.T) {
	// EPSS server returns a score for one CVE.
	epssSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"OK","data":[
		  {"cve":"CVE-2021-44228","epss":"0.94","percentile":"0.99"}
		]}`))
	}))
	defer epssSrv.Close()

	// KEV: seed disk cache with a known feed so IsKEV reads from disk
	// and never hits the network.
	cacheDir := t.TempDir()
	if err := os.WriteFile(cacheDir+"/kev.json",
		[]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	e := NewWithClients(
		epss.New(epss.WithBaseURL(epssSrv.URL)),
		kev.New(kev.WithCacheDir(cacheDir)),
	)

	advs := []domain.Advisory{
		{ID: "CVE-2021-44228"},
		{ID: "GHSA-only"}, // no CVE alias — both EPSS and KEV skip
	}
	out := e.Enrich(context.Background(), advs)

	if out[0].EPSS == 0 {
		t.Errorf("CVE-2021-44228 should have EPSS set: %+v", out[0])
	}
	if !out[0].InKEV {
		t.Errorf("CVE-2021-44228 should be in KEV: %+v", out[0])
	}
	if out[1].EPSS != 0 || out[1].InKEV {
		t.Errorf("GHSA-only must not be enriched: %+v", out[1])
	}
}

func TestEnrich_EmptyAdvisoriesNoOp(t *testing.T) {
	e := NewWithClients(epss.New(), kev.New())
	out := e.Enrich(context.Background(), nil)
	if len(out) != 0 {
		t.Errorf("nil in, expected 0 out, got %d", len(out))
	}
}

func TestFindCVEID(t *testing.T) {
	tests := []struct {
		name string
		adv  domain.Advisory
		want string
	}{
		{"direct CVE id", domain.Advisory{ID: "CVE-2024-1"}, "CVE-2024-1"},
		{"alias", domain.Advisory{ID: "GHSA-x", Aliases: []string{"CVE-2024-2"}}, "CVE-2024-2"},
		{"no CVE anywhere", domain.Advisory{ID: "GHSA-only"}, ""},
	}
	for _, tt := range tests {
		if got := findCVEID(tt.adv); got != tt.want {
			t.Errorf("%s: got %q want %q", tt.name, got, tt.want)
		}
	}
}
