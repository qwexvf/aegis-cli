package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/infra/aegisapi"
	"github.com/qwexvf/aegis-cli/internal/infra/allowlist"
)

func TestCheckRuntime_AlwaysPasses(t *testing.T) {
	r := checkRuntime()
	if r.Status != doctorPass {
		t.Errorf("runtime check status = %v, want PASS", r.Status)
	}
	if !strings.Contains(r.Detail, "aegis") {
		t.Errorf("runtime detail missing 'aegis': %q", r.Detail)
	}
}

func TestCheckAPI_NilClientWarns(t *testing.T) {
	r := checkAPI(context.Background(), nil)
	if r.Status != doctorWarn {
		t.Errorf("nil client should WARN, got %v", r.Status)
	}
}

func TestCheckAPI_ReachableServerPasses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()
	t.Setenv("AEGIS_API_URL", srv.URL)
	api, err := aegisapi.New()
	if err != nil {
		t.Fatal(err)
	}

	r := checkAPI(context.Background(), api)
	if r.Status != doctorPass {
		t.Errorf("reachable server status = %v, want PASS (detail: %s)", r.Status, r.Detail)
	}
}

func TestCheckAPI_ServerErrorWarns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	t.Setenv("AEGIS_API_URL", srv.URL)
	api, err := aegisapi.New()
	if err != nil {
		t.Fatal(err)
	}

	r := checkAPI(context.Background(), api)
	if r.Status != doctorWarn {
		t.Errorf("502 should WARN (server alive but ill), got %v", r.Status)
	}
}

func TestCheckAPI_NetworkErrorWarns(t *testing.T) {
	t.Setenv("AEGIS_API_URL", "http://127.0.0.1:9") // discard port — connection refused
	api, err := aegisapi.New()
	if err != nil {
		t.Fatal(err)
	}
	r := checkAPI(context.Background(), api)
	// Cloud is optional — an unreachable API is advisory (WARN), not a
	// failure, so `aegis doctor` exits 0 for an offline-only OSS user.
	if r.Status != doctorWarn {
		t.Errorf("unreachable should WARN, got %v (detail: %s)", r.Status, r.Detail)
	}
}

func TestCheckConfigDirWritable_PassesWhenWritable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AEGIS_CONFIG_DIR", dir)
	r := checkConfigDirWritable()
	if r.Status != doctorPass {
		t.Errorf("writable temp dir status = %v, want PASS", r.Status)
	}
}

func TestCheckAllowlist_LoaderNilWarns(t *testing.T) {
	r := checkAllowlist(nil)
	if r.Status != doctorWarn {
		t.Errorf("nil loader should WARN, got %v", r.Status)
	}
}

func TestCheckAllowlist_GoodFilePasses(t *testing.T) {
	t.Setenv("AEGIS_CONFIG_DIR", t.TempDir())
	loader := func() *allowlist.Loader { return allowlist.New(t.TempDir()) }
	r := checkAllowlist(loader)
	if r.Status != doctorPass {
		t.Errorf("clean loader should PASS, got %v (detail: %s)", r.Status, r.Detail)
	}
}

func TestCheckAllowlist_MalformedFails(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("AEGIS_CONFIG_DIR", cfg)
	if err := os.WriteFile(filepath.Join(cfg, "allowlist.yaml"), []byte("rules: not-a-list"), 0o644); err != nil {
		t.Fatal(err)
	}
	loader := func() *allowlist.Loader { return allowlist.New(t.TempDir()) }
	r := checkAllowlist(loader)
	if r.Status != doctorFail {
		t.Errorf("malformed allowlist should FAIL, got %v (detail: %s)", r.Status, r.Detail)
	}
}

func TestCheckProjectDir_DetectsLockfile(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "package.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := checkProjectDir(cwd)
	if r.Status != doctorPass {
		t.Errorf("dir with package.json should PASS, got %v", r.Status)
	}
	if !strings.Contains(r.Detail, "package.json") {
		t.Errorf("detail should mention package.json: %q", r.Detail)
	}
}

func TestCheckProjectDir_NoLockfileWarns(t *testing.T) {
	r := checkProjectDir(t.TempDir())
	if r.Status != doctorWarn {
		t.Errorf("empty dir should WARN, got %v", r.Status)
	}
}

func TestAnyFailed(t *testing.T) {
	if anyFailed([]doctorResult{{Status: doctorPass}, {Status: doctorWarn}}) {
		t.Errorf("PASS+WARN should not count as failed")
	}
	if !anyFailed([]doctorResult{{Status: doctorPass}, {Status: doctorFail}}) {
		t.Errorf("any FAIL should count as failed")
	}
}

func TestRenderDoctorJSON_StableShape(t *testing.T) {
	buf := &bytes.Buffer{}
	renderDoctorJSON(buf, []doctorResult{
		{Name: "api", Status: doctorPass, Detail: "ok"},
		{Name: "cache", Status: doctorWarn, Detail: "size: 1.2 MB"},
	})
	var got []map[string]string
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json invalid: %v\n%s", err, buf.String())
	}
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got))
	}
	if got[0]["name"] != "api" || got[0]["status"] != "PASS" {
		t.Errorf("first entry shape wrong: %+v", got[0])
	}
}

func TestRenderDoctorResults_HumanFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	renderDoctorResults(buf, []doctorResult{
		{Name: "api", Status: doctorPass, Detail: "ok"},
	}, false)
	out := buf.String()
	for _, want := range []string{"api", "PASS", "ok"} {
		if !strings.Contains(out, want) {
			t.Errorf("human output missing %q:\n%s", want, out)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{1024, "1.0 KB"},
		{1500, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{2 * 1024 * 1024 * 1024, "2.0 GB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.in); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
