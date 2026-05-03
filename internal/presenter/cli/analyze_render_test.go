package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

func newTestAnalyzePresenter(t *testing.T) (*AnalyzePresenter, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	stderr := &bytes.Buffer{}
	stdout := &bytes.Buffer{}
	ap := NewAnalyzePresenter(NewWith(stderr)).SetJSONWriter(stdout)
	return ap, stderr, stdout
}

func TestAnalyzePresenter_HumanRendersVerdictAndCaps(t *testing.T) {
	ap, stderr, _ := newTestAnalyzePresenter(t)
	ap.OnAnalyzeStart(domain.EcoNpm, "evil", "1.0.0")
	ap.OnAnalyzeStage(usecase.EnrichStageFetch)
	ap.OnAnalyzeStage(usecase.EnrichStageScan)
	ap.OnAnalyzeResult(usecase.AnalyzeResult{
		Ecosystem: domain.EcoNpm,
		Name:      "evil",
		Version:   "1.0.0",
		Verdict:   domain.VerdictBlock,
		Risk: domain.RiskAssessment{
			Score: 87,
			Flags: []domain.RiskFlag{
				{Code: "shell-spawn", Detail: "spawns subprocess", Weight: 20},
			},
		},
		Fingerprint: domain.Fingerprint{
			Capabilities: domain.NewCapabilitySet(domain.CapShellSpawn),
			Hooks: []domain.InstallHook{
				{Phase: domain.PhasePostInstall, Source: "scripts.postinstall", Sha256: "abcdef0123456789"},
			},
			EnvReads:        []string{"HOME", "PATH"},
			SourceSizeBytes: 1234,
		},
		TarballSha256: "ff00ff00ff00ff00ff00ff00ff00ff00",
		FilesAnalyzed: 12,
		SourceBytes:   1234,
	}, false)

	out := stderr.String()
	for _, want := range []string{
		"analyzing npm/evil@1.0.0",
		"fetch ...",
		"scan ...",
		"verdict=block",
		"risk=87",
		"shell-spawn",
		"postinstall",
		"abcdef012345…",
		"HOME, PATH",
		"1.2 KB across 12 files",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in stderr:\n%s", want, out)
		}
	}
}

func TestAnalyzePresenter_HumanShowsEvidenceWhenRequested(t *testing.T) {
	ap, stderr, _ := newTestAnalyzePresenter(t)
	ap.OnAnalyzeResult(usecase.AnalyzeResult{
		Ecosystem: domain.EcoNpm, Name: "x", Version: "1",
		Verdict: domain.VerdictReview,
		Evidence: []domain.Evidence{
			{Capability: domain.CapShellSpawn, File: "lib/run.js", Line: 42, Snippet: "child_process.exec(cmd)"},
		},
	}, true)
	out := stderr.String()
	if !strings.Contains(out, "Evidence:") {
		t.Errorf("evidence header missing:\n%s", out)
	}
	if !strings.Contains(out, "lib/run.js:42") {
		t.Errorf("evidence file:line missing:\n%s", out)
	}
	if !strings.Contains(out, "child_process.exec(cmd)") {
		t.Errorf("evidence snippet missing:\n%s", out)
	}
}

func TestAnalyzePresenter_HumanHidesEvidenceByDefault(t *testing.T) {
	ap, stderr, _ := newTestAnalyzePresenter(t)
	ap.OnAnalyzeResult(usecase.AnalyzeResult{
		Ecosystem: domain.EcoNpm, Name: "x", Version: "1",
		Evidence: []domain.Evidence{
			{Capability: domain.CapShellSpawn, File: "lib/run.js", Line: 42, Snippet: "secret"},
		},
	}, false)
	if strings.Contains(stderr.String(), "Evidence:") {
		t.Errorf("evidence section should not appear without --evidence")
	}
}

func TestAnalyzePresenter_JSONModeWritesToStdoutAndSilencesStderr(t *testing.T) {
	ap, stderr, stdout := newTestAnalyzePresenter(t)
	ap.SetJSONMode(true)
	ap.OnAnalyzeStart(domain.EcoNpm, "x", "1")
	ap.OnAnalyzeStage(usecase.EnrichStageFetch)
	ap.OnAnalyzeResult(usecase.AnalyzeResult{
		Ecosystem: domain.EcoNpm, Name: "x", Version: "1",
		Verdict: domain.VerdictSafe,
		Risk:    domain.RiskAssessment{Score: 0},
		Fingerprint: domain.Fingerprint{
			Capabilities: domain.NewCapabilitySet(),
		},
		FilesAnalyzed: 5,
		SourceBytes:   100,
	}, true)

	if stderr.Len() != 0 {
		t.Errorf("stderr should be empty in JSON mode, got: %q", stderr.String())
	}
	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	for _, key := range []string{"ecosystem", "name", "version", "verdict", "risk_score", "files_analyzed", "source_bytes"} {
		if _, ok := got[key]; !ok {
			t.Errorf("JSON missing key %q: %v", key, got)
		}
	}
	if got["verdict"] != "safe" {
		t.Errorf("verdict = %v, want safe", got["verdict"])
	}
}

func TestAnalyzePresenter_JSONErrorHasErrorKey(t *testing.T) {
	ap, _, stdout := newTestAnalyzePresenter(t)
	ap.SetJSONMode(true)
	ap.OnAnalyzeError(domain.EcoNpm, "x", "1", &simpleErr{msg: "fetch: 404"})

	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if got["error"] != "fetch: 404" {
		t.Errorf("error = %v, want 'fetch: 404'", got["error"])
	}
}

func TestHumanSize(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1500, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{2 * 1024 * 1024 * 1024, "2.0 GB"},
	}
	for _, c := range cases {
		if got := humanSize(c.in); got != c.want {
			t.Errorf("humanSize(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestShortHash(t *testing.T) {
	if got := shortHash("abc"); got != "abc" {
		t.Errorf("short hash unchanged: got %q", got)
	}
	if got := shortHash("0123456789abcdef0123456789abcdef"); got != "0123456789ab…" {
		t.Errorf("long hash trim: got %q", got)
	}
}

type simpleErr struct{ msg string }

func (e *simpleErr) Error() string { return e.msg }
