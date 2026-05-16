package actions

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestParseActionRef(t *testing.T) {
	tests := []struct {
		raw  string
		want domain.ActionRef
	}{
		{
			raw:  "actions/checkout@v4",
			want: domain.ActionRef{Owner: "actions", Repo: "checkout", Ref: "v4", Kind: domain.ActionRefRemote},
		},
		{
			raw:  "tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67",
			want: domain.ActionRef{Owner: "tj-actions", Repo: "changed-files", Ref: "0e58ed8671d6b60d0890c21b07f8835ace038e67", Kind: domain.ActionRefRemote},
		},
		{
			raw:  "actions/cache/restore@v3",
			want: domain.ActionRef{Owner: "actions", Repo: "cache", Path: "restore", Ref: "v3", Kind: domain.ActionRefRemote},
		},
		{
			raw:  "./.github/actions/setup",
			want: domain.ActionRef{Path: "./.github/actions/setup", Kind: domain.ActionRefLocal},
		},
		{
			raw:  "docker://alpine:3.18",
			want: domain.ActionRef{Path: "docker://alpine:3.18", Kind: domain.ActionRefDocker},
		},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			got := parseActionRef(tc.raw)
			if got.Owner != tc.want.Owner || got.Repo != tc.want.Repo ||
				got.Path != tc.want.Path || got.Ref != tc.want.Ref || got.Kind != tc.want.Kind {
				t.Errorf("parseActionRef(%q):\n  got  %+v\n  want %+v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseBytes_BasicWorkflow(t *testing.T) {
	body := []byte(`name: CI
on: [push, pull_request]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo hello
`)
	wf, err := ParseBytes(".github/workflows/ci.yml", body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if wf.Name != "CI" {
		t.Errorf("name: got %q want CI", wf.Name)
	}
	if len(wf.On) != 2 || wf.On[0] != "push" || wf.On[1] != "pull_request" {
		t.Errorf("on: got %v want [push pull_request]", wf.On)
	}
	if wf.Permissions.Mode != "scopes" || wf.Permissions.Scopes["contents"] != "read" {
		t.Errorf("permissions: got %+v", wf.Permissions)
	}
	if len(wf.Jobs) != 1 {
		t.Fatalf("jobs: got %d want 1", len(wf.Jobs))
	}
	job := wf.Jobs[0]
	if job.ID != "build" || job.RunsOn != "ubuntu-latest" {
		t.Errorf("job: %+v", job)
	}
	if len(job.Steps) != 2 {
		t.Fatalf("steps: got %d want 2", len(job.Steps))
	}
	if job.Steps[0].Uses == nil || job.Steps[0].Uses.Owner != "actions" || job.Steps[0].Uses.Repo != "checkout" {
		t.Errorf("step0.uses: %+v", job.Steps[0].Uses)
	}
	if job.Steps[1].Run == nil || job.Steps[1].Run.Body != "echo hello" {
		t.Errorf("step1.run: %+v", job.Steps[1].Run)
	}
}

func TestParseBytes_OnMapping(t *testing.T) {
	body := []byte(`on:
  pull_request_target:
    branches: [main]
  push:
    branches: [main]
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: echo
`)
	wf, err := ParseBytes("x.yml", body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[string]bool{"pull_request_target": true, "push": true}
	for _, e := range wf.On {
		if !want[e] {
			t.Errorf("unexpected event %q", e)
		}
		delete(want, e)
	}
	if len(want) > 0 {
		t.Errorf("missing events: %v", want)
	}
}
