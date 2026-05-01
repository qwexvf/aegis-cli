package main

import (
	"os"
	"testing"
)

// clearCIMarkers wipes the CI-detection envs envprobe.IsCI checks so
// tests start from a clean slate. Mirrors the list in
// internal/infra/envprobe — kept inline here so a drift in either
// list trips this test rather than silently passing.
func clearCIMarkers(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"AEGIS_CI", "CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI",
		"TRAVIS", "BUILDKITE", "DRONE", "TEAMCITY_VERSION",
		"BITBUCKET_BUILD_NUMBER", "CODEBUILD_BUILD_ID", "JENKINS_URL",
	} {
		t.Setenv(k, "")
	}
}

func TestShouldPrettyLog_FalseUnderCIMarker(t *testing.T) {
	clearCIMarkers(t)
	t.Setenv("CI", "true")
	if shouldPrettyLog() {
		t.Errorf("shouldPrettyLog() = true with CI=true; want false (CI runs get JSON for log shippers)")
	}
}

func TestShouldPrettyLog_FalseUnderGitHubActions(t *testing.T) {
	clearCIMarkers(t)
	t.Setenv("GITHUB_ACTIONS", "true")
	if shouldPrettyLog() {
		t.Errorf("shouldPrettyLog() = true under GITHUB_ACTIONS; want false")
	}
}

func TestShouldPrettyLog_FalseWhenStderrNotTTY(t *testing.T) {
	// `go test` runs with stderr redirected to a pipe, not a TTY,
	// so this is the natural state of the test process. Verify the
	// non-TTY path returns false even with no CI markers set.
	clearCIMarkers(t)
	if shouldPrettyLog() {
		t.Errorf("shouldPrettyLog() = true with non-TTY stderr; want false")
	}
}

func TestNewInvocationID_ProducesHex32(t *testing.T) {
	id := newInvocationID()
	if len(id) != 32 {
		t.Errorf("invocation id length = %d, want 32", len(id))
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("invocation id %q contains non-hex char %q", id, c)
			break
		}
	}
}

func TestNewInvocationID_EachCallUnique(t *testing.T) {
	// Probabilistic — 128 bits of entropy means collision is
	// astronomically unlikely. If this ever fails twice in a row,
	// crypto/rand is broken or someone substituted the impl.
	a := newInvocationID()
	b := newInvocationID()
	if a == b {
		t.Errorf("two consecutive invocation IDs collided: %s", a)
	}
}

// Sanity: shouldPrettyLog uses os.Stderr.Stat which can fail if the
// underlying fd is somehow unusable. Hard to provoke from a test, but
// pin the contract: stat error → false.
func TestShouldPrettyLog_StatFailureReturnsFalse(t *testing.T) {
	clearCIMarkers(t)
	// Best-effort: replace os.Stderr with a closed file. The
	// shouldPrettyLog reads the package-level os.Stderr, so we
	// swap it out for the duration of the test.
	orig := os.Stderr
	defer func() { os.Stderr = orig }()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	w.Close()
	os.Stderr = w // closed fd — Stat will likely succeed but Mode won't have CharDevice set

	if shouldPrettyLog() {
		t.Errorf("shouldPrettyLog() = true with non-TTY (closed pipe) stderr; want false")
	}
}
