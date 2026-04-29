package envprobe

import (
	"os"
	"testing"
)

func clearAll(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"AEGIS_CI", "CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI",
		"TRAVIS", "BUILDKITE", "DRONE", "TEAMCITY_VERSION",
		"BITBUCKET_BUILD_NUMBER", "CODEBUILD_BUILD_ID", "JENKINS_URL",
		"AEGIS_OVERRIDE", "AEGIS_OVERRIDE_REASON",
	} {
		old, ok := os.LookupEnv(k)
		os.Unsetenv(k)
		if ok {
			t.Cleanup(func() { os.Setenv(k, old) })
		}
	}
}

func TestProbe_IsCI_FalseByDefault(t *testing.T) {
	clearAll(t)
	if New().IsCI() {
		t.Error("IsCI() = true with all markers cleared")
	}
}

func TestProbe_IsCI_DetectsEachMarker(t *testing.T) {
	markers := []string{
		"AEGIS_CI", "CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI",
		"TRAVIS", "BUILDKITE", "DRONE", "TEAMCITY_VERSION",
		"BITBUCKET_BUILD_NUMBER", "CODEBUILD_BUILD_ID", "JENKINS_URL",
	}
	for _, m := range markers {
		t.Run(m, func(t *testing.T) {
			clearAll(t)
			t.Setenv(m, "1")
			if !New().IsCI() {
				t.Errorf("IsCI() = false with %s set", m)
			}
		})
	}
}

func TestProbe_Override_DefaultDisallow(t *testing.T) {
	clearAll(t)
	allow, reason := New().Override()
	if allow || reason != "" {
		t.Errorf("got (%v,%q), want (false,'')", allow, reason)
	}
}

func TestProbe_Override_AllowReadsReason(t *testing.T) {
	clearAll(t)
	t.Setenv("AEGIS_OVERRIDE", "allow")
	t.Setenv("AEGIS_OVERRIDE_REASON", "hotfix")
	allow, reason := New().Override()
	if !allow || reason != "hotfix" {
		t.Errorf("got (%v,%q), want (true,'hotfix')", allow, reason)
	}
}

func TestProbe_Override_NonAllowValueIgnored(t *testing.T) {
	clearAll(t)
	t.Setenv("AEGIS_OVERRIDE", "yes")
	allow, _ := New().Override()
	if allow {
		t.Error("AEGIS_OVERRIDE=yes must NOT enable override (only 'allow')")
	}
}
