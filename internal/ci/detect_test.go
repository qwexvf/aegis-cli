package ci

import (
	"os"
	"testing"
)

// clearAllCI wipes every env var IsCI examines so tests start from a
// known-clean slate. Without this, running on a developer's CI laptop
// (or in actual CI) would leak true into every test.
func clearAllCI(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"AEGIS_CI", "CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI",
		"TRAVIS", "BUILDKITE", "DRONE", "TEAMCITY_VERSION",
		"BITBUCKET_BUILD_NUMBER", "CODEBUILD_BUILD_ID", "JENKINS_URL",
	} {
		old, ok := os.LookupEnv(k)
		os.Unsetenv(k)
		if ok {
			t.Cleanup(func() { os.Setenv(k, old) })
		}
	}
}

func TestIsCI_FalseByDefault(t *testing.T) {
	clearAllCI(t)
	if IsCI() {
		t.Error("IsCI() = true with all markers cleared")
	}
}

func TestIsCI_DetectsEachMarker(t *testing.T) {
	markers := []string{
		"AEGIS_CI", "CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI",
		"TRAVIS", "BUILDKITE", "DRONE", "TEAMCITY_VERSION",
		"BITBUCKET_BUILD_NUMBER", "CODEBUILD_BUILD_ID", "JENKINS_URL",
	}
	for _, m := range markers {
		t.Run(m, func(t *testing.T) {
			clearAllCI(t)
			t.Setenv(m, "1")
			if !IsCI() {
				t.Errorf("IsCI() = false with %s set", m)
			}
		})
	}
}
