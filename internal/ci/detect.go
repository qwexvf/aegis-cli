// Package ci detects whether aegis is running inside a continuous-
// integration environment. We use this to escalate `prompt` decisions
// to `block` automatically — CI has no human to answer the prompt.
package ci

import "os"

// IsCI returns true if any common CI marker is present.
func IsCI() bool {
	// Generic + per-vendor markers. Order doesn't matter; we OR them.
	for _, key := range []string{
		"AEGIS_CI",       // explicit override (any non-empty value)
		"CI",             // generic; many systems set this to "true"
		"GITHUB_ACTIONS", // GitHub Actions
		"GITLAB_CI",      // GitLab CI
		"CIRCLECI",       // CircleCI
		"TRAVIS",         // Travis
		"BUILDKITE",      // Buildkite
		"DRONE",          // Drone
		"TEAMCITY_VERSION",
		"BITBUCKET_BUILD_NUMBER",
		"CODEBUILD_BUILD_ID", // AWS CodeBuild
	} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	// Jenkins exposes JENKINS_URL but not always CI=true.
	if os.Getenv("JENKINS_URL") != "" {
		return true
	}
	return false
}
