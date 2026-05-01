// Package envprobe satisfies usecase.EnvProbe by reading process env
// vars. It is the only place in the binary that reads CI-detection
// markers and AEGIS_OVERRIDE / AEGIS_OVERRIDE_REASON, so the policy
// layer never touches os.Getenv directly.
package envprobe

import "os"

// Probe is an EnvProbe that reads from the live process environment.
type Probe struct{}

// New returns a Probe.
func New() *Probe { return &Probe{} }

// IsCI returns true if any common CI marker is set in the environment.
func (Probe) IsCI() bool { return IsCI() }

// IsCI is a package-level CI-marker probe — the same logic as
// Probe.IsCI but callable without constructing a Probe. Use this from
// places that just need a yes/no (logger format selection, live-region
// fallback) rather than a stateful adapter.
func IsCI() bool {
	for _, key := range []string{
		"AEGIS_CI",       // explicit override
		"CI",             // generic
		"GITHUB_ACTIONS", // GitHub Actions
		"GITLAB_CI",      // GitLab CI
		"CIRCLECI",       // CircleCI
		"TRAVIS",         // Travis
		"BUILDKITE",      // Buildkite
		"DRONE",          // Drone
		"TEAMCITY_VERSION",
		"BITBUCKET_BUILD_NUMBER",
		"CODEBUILD_BUILD_ID", // AWS CodeBuild
		"JENKINS_URL",        // Jenkins
	} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	return false
}

// Override returns the AEGIS_OVERRIDE / AEGIS_OVERRIDE_REASON pair.
// allow is true iff the override env is exactly "allow"; reason is the
// raw value of AEGIS_OVERRIDE_REASON. The use case enforces the
// "reason required" rule.
func (Probe) Override() (allow bool, reason string) {
	allow = os.Getenv("AEGIS_OVERRIDE") == "allow"
	reason = os.Getenv("AEGIS_OVERRIDE_REASON")
	return
}
