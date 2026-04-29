package main

import "github.com/qwexvf/aegis/services/cli/internal/infra/pmwrapper"

// registeredPMs is populated by per-PM init() functions, each guarded
// by a build tag (see pm_npm.go, pm_bun.go, pm_yarn.go, pm_pnpm.go).
// A build with `-tags='nonpm'` produces a binary whose `aegis --help`
// no longer lists `aegis npm`; the npm wrapper is not compiled in.
//
// Default (no tags) registers all four; size delta per PM is small
// (~5 KB), so this is primarily a UX/distribution feature.
var registeredPMs []pmwrapper.PackageManager

func registerPM(pm pmwrapper.PackageManager) {
	registeredPMs = append(registeredPMs, pm)
}
