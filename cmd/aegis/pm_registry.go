package main

import "github.com/qwexvf/aegis-cli/internal/infra/pmwrapper"

// registeredPMs is populated by per-PM init() functions in pm_npm.go,
// pm_bun.go, pm_yarn.go, pm_pnpm.go. All four wrappers are always
// compiled in — aegis ships as one all-in-one binary.
var registeredPMs []pmwrapper.PackageManager

func registerPM(pm pmwrapper.PackageManager) {
	registeredPMs = append(registeredPMs, pm)
}
