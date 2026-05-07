package usecase

import "os"

// unusedSuppressEnabled reports whether the reachability layer should
// suppress non-install risk flags on deps marked
// domain.ReachabilityUnused.
//
// Default: off. Setting AEGIS_UNUSED_SUPPRESS to any non-empty value
// turns it on. We default off so the reachability data accumulates
// in snapshots without changing existing verdicts; teams opt in once
// they trust the import scan.
func unusedSuppressEnabled() bool {
	return os.Getenv("AEGIS_UNUSED_SUPPRESS") != ""
}
