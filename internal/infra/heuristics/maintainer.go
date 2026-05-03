package heuristics

import (
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// Threshold constants — exported so tests and future configuration
// can reference them by name. Defaults are tuned against the
// observed shape of historical npm hijacks (event-stream,
// ua-parser-js, coa, rc, node-ipc).
const (
	// FreshPublishWindow — versions younger than this are "fresh".
	// 7 days catches the typical "publish, ride for a few days,
	// get caught" attack window.
	FreshPublishWindow = 7 * 24 * time.Hour

	// LongGapThreshold — minimum time since the previous publish to
	// count as "abandoned then handed over". 180 days is the gap
	// that surfaced event-stream's compromise (the original
	// maintainer hadn't published in months).
	LongGapThreshold = 180 * 24 * time.Hour

	// LowDownloadsThreshold — packages below this are "low traffic"
	// and historically more attractive to hijack (less scrutiny).
	// 1000/week is roughly the boundary between "clearly used by
	// real apps" and "obscure".
	LowDownloadsThreshold = int64(1000)

	// HijackSignalThreshold — number of conditions (out of 3) that
	// must hold for the heuristic to fire. 2 of 3 keeps false
	// positives down: lots of legit packages are recently published,
	// but a recent + low-traffic + with-a-long-gap is the
	// distinctive shape.
	HijackSignalThreshold = 2
)

// DetectMaintainerHijackRisk scores the registry-side metadata
// against three known-bad shape signals and fires when at least
// HijackSignalThreshold of them hold:
//
//  1. Fresh publish (this version published within FreshPublishWindow)
//  2. Long gap (≥ LongGapThreshold since previous version)
//  3. Low downloads (< LowDownloadsThreshold weekly)
//
// Returns CapMaintainerHijackRisk on fire, 0 otherwise. Empty
// signal struct (no data) returns 0 — the heuristic only fires on
// positive evidence, never on missing data.
//
// Time is read via the now() function so tests can pin it.
func DetectMaintainerHijackRisk(sig domain.MaintainerSignal) domain.Capability {
	return detectMaintainerHijackAt(sig, time.Now)
}

// detectMaintainerHijackAt is the testable entry — same logic with
// an injected clock.
func detectMaintainerHijackAt(sig domain.MaintainerSignal, now func() time.Time) domain.Capability {
	if sig.PublishedAt == "" {
		return 0 // no data = no signal
	}
	publishT, err := time.Parse(time.RFC3339, sig.PublishedAt)
	if err != nil {
		return 0
	}
	signals := 0

	// 1. Fresh publish?
	if now().Sub(publishT) <= FreshPublishWindow {
		signals++
	}

	// 2. Long gap from previous publish?
	if sig.PreviousPublishedAt != "" {
		prevT, err := time.Parse(time.RFC3339, sig.PreviousPublishedAt)
		if err == nil && publishT.Sub(prevT) >= LongGapThreshold {
			signals++
		}
	}

	// 3. Low weekly downloads? (Zero means "unknown" — don't count.)
	if sig.WeeklyDownloads > 0 && sig.WeeklyDownloads < LowDownloadsThreshold {
		signals++
	}

	if signals >= HijackSignalThreshold {
		return domain.CapMaintainerHijackRisk
	}
	return 0
}
