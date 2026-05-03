package heuristics

import (
	"testing"
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// fixedNow returns a now() function that always reports `t`. Lets the
// hijack heuristic's "fresh publish" check be deterministic in tests.
func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestDetectMaintainerHijackRisk(t *testing.T) {
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	rfc := func(d time.Time) string { return d.Format(time.RFC3339) }

	tests := []struct {
		name string
		sig  domain.MaintainerSignal
		want domain.Capability
	}{
		// --- positive cases (canonical hijack shapes) ---
		{
			name: "event-stream shape: fresh publish + 3-year gap + low downloads",
			sig: domain.MaintainerSignal{
				PublishedAt:         rfc(now.Add(-1 * 24 * time.Hour)), // 1d old
				PreviousPublishedAt: rfc(now.AddDate(-3, 0, 0)),        // last publish 3y ago
				WeeklyDownloads:     500,                               // small package
			},
			want: domain.CapMaintainerHijackRisk,
		},
		{
			name: "fresh + long gap (downloads unknown) — 2 of 3 fires",
			sig: domain.MaintainerSignal{
				PublishedAt:         rfc(now.Add(-3 * 24 * time.Hour)),
				PreviousPublishedAt: rfc(now.AddDate(-1, 0, 0)),
				WeeklyDownloads:     0, // unknown — doesn't count
			},
			want: domain.CapMaintainerHijackRisk,
		},
		{
			name: "fresh + low downloads (no previous publish) — 2 of 3 fires",
			sig: domain.MaintainerSignal{
				PublishedAt:     rfc(now.Add(-2 * 24 * time.Hour)),
				WeeklyDownloads: 200,
			},
			want: domain.CapMaintainerHijackRisk,
		},

		// --- negative cases ---
		{
			name: "fresh publish only — 1 of 3 doesn't fire",
			sig: domain.MaintainerSignal{
				PublishedAt:     rfc(now.Add(-2 * 24 * time.Hour)),
				WeeklyDownloads: 100000, // high downloads cancels low
			},
			want: 0,
		},
		{
			name: "old publish, low downloads — 1 of 3 doesn't fire",
			sig: domain.MaintainerSignal{
				PublishedAt:     rfc(now.AddDate(-2, 0, 0)),
				WeeklyDownloads: 100,
			},
			want: 0,
		},
		{
			name: "no data — no signal",
			sig:  domain.MaintainerSignal{},
			want: 0,
		},
		{
			name: "malformed publish time — graceful no-signal",
			sig: domain.MaintainerSignal{
				PublishedAt: "yesterday",
			},
			want: 0,
		},
		{
			name: "high downloads + recent gap — typical popular package, doesn't fire",
			sig: domain.MaintainerSignal{
				PublishedAt:         rfc(now.Add(-3 * 24 * time.Hour)),
				PreviousPublishedAt: rfc(now.Add(-30 * 24 * time.Hour)), // 30d gap, not "long"
				WeeklyDownloads:     5000000,                            // millions
			},
			want: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := detectMaintainerHijackAt(tc.sig, fixedNow(now))
			if got != tc.want {
				t.Errorf("detectMaintainerHijackAt = %v, want %v", got, tc.want)
			}
		})
	}
}
