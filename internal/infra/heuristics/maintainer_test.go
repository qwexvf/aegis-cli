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

func TestDetectMaintainerChanged(t *testing.T) {
	tests := []struct {
		name string
		sig  domain.MaintainerSignal
		want domain.Capability
	}{
		{
			name: "event-stream shape — publisher changed between versions",
			sig: domain.MaintainerSignal{
				Publisher:         "right9ctrl",
				PreviousPublisher: "dominictarr",
			},
			want: domain.CapMaintainerChanged,
		},
		{
			name: "same publisher across versions — no signal",
			sig: domain.MaintainerSignal{
				Publisher:         "sindresorhus",
				PreviousPublisher: "sindresorhus",
			},
			want: 0,
		},
		{
			name: "missing current publisher — no signal (don't fire on missing data)",
			sig: domain.MaintainerSignal{
				PreviousPublisher: "dominictarr",
			},
			want: 0,
		},
		{
			name: "missing previous publisher — no signal",
			sig: domain.MaintainerSignal{
				Publisher: "right9ctrl",
			},
			want: 0,
		},
		{
			name: "no data at all — no signal",
			sig:  domain.MaintainerSignal{},
			want: 0,
		},
		{
			name: "publisher case sensitive — different case is a different account",
			sig: domain.MaintainerSignal{
				Publisher:         "Dominictarr",
				PreviousPublisher: "dominictarr",
			},
			want: domain.CapMaintainerChanged,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectMaintainerChanged(tc.sig)
			if got != tc.want {
				t.Errorf("DetectMaintainerChanged = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRunMaintainerSignal_BothFire(t *testing.T) {
	// event-stream shape: publisher changed AND hijack-shape (low
	// downloads, long gap, fresh publish). Both heuristics fire;
	// the aggregator returns both caps.
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	rfc := func(d time.Time) string { return d.Format(time.RFC3339) }
	sig := domain.MaintainerSignal{
		PublishedAt:         rfc(now.Add(-3 * 24 * time.Hour)),
		PreviousPublishedAt: rfc(now.AddDate(-1, 0, 0)),
		WeeklyDownloads:     200,
		Publisher:           "right9ctrl",
		PreviousPublisher:   "dominictarr",
	}
	hijack := detectMaintainerHijackAt(sig, fixedNow(now))
	changed := DetectMaintainerChanged(sig)
	if hijack != domain.CapMaintainerHijackRisk {
		t.Errorf("hijack = %v, want CapMaintainerHijackRisk", hijack)
	}
	if changed != domain.CapMaintainerChanged {
		t.Errorf("changed = %v, want CapMaintainerChanged", changed)
	}
}

// TestDetectVersionUnpublished covers the yanked-version detector that
// catches users whose lockfile pins a version that was published during
// an active incident window and subsequently removed from the registry.
func TestDetectVersionUnpublished(t *testing.T) {
	t.Run("tanstack-2026 — version yanked after incident", func(t *testing.T) {
		// Simulates @tanstack/react-router@1.169.5: present in time map,
		// absent from versions map = published then yanked.
		sig := domain.MaintainerSignal{
			PublishedAt:        "2026-05-11T19:20:42.105Z",
			VersionUnpublished: true,
		}
		got := DetectVersionUnpublished(sig)
		if got != domain.CapVersionUnpublished {
			t.Fatalf("want CapVersionUnpublished, got %v", got)
		}
	})

	t.Run("normal live version — not flagged", func(t *testing.T) {
		sig := domain.MaintainerSignal{
			PublishedAt:        "2026-05-05T20:37:38.526Z",
			VersionUnpublished: false,
		}
		got := DetectVersionUnpublished(sig)
		if got != 0 {
			t.Errorf("want 0 (version is live), got %v", got)
		}
	})

	t.Run("empty signal — no false positive", func(t *testing.T) {
		got := DetectVersionUnpublished(domain.MaintainerSignal{})
		if got != 0 {
			t.Errorf("want 0 on empty signal, got %v", got)
		}
	})
}
