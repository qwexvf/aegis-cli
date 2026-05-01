package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/qwexvf/aegis/services/cli/internal/usecase"
)

// newTestLive constructs an EnrichLivePresenter writing to an
// in-memory buffer, bypassing the TTY check used by the public
// constructor. The ticker is NOT started — tests drive renders by
// calling buildLinesLocked / renderLocked directly so they don't race
// the goroutine.
func newTestLive() (*EnrichLivePresenter, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	base := NewSnapshotPresenter(NewWith(buf))
	return &EnrichLivePresenter{
		SnapshotPresenter: base,
		w:                 buf,
		slots:             map[int]*liveSlot{},
		started:           time.Now(),
	}, buf
}

func TestEnrichLive_NewestSlotsBubbleToTop(t *testing.T) {
	lp, _ := newTestLive()
	lp.OnEnrichSlotStart(0, "npm", "first", "1.0.0")
	lp.OnEnrichSlotStart(1, "npm", "second", "2.0.0")
	lp.OnEnrichSlotStart(2, "npm", "third", "3.0.0")

	if got := lp.order; len(got) != 3 || got[0] != 2 || got[1] != 1 || got[2] != 0 {
		t.Fatalf("expected newest-first order [2 1 0], got %v", got)
	}
}

func TestEnrichLive_SlotDoneRemovesFromOrder(t *testing.T) {
	lp, _ := newTestLive()
	lp.OnEnrichSlotStart(0, "npm", "a", "1")
	lp.OnEnrichSlotStart(1, "npm", "b", "1")
	lp.OnEnrichSlotStart(2, "npm", "c", "1")

	lp.OnEnrichSlotDone(1, "npm", "b", "1", true)

	if _, exists := lp.slots[1]; exists {
		t.Errorf("slot 1 should be removed from slots map")
	}
	if got := lp.order; len(got) != 2 || got[0] != 2 || got[1] != 0 {
		t.Errorf("expected order [2 0] after removing slot 1, got %v", got)
	}
}

func TestEnrichLive_WindowCapsRowsWithMoreFooter(t *testing.T) {
	lp, _ := newTestLive()
	for i := range 15 {
		lp.OnEnrichSlotStart(i, "npm", "pkg", "1.0.0")
	}

	lines := lp.buildLinesLocked()
	// header + blank + 10 slot lines + "… 5 more"
	if got := len(lines); got != 13 {
		t.Fatalf("expected 13 lines (header + blank + 10 slots + footer), got %d:\n%s",
			got, strings.Join(lines, "\n"))
	}
	if !strings.Contains(lines[12], "5 more") {
		t.Errorf("expected footer to mention '5 more', got %q", lines[12])
	}
}

func TestEnrichLive_NoFooterWhenAtOrUnderCap(t *testing.T) {
	lp, _ := newTestLive()
	for i := range 10 {
		lp.OnEnrichSlotStart(i, "npm", "pkg", "1.0.0")
	}
	lines := lp.buildLinesLocked()
	for _, ln := range lines {
		if strings.Contains(ln, "more") {
			t.Errorf("did not expect '… N more' footer at exactly %d slots:\n%s",
				enrichWindowRows, strings.Join(lines, "\n"))
		}
	}
}

func TestEnrichLive_HeaderShowsCounters(t *testing.T) {
	lp, _ := newTestLive()
	lp.OnEnrichBegin(100)
	defer lp.OnEnrichEnd()
	// Don't run the ticker — drain it before assertions.
	close(lp.stop)
	<-lp.done
	lp.running = false

	lp.OnSnapshotEnrichProgress(33, 100, "anything")
	lp.OnEnrichSlotStart(0, "npm", "x", "1")
	lp.OnEnrichSlotStart(1, "npm", "y", "1")

	header := lp.headerLineLocked()
	for _, want := range []string{"33/100", "33%", "2 active", "Enriching"} {
		if !strings.Contains(header, want) {
			t.Errorf("header missing %q: %s", want, header)
		}
	}
}

func TestEnrichLive_StageLabelAppearsInSlotLine(t *testing.T) {
	lp, _ := newTestLive()
	lp.OnEnrichSlotStart(0, "npm", "lodash", "4.17.21")
	lp.OnEnrichSlotStage(0, usecase.EnrichStageScan)

	line := lp.slotLineLocked(lp.slots[0])
	if !strings.Contains(line, "scan") {
		t.Errorf("slot line should show 'scan' stage: %q", line)
	}
	if !strings.Contains(line, "npm/lodash@4.17.21") {
		t.Errorf("slot line should show pkg ref: %q", line)
	}
}

func TestEnrichLive_LongPackageNameTruncated(t *testing.T) {
	lp, _ := newTestLive()
	long := strings.Repeat("a", 80)
	lp.OnEnrichSlotStart(0, "npm", long, "1.0.0")

	line := lp.slotLineLocked(lp.slots[0])
	if !strings.Contains(line, "…") {
		t.Errorf("expected truncation ellipsis: %q", line)
	}
}

func TestEnrichLive_StuckSlotShowsElapsed(t *testing.T) {
	lp, _ := newTestLive()
	lp.OnEnrichSlotStart(0, "npm", "slow", "1.0.0")
	// Backdate so the elapsed-tag threshold trips.
	lp.slots[0].startAt = time.Now().Add(-12 * time.Second)

	line := lp.slotLineLocked(lp.slots[0])
	if !strings.Contains(line, "12s") {
		t.Errorf("expected elapsed tag when slot is stuck: %q", line)
	}
}

func TestEnrichLive_FastSlotHidesElapsed(t *testing.T) {
	lp, _ := newTestLive()
	lp.OnEnrichSlotStart(0, "npm", "fast", "1.0.0")

	line := lp.slotLineLocked(lp.slots[0])
	// Should not have a trailing elapsed tag for sub-threshold work.
	parts := strings.Fields(line)
	if last := parts[len(parts)-1]; strings.HasSuffix(last, "s") && last != "fetch" && last != "scan" {
		t.Errorf("did not expect elapsed tag on fresh slot: %q", line)
	}
}

func TestEnrichLive_FallbackPathBypassesLive(t *testing.T) {
	t.Setenv("AEGIS_NO_LIVE", "1")
	base := NewSnapshotPresenter(NewWith(&bytes.Buffer{}))
	got := NewEnrichLivePresenter(base)
	if got != usecase.SnapshotPresenter(base) {
		t.Errorf("AEGIS_NO_LIVE should return base presenter unchanged")
	}
}

func TestEnrichLive_FallbackPathHonorsCI(t *testing.T) {
	t.Setenv("CI", "true")
	base := NewSnapshotPresenter(NewWith(&bytes.Buffer{}))
	got := NewEnrichLivePresenter(base)
	if got != usecase.SnapshotPresenter(base) {
		t.Errorf("CI=true should return base presenter unchanged")
	}
}

func TestEnrichLive_StageUpdateOnRemovedSlotIsNoop(t *testing.T) {
	lp, _ := newTestLive()
	lp.OnEnrichSlotStart(0, "npm", "a", "1")
	lp.OnEnrichSlotDone(0, "npm", "a", "1", true)
	// Stage update on a removed slot must not panic and must not
	// resurrect the slot.
	lp.OnEnrichSlotStage(0, usecase.EnrichStageScan)
	if _, exists := lp.slots[0]; exists {
		t.Errorf("stage update should not resurrect a removed slot")
	}
}

func TestEnrichLive_OnSnapshotInfoBuffersDuringRunning(t *testing.T) {
	lp, _ := newTestLive()
	lp.running = true

	lp.OnSnapshotInfo("first")
	lp.OnSnapshotInfo("second")
	lp.OnSnapshotInfo("third")

	if got := len(lp.pendingInfos); got != 3 {
		t.Errorf("expected 3 buffered messages, got %d", got)
	}
	for i, want := range []string{"first", "second", "third"} {
		if lp.pendingInfos[i].msg != want {
			t.Errorf("pendingInfos[%d].msg = %q, want %q", i, lp.pendingInfos[i].msg, want)
		}
	}
}

func TestEnrichLive_OnSnapshotInfoBypassesBufferOutsideRunning(t *testing.T) {
	lp, buf := newTestLive()
	lp.running = false
	lp.OnSnapshotInfo("immediate")
	if len(lp.pendingInfos) != 0 {
		t.Errorf("expected pending queue empty when not running, got %d", len(lp.pendingInfos))
	}
	if !strings.Contains(buf.String(), "immediate") {
		t.Errorf("expected message written to base presenter buf:\n%s", buf.String())
	}
}

func TestEnrichLive_FlushDrainsAndForwards(t *testing.T) {
	lp, buf := newTestLive()
	lp.running = true
	lp.OnSnapshotInfo("alpha")
	lp.OnSnapshotInfo("beta")

	lp.mu.Lock()
	lp.flushPendingInfosLocked()
	lp.mu.Unlock()

	if len(lp.pendingInfos) != 0 {
		t.Errorf("flush should empty pendingInfos, got %d remaining", len(lp.pendingInfos))
	}
	out := buf.String()
	for _, want := range []string{"alpha", "beta"} {
		if !strings.Contains(out, want) {
			t.Errorf("flushed output missing %q:\n%s", want, out)
		}
	}
}

func TestEnrichLive_OnSnapshotErrorAlsoBuffered(t *testing.T) {
	lp, _ := newTestLive()
	lp.running = true
	lp.OnSnapshotError(&simpleErr{msg: "boom"})
	if len(lp.pendingInfos) != 1 || lp.pendingInfos[0].err == nil {
		t.Errorf("expected 1 buffered error, got %+v", lp.pendingInfos)
	}
}

func TestFormatElapsed(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{5 * time.Second, "5s"},
		{59 * time.Second, "59s"},
		{60 * time.Second, "1:00"},
		{90 * time.Second, "1:30"},
		{125 * time.Second, "2:05"},
	}
	for _, c := range cases {
		if got := formatElapsed(c.in); got != c.want {
			t.Errorf("formatElapsed(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
