package cli

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/qwexvf/aegis-cli/internal/infra/envprobe"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// enrichWindowRows caps how many in-flight slots are shown at once.
// More than that gets summarised as "… N more" so the rendered region
// doesn't expand past one screenful even when the worker pool is wide.
const enrichWindowRows = 10

// enrichTickRate is the redraw interval. 100ms gives ~10fps spinner
// motion, which is the sweet spot for "alive but not seizure-inducing"
// in modern terminals.
const enrichTickRate = 100 * time.Millisecond

// stuckThreshold appends an elapsed-time tag to slots that have been
// in-flight longer than this — useful for spotting one slow tarball in
// a fast batch before it scrolls out of the window.
const stuckThreshold = 5 * time.Second

var spinnerFrames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

// EnrichLivePresenter wraps a SnapshotPresenter with a windowed
// "what's running right now" region for `aegis snapshot enrich`. It
// embeds the base so non-enrich callbacks pass through unchanged; only
// the enrich lifecycle methods are overridden. Concurrency: callbacks
// fire from the worker pool (up to enrichWorkers goroutines) so all
// state mutation is mutex-guarded.
//
// Construct via NewEnrichLivePresenter — that decides whether to
// activate the live region based on TTY/CI/NO_COLOR and returns the
// base unchanged when inappropriate.
type EnrichLivePresenter struct {
	*SnapshotPresenter
	w io.Writer

	mu        sync.Mutex
	slots     map[int]*liveSlot // active workers, keyed by slot id
	order     []int             // slot ids, newest first
	completed int
	total     int
	started   time.Time
	prevLines int // lines drawn last frame (0 = nothing pinned)
	frame     int
	running   bool
	// pendingInfos buffers OnSnapshotInfo / OnSnapshotError messages
	// that arrive between renders so the live region only clears +
	// redraws once per tick instead of once per message. Without this,
	// 50 rapid "skip foo@bar: err" lines from a flaky network produce
	// 50 clear-and-redraw cycles and the screen flickers heavily.
	pendingInfos []bufferedInfo
	stop         chan struct{}
	done         chan struct{}
}

// liveSlot is the per-worker state the renderer reads each frame.
type liveSlot struct {
	eco     string
	name    string
	version string
	stage   usecase.EnrichStage
	startAt time.Time
}

// bufferedInfo is one queued info/error message awaiting flush by the
// next render tick. err==nil means it was OnSnapshotInfo, non-nil
// means OnSnapshotError — the flush calls the matching base method
// so coloring + format are preserved.
type bufferedInfo struct {
	msg string
	err error
}

// NewEnrichLivePresenter wraps base with a live region when the
// environment is interactive; otherwise returns base unchanged so
// callers can use it identically either way. Honors:
//
//   - NO_COLOR / AEGIS_NO_LIVE: opt out
//   - CI / GITHUB_ACTIONS / GITLAB_CI / BUILDKITE / CIRCLECI: opt out
//   - non-TTY stderr: opt out
//
// In opt-out mode the existing per-completion log line
// (OnSnapshotEnrichProgress) is the user's progress UX.
func NewEnrichLivePresenter(base *SnapshotPresenter) usecase.SnapshotPresenter {
	if !shouldUseLive() {
		return base
	}
	return &EnrichLivePresenter{
		SnapshotPresenter: base,
		w:                 os.Stderr,
		slots:             map[int]*liveSlot{},
	}
}

func shouldUseLive() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("AEGIS_NO_LIVE") != "" {
		return false
	}
	if envprobe.IsCI() {
		return false
	}
	return isTerminal(os.Stderr.Fd())
}

// --- enrich lifecycle ---------------------------------------------------

// OnEnrichBegin records the total work, hides the cursor, and starts
// the redraw ticker. Idempotent: a second Begin without an End in
// between is treated as a reset.
func (lp *EnrichLivePresenter) OnEnrichBegin(total int) {
	lp.mu.Lock()
	if lp.running {
		// Defensive: stop existing loop before resetting.
		close(lp.stop)
		lp.mu.Unlock()
		<-lp.done
		lp.mu.Lock()
	}
	lp.total = total
	lp.completed = 0
	lp.started = time.Now()
	lp.slots = map[int]*liveSlot{}
	lp.order = lp.order[:0]
	lp.prevLines = 0
	lp.frame = 0
	lp.running = true
	lp.stop = make(chan struct{})
	lp.done = make(chan struct{})
	lp.mu.Unlock()

	fmt.Fprint(lp.w, "\x1b[?25l") // hide cursor
	go lp.tickLoop()
}

// OnEnrichEnd stops the ticker, clears the live region, flushes any
// buffered info/error messages, and restores the cursor. Safe to
// call without a matching Begin.
func (lp *EnrichLivePresenter) OnEnrichEnd() {
	lp.mu.Lock()
	if !lp.running {
		lp.mu.Unlock()
		return
	}
	lp.running = false
	close(lp.stop)
	stopCh := lp.done
	lp.mu.Unlock()
	<-stopCh

	lp.mu.Lock()
	// Drain any messages that arrived between the last tick and Stop.
	// flushPendingInfosLocked clears the region first.
	lp.flushPendingInfosLocked()
	lp.clearRegionLocked()
	fmt.Fprint(lp.w, "\x1b[?25h") // show cursor
	lp.mu.Unlock()
}

// OnEnrichSlotStart records a worker picking up a task. The new slot
// goes to the top of the order so the user always sees what just
// started.
func (lp *EnrichLivePresenter) OnEnrichSlotStart(slot int, eco, name, version string) {
	lp.mu.Lock()
	defer lp.mu.Unlock()
	s := &liveSlot{
		eco:     eco,
		name:    name,
		version: version,
		stage:   usecase.EnrichStageFetch,
		startAt: time.Now(),
	}
	if _, existed := lp.slots[slot]; !existed {
		// Prepend in place — once the slice reaches steady-state
		// capacity (≈ workerCount), this is alloc-free; the literal
		// `append([]int{slot}, ...)` form allocates every call.
		lp.order = append(lp.order, 0)
		copy(lp.order[1:], lp.order[:len(lp.order)-1])
		lp.order[0] = slot
	}
	lp.slots[slot] = s
}

// OnEnrichSlotStage updates an in-flight slot's stage label. No-op if
// the slot has already been removed (race between Done and Stage).
func (lp *EnrichLivePresenter) OnEnrichSlotStage(slot int, stage usecase.EnrichStage) {
	lp.mu.Lock()
	defer lp.mu.Unlock()
	if s, ok := lp.slots[slot]; ok {
		s.stage = stage
	}
}

// OnEnrichSlotDone removes the slot from the active set. Counters are
// driven by OnSnapshotEnrichProgress (which fires for cache hits too),
// not from here.
func (lp *EnrichLivePresenter) OnEnrichSlotDone(slot int, _, _, _ string, _ bool) {
	lp.mu.Lock()
	defer lp.mu.Unlock()
	delete(lp.slots, slot)
	for i, id := range lp.order {
		if id == slot {
			lp.order = append(lp.order[:i], lp.order[i+1:]...)
			break
		}
	}
}

// OnSnapshotEnrichProgress is the canonical completion counter. It
// fires for every completed dep including cache hits, so the live
// region uses it directly rather than incrementing on SlotDone.
func (lp *EnrichLivePresenter) OnSnapshotEnrichProgress(done, total int, _ string) {
	lp.mu.Lock()
	defer lp.mu.Unlock()
	lp.completed = done
	lp.total = max(lp.total, total)
}

// OnSnapshotInfo buffers the message during a live enrich and lets
// the next render tick flush it above the region. Outside an active
// enrich, falls through to the base presenter immediately. Buffering
// avoids one clear-and-redraw cycle per message — a stream of "skip
// X" lines from a flaky network would otherwise produce visible
// flicker.
func (lp *EnrichLivePresenter) OnSnapshotInfo(message string) {
	lp.mu.Lock()
	if lp.running {
		lp.pendingInfos = append(lp.pendingInfos, bufferedInfo{msg: message})
		lp.mu.Unlock()
		return
	}
	lp.mu.Unlock()
	lp.SnapshotPresenter.OnSnapshotInfo(message)
}

// OnSnapshotError follows the same buffer-during-enrich pattern.
func (lp *EnrichLivePresenter) OnSnapshotError(err error) {
	lp.mu.Lock()
	if lp.running {
		lp.pendingInfos = append(lp.pendingInfos, bufferedInfo{err: err})
		lp.mu.Unlock()
		return
	}
	lp.mu.Unlock()
	lp.SnapshotPresenter.OnSnapshotError(err)
}

// --- rendering ----------------------------------------------------------

func (lp *EnrichLivePresenter) tickLoop() {
	defer close(lp.done)
	ticker := time.NewTicker(enrichTickRate)
	defer ticker.Stop()
	for {
		select {
		case <-lp.stop:
			return
		case <-ticker.C:
			lp.mu.Lock()
			if lp.running {
				lp.renderLocked()
			}
			lp.mu.Unlock()
		}
	}
}

// renderLocked redraws the live region in place. Caller holds lp.mu.
//
// Strategy: flush any queued info/error messages above the region
// (one clear + N writes for the whole batch), then move the cursor
// up to where the previous region started, rewrite each line with a
// leading clear-line escape, and handle the case where the new
// region is shorter than the old one by clearing the trailing lines.
func (lp *EnrichLivePresenter) renderLocked() {
	lp.flushPendingInfosLocked()
	lp.frame = (lp.frame + 1) % len(spinnerFrames)
	lines := lp.buildLinesLocked()

	if lp.prevLines > 0 {
		fmt.Fprintf(lp.w, "\x1b[%dA", lp.prevLines)
	}
	for _, ln := range lines {
		fmt.Fprintf(lp.w, "\x1b[2K%s\n", ln)
	}
	if extra := lp.prevLines - len(lines); extra > 0 {
		for range extra {
			fmt.Fprint(lp.w, "\x1b[2K\n")
		}
		fmt.Fprintf(lp.w, "\x1b[%dA", extra)
	}
	lp.prevLines = len(lines)
}

func (lp *EnrichLivePresenter) buildLinesLocked() []string {
	lines := make([]string, 0, enrichWindowRows+3)
	lines = append(lines, lp.headerLineLocked())
	lines = append(lines, "")

	show := min(len(lp.order), enrichWindowRows)
	for i := range show {
		s := lp.slots[lp.order[i]]
		if s == nil {
			continue
		}
		lines = append(lines, lp.slotLineLocked(s))
	}
	if extra := len(lp.order) - show; extra > 0 {
		lines = append(lines, fmt.Sprintf("  … %d more", extra))
	}
	return lines
}

// headerLineLocked formats the top status line. Caller holds lp.mu.
func (lp *EnrichLivePresenter) headerLineLocked() string {
	pct := 0
	if lp.total > 0 {
		pct = lp.completed * 100 / lp.total
	}
	elapsed := time.Since(lp.started).Truncate(time.Second)
	return fmt.Sprintf("Enriching dependencies — %d/%d (%d%%) • %d active • %s elapsed",
		lp.completed, lp.total, pct, len(lp.order), formatElapsed(elapsed))
}

// slotLineLocked formats one in-flight slot. Caller holds lp.mu.
func (lp *EnrichLivePresenter) slotLineLocked(s *liveSlot) string {
	spin := string(spinnerFrames[lp.frame])
	pkg := fmt.Sprintf("%s/%s@%s", s.eco, s.name, s.version)
	if len(pkg) > 48 {
		pkg = pkg[:47] + "…"
	}
	elapsed := time.Since(s.startAt).Truncate(time.Second)
	stuck := ""
	if elapsed >= stuckThreshold {
		stuck = "  " + formatElapsed(elapsed)
	}
	return fmt.Sprintf("  %s %-48s %s%s", spin, pkg, s.stage, stuck)
}

// flushPendingInfosLocked drains the buffered info/error messages,
// clears the region once, and forwards each to the base presenter.
// Caller holds lp.mu. After return, prevLines is 0 and the live
// region is ready to be redrawn below the flushed lines.
func (lp *EnrichLivePresenter) flushPendingInfosLocked() {
	if len(lp.pendingInfos) == 0 {
		return
	}
	lp.clearRegionLocked()
	for _, b := range lp.pendingInfos {
		if b.err != nil {
			lp.SnapshotPresenter.OnSnapshotError(b.err)
		} else {
			lp.SnapshotPresenter.OnSnapshotInfo(b.msg)
		}
	}
	lp.pendingInfos = lp.pendingInfos[:0]
}

// clearRegionLocked erases the pinned region and leaves the cursor at
// its starting position (i.e. where the region's first line was).
// Caller holds lp.mu.
func (lp *EnrichLivePresenter) clearRegionLocked() {
	if lp.prevLines == 0 {
		return
	}
	fmt.Fprintf(lp.w, "\x1b[%dA", lp.prevLines)
	for range lp.prevLines {
		fmt.Fprint(lp.w, "\x1b[2K\n")
	}
	fmt.Fprintf(lp.w, "\x1b[%dA", lp.prevLines)
	lp.prevLines = 0
}

func formatElapsed(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%d:%02d", int(d.Minutes()), int(d.Seconds())%60)
}
