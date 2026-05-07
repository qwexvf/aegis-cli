package cli

import (
	"fmt"
	"strconv"
	"text/tabwriter"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// SnapshotPresenter satisfies usecase.SnapshotPresenter. It writes
// snapshot save/show/diff/verify output to an io.Writer with optional
// ANSI colors (NO_COLOR / non-TTY aware via the existing Presenter).
type SnapshotPresenter struct{ p *Presenter }

// NewSnapshotPresenter wraps a base Presenter. Re-uses NO_COLOR / TTY
// detection from the install-gate presenter.
func NewSnapshotPresenter(p *Presenter) *SnapshotPresenter { return &SnapshotPresenter{p: p} }

// OnSnapshotSaved prints "saved to <path> (N deps)".
func (sp *SnapshotPresenter) OnSnapshotSaved(path string, depCount int) {
	fmt.Fprintf(sp.p.w, "%s[aegis]%s saved %d deps → %s%s%s\n",
		sp.p.dim(), sp.p.reset(),
		depCount,
		sp.p.green(), path, sp.p.reset())
}

// OnSnapshotShow renders the snapshot as a table.
func (sp *SnapshotPresenter) OnSnapshotShow(s domain.Snapshot, directOnly, usedOnly bool) {
	header := fmt.Sprintf("%s[aegis]%s snapshot: %s, %d deps, schema v%d, saved %s",
		sp.p.dim(), sp.p.reset(),
		s.Project, len(s.Deps), s.SchemaVersion,
		s.CreatedAt.Format("2006-01-02 15:04:05Z"))
	fmt.Fprintln(sp.p.w, header)

	tw := tabwriter.NewWriter(sp.p.w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  ECO\tNAME\tVERSION\tDIRECT\tCAPS\tADVISORIES")
	shown := 0
	hiddenUnused := 0
	for _, d := range s.Deps {
		if directOnly && !d.Direct {
			continue
		}
		if usedOnly && d.Reachability == domain.ReachabilityUnused {
			hiddenUnused++
			continue
		}
		flag := ""
		if d.Direct {
			flag = "✓"
		}
		// CAPS: terse summary of the AST/heuristic capability
		// count. Empty when the dep wasn't enriched yet.
		caps := snapshotCapsCell(d)
		// ADVISORIES: count + max severity. Empty when none /
		// not yet looked up. Color-coded by max severity so
		// the eye finds the high-severity rows first.
		advs := snapshotAdvisoryCell(sp.p, d)
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
			d.Ecosystem, d.Name, d.Version, flag, caps, advs)
		shown++
	}
	tw.Flush()
	if directOnly {
		fmt.Fprintf(sp.p.w, "%s[aegis]%s shown %d direct deps (--all to include transitives)\n",
			sp.p.dim(), sp.p.reset(), shown)
	}
	if usedOnly && hiddenUnused > 0 {
		fmt.Fprintf(sp.p.w, "%s[aegis]%s hid %d unused deps (drop --used-only to show)\n",
			sp.p.dim(), sp.p.reset(), hiddenUnused)
	}
}

// snapshotCapsCell renders the CAPS column for one dep. Empty when
// the dep hasn't been enriched yet (Fingerprint == nil). When
// enriched but with no findings, returns "—" so the user can
// distinguish "scanned, clean" from "not yet scanned". Appends
// "[unused]" when the reachability scan saw no project source
// importing the dep.
func snapshotCapsCell(d domain.Dependency) string {
	base := ""
	if d.Fingerprint == nil || !d.Fingerprint.Analyzed {
		base = ""
	} else if n := len(d.Fingerprint.Capabilities); n == 0 {
		base = "—"
	} else {
		base = strconv.Itoa(n)
	}
	if d.Reachability == domain.ReachabilityUnused {
		if base == "" {
			return "[unused]"
		}
		return base + " [unused]"
	}
	return base
}

// snapshotAdvisoryCell renders the ADVISORIES column for one dep:
// the count + the max severity, colored by severity. Empty when
// the dep's Advisories slice is nil (not looked up yet); "—" when
// looked up with no matches; "Nx (severity)" otherwise.
func snapshotAdvisoryCell(p *Presenter, d domain.Dependency) string {
	if d.Advisories == nil {
		return ""
	}
	if len(d.Advisories) == 0 {
		return "—"
	}
	max := domain.MaxSeverity(d.Advisories)
	var color string
	switch max {
	case domain.SevCritical, domain.SevHigh:
		color = p.red()
	case domain.SevMedium:
		color = p.yellow()
	default:
		color = p.dim()
	}
	return fmt.Sprintf("%s%d (%s)%s", color, len(d.Advisories), max, p.reset())
}

// OnSnapshotDiff renders Added/Removed/Upgraded entries with their
// risk verdicts. Each entry shows the verdict marker (✓/⚠/✗), the
// name@version, and (when non-zero) a per-flag breakdown of the
// score so users can see *why* the engine flagged it.
func (sp *SnapshotPresenter) OnSnapshotDiff(report usecase.DiffReport) {
	if len(report.Entries) == 0 {
		fmt.Fprintf(sp.p.w, "%s[aegis]%s no changes\n", sp.p.dim(), sp.p.reset())
		return
	}

	added, removed, upgraded := splitEntries(report.Entries)

	if len(added) > 0 {
		fmt.Fprintf(sp.p.w, "%s[aegis]%s %s+ added (%d)%s\n",
			sp.p.dim(), sp.p.reset(),
			sp.p.green(), len(added), sp.p.reset())
		for _, e := range added {
			sp.renderEntry(e)
		}
	}
	if len(removed) > 0 {
		fmt.Fprintf(sp.p.w, "%s[aegis]%s %s- removed (%d)%s\n",
			sp.p.dim(), sp.p.reset(),
			sp.p.dim(), len(removed), sp.p.reset())
		for _, e := range removed {
			d := *e.Old
			fmt.Fprintf(sp.p.w, "    %s%s@%s%s%s\n",
				sp.p.dim(), d.Name, d.Version, sp.p.reset(),
				directBadge(d))
		}
	}
	if len(upgraded) > 0 {
		fmt.Fprintf(sp.p.w, "%s[aegis]%s %s~ upgraded (%d)%s\n",
			sp.p.dim(), sp.p.reset(),
			sp.p.yellow(), len(upgraded), sp.p.reset())
		for _, e := range upgraded {
			sp.renderEntry(e)
		}
	}
}

// OnSnapshotEnrichProgress prints a per-dep progress line during AST scan.
func (sp *SnapshotPresenter) OnSnapshotEnrichProgress(done, total int, name string) {
	fmt.Fprintf(sp.p.w, "%s[aegis]%s [%d/%d] analyzing %s\n",
		sp.p.dim(), sp.p.reset(), done, total, name)
}

// OnEnrichBegin / OnEnrichEnd / OnEnrichSlot* are intentionally no-ops
// on the plain (non-TTY) presenter — its progress UX is the per-dep
// line written by OnSnapshotEnrichProgress. The live presenter
// (enrich_live.go) overrides these to render a windowed view.
func (sp *SnapshotPresenter) OnEnrichBegin(int)                                  {}
func (sp *SnapshotPresenter) OnEnrichEnd()                                       {}
func (sp *SnapshotPresenter) OnEnrichSlotStart(int, string, string, string)      {}
func (sp *SnapshotPresenter) OnEnrichSlotStage(int, usecase.EnrichStage)         {}
func (sp *SnapshotPresenter) OnEnrichSlotDone(int, string, string, string, bool) {}

// OnSnapshotEmpty prints a one-line "nothing to do" message.
func (sp *SnapshotPresenter) OnSnapshotEmpty(reason string) {
	fmt.Fprintf(sp.p.w, "%s[aegis]%s %s\n", sp.p.dim(), sp.p.reset(), reason)
}

// OnSnapshotInfo is a generic info line.
func (sp *SnapshotPresenter) OnSnapshotInfo(message string) {
	fmt.Fprintf(sp.p.w, "%s[aegis]%s %s\n", sp.p.dim(), sp.p.reset(), message)
}

// OnSnapshotError prints a single-line error.
func (sp *SnapshotPresenter) OnSnapshotError(err error) {
	fmt.Fprintf(sp.p.w, "%s[aegis]%s %s%s! %v%s\n",
		sp.p.dim(), sp.p.reset(),
		sp.p.red(), sp.p.bold(), err, sp.p.reset())
}

// --- helpers ----------------------------------------------------------

func splitEntries(es []usecase.DiffEntry) (added, removed, upgraded []usecase.DiffEntry) {
	for _, e := range es {
		switch e.Kind {
		case usecase.DiffAdded:
			added = append(added, e)
		case usecase.DiffRemoved:
			removed = append(removed, e)
		case usecase.DiffUpgraded:
			upgraded = append(upgraded, e)
		}
	}
	return
}

// renderEntry emits one row + flag breakdown.
func (sp *SnapshotPresenter) renderEntry(e usecase.DiffEntry) {
	marker, color := sp.verdictMarker(e.Verdict)

	switch e.Kind {
	case usecase.DiffAdded:
		d := *e.New
		fmt.Fprintf(sp.p.w, "    %s%s%s %s%s@%s%s%s\n",
			color, marker, sp.p.reset(),
			sp.p.green(), d.Name, d.Version, sp.p.reset(),
			directBadge(d))
	case usecase.DiffUpgraded:
		fmt.Fprintf(sp.p.w, "    %s%s%s %s%s%s  %s%s%s → %s%s%s\n",
			color, marker, sp.p.reset(),
			sp.p.bold(), e.New.Name, sp.p.reset(),
			sp.p.dim(), e.Old.Version, sp.p.reset(),
			sp.p.yellow(), e.New.Version, sp.p.reset())
	}

	totalScore := max(e.Drift.Score, e.Risk.Score)
	// Show breakdown when ANY of: non-zero score, OR any flag exists
	// (suppressed flags are kept visible for transparency).
	if totalScore == 0 && len(e.Risk.Flags) == 0 && len(e.Drift.Flags) == 0 {
		return
	}

	fmt.Fprintf(sp.p.w, "        %s└─ verdict=%s%s%s  risk=%d  drift=%d%s\n",
		sp.p.dim(),
		color, e.Verdict, sp.p.reset(), e.Risk.Score, e.Drift.Score,
		sp.p.reset())
	for _, f := range e.Risk.Flags {
		sp.renderFlag("+", sp.p.yellow(), f)
	}
	for _, f := range e.Drift.Flags {
		sp.renderFlag("Δ", sp.p.red(), f)
	}
}

// renderFlag prints one flag line. Suppressed flags swap their marker
// to ~ and show "(suppressed +N, allowlisted: <reason>)" so the
// reader sees the original weight while making it clear it wasn't
// added to Score.
func (sp *SnapshotPresenter) renderFlag(marker, color string, f domain.RiskFlag) {
	if f.Suppressed {
		fmt.Fprintf(sp.p.w, "           %s~ %s%s%s — %s  %s(suppressed +%d, allowlisted: %s)%s\n",
			sp.p.dim(),
			sp.p.dim(), f.Code, sp.p.reset(),
			f.Detail,
			sp.p.dim(), f.Weight, f.SuppressBy, sp.p.reset())
		return
	}
	fmt.Fprintf(sp.p.w, "           %s%s %s%s%s — %s  %s(+%d)%s\n",
		sp.p.dim(), marker,
		color, f.Code, sp.p.reset(),
		f.Detail,
		sp.p.dim(), f.Weight, sp.p.reset())
}

func (sp *SnapshotPresenter) verdictMarker(v domain.VerdictKind) (marker, color string) {
	switch v {
	case domain.VerdictBlock:
		return "✗", sp.p.red()
	case domain.VerdictPrompt:
		return "⚠", sp.p.red()
	case domain.VerdictReview:
		return "⚠", sp.p.yellow()
	default:
		return "✓", sp.p.green()
	}
}

func directBadge(d domain.Dependency) string {
	if d.Direct {
		return "  (direct)"
	}
	return ""
}
