package cli

import (
	"fmt"
	"text/tabwriter"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
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
func (sp *SnapshotPresenter) OnSnapshotShow(s domain.Snapshot, directOnly bool) {
	header := fmt.Sprintf("%s[aegis]%s snapshot: %s, %d deps, schema v%d, saved %s",
		sp.p.dim(), sp.p.reset(),
		s.Project, len(s.Deps), s.SchemaVersion,
		s.CreatedAt.Format("2006-01-02 15:04:05Z"))
	fmt.Fprintln(sp.p.w, header)

	tw := tabwriter.NewWriter(sp.p.w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  ECO\tNAME\tVERSION\tDIRECT")
	shown := 0
	for _, d := range s.Deps {
		if directOnly && !d.Direct {
			continue
		}
		flag := ""
		if d.Direct {
			flag = "✓"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", d.Ecosystem, d.Name, d.Version, flag)
		shown++
	}
	tw.Flush()
	if directOnly {
		fmt.Fprintf(sp.p.w, "%s[aegis]%s shown %d direct deps (--all to include transitives)\n",
			sp.p.dim(), sp.p.reset(), shown)
	}
}

// OnSnapshotDiff renders an Added/Removed/Upgraded diff.
func (sp *SnapshotPresenter) OnSnapshotDiff(d domain.SnapshotDelta) {
	if d.Empty() {
		fmt.Fprintf(sp.p.w, "%s[aegis]%s no changes\n", sp.p.dim(), sp.p.reset())
		return
	}

	if len(d.Added) > 0 {
		fmt.Fprintf(sp.p.w, "%s[aegis]%s %s+ added (%d)%s\n",
			sp.p.dim(), sp.p.reset(),
			sp.p.green(), len(d.Added), sp.p.reset())
		for _, a := range d.Added {
			fmt.Fprintf(sp.p.w, "    %s%s@%s%s%s\n",
				sp.p.green(), a.Name, a.Version, sp.p.reset(),
				directBadge(a))
		}
	}
	if len(d.Removed) > 0 {
		fmt.Fprintf(sp.p.w, "%s[aegis]%s %s- removed (%d)%s\n",
			sp.p.dim(), sp.p.reset(),
			sp.p.red(), len(d.Removed), sp.p.reset())
		for _, r := range d.Removed {
			fmt.Fprintf(sp.p.w, "    %s%s@%s%s%s\n",
				sp.p.red(), r.Name, r.Version, sp.p.reset(),
				directBadge(r))
		}
	}
	if len(d.Upgraded) > 0 {
		fmt.Fprintf(sp.p.w, "%s[aegis]%s %s~ upgraded (%d)%s\n",
			sp.p.dim(), sp.p.reset(),
			sp.p.yellow(), len(d.Upgraded), sp.p.reset())
		for _, u := range d.Upgraded {
			fmt.Fprintf(sp.p.w, "    %s%s%s  %s%s%s → %s%s%s\n",
				sp.p.bold(), u.Name, sp.p.reset(),
				sp.p.dim(), u.Old.Version, sp.p.reset(),
				sp.p.yellow(), u.New.Version, sp.p.reset())
		}
	}
}

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

func directBadge(d domain.Dependency) string {
	if d.Direct {
		return "  (direct)"
	}
	return ""
}
