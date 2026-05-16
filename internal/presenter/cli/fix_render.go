package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// FixPresenter satisfies usecase.FixPresenter. Renders the upgrade plan
// to stderr in human mode or stdout as JSON.
type FixPresenter struct {
	p        *Presenter
	jsonOut  io.Writer
	jsonMode bool
	asScript bool // when true, only the upgrade commands are printed (pipe to sh)
}

// NewFixPresenter wraps a base Presenter for stderr output and targets
// stdout for JSON / shell-script output.
func NewFixPresenter(base *Presenter) *FixPresenter {
	return &FixPresenter{p: base, jsonOut: os.Stdout}
}

// SetJSONMode toggles JSON output. Returns the receiver for chaining.
func (fp *FixPresenter) SetJSONMode(on bool) *FixPresenter {
	fp.jsonMode = on
	return fp
}

// SetScriptMode toggles "shell script" output — only the upgrade commands,
// one per line, suitable for piping into `sh`. Quiets everything else.
func (fp *FixPresenter) SetScriptMode(on bool) *FixPresenter {
	fp.asScript = on
	return fp
}

// SetJSONWriter overrides the stdout destination. Tests inject a buffer.
func (fp *FixPresenter) SetJSONWriter(w io.Writer) *FixPresenter {
	fp.jsonOut = w
	return fp
}

// OnFixBegin prints the header in human mode. JSON / script modes keep
// stderr quiet so downstream pipes stay clean.
func (fp *FixPresenter) OnFixBegin(projectDir string) {
	if fp.jsonMode || fp.asScript {
		return
	}
	fmt.Fprintf(fp.p.w, "%s[aegis]%s fix — planning upgrades for %s\n",
		fp.p.dim(), fp.p.reset(), projectDir)
}

// OnFixError surfaces a load / build failure.
func (fp *FixPresenter) OnFixError(err error) {
	if fp.jsonMode {
		_ = json.NewEncoder(fp.jsonOut).Encode(fixErrorJSON{Error: err.Error()})
		return
	}
	fmt.Fprintf(fp.p.w, "%s[aegis]%s %s%s! %v%s\n",
		fp.p.dim(), fp.p.reset(),
		fp.p.red(), fp.p.bold(), err, fp.p.reset())
}

// OnFixResult prints the plan in the active mode.
func (fp *FixPresenter) OnFixResult(r usecase.FixResult) {
	if fp.jsonMode {
		_ = json.NewEncoder(fp.jsonOut).Encode(toFixJSONResult(r))
		return
	}
	if fp.asScript {
		fp.renderScript(r)
		return
	}
	fp.renderHuman(r)
}

func (fp *FixPresenter) renderHuman(r usecase.FixResult) {
	if r.Plan.Empty() {
		fmt.Fprintf(fp.p.w, "%s[aegis]%s no advisories — nothing to fix\n",
			fp.p.dim(), fp.p.reset())
		return
	}

	resolved := 0
	cves := 0
	for _, item := range r.Plan.Items {
		resolved += len(item.ResolvedAdvisories)
		cves += len(item.ResolvedAdvisories) + len(item.UnresolvedAdvisories)
	}
	fmt.Fprintf(fp.p.w, "%s[aegis]%s %d advisories across %d dep(s); %d resolvable via upgrade\n\n",
		fp.p.dim(), fp.p.reset(), cves, len(r.Plan.Items), resolved)

	for _, item := range r.Plan.Items {
		fp.renderItem(item)
	}
}

func (fp *FixPresenter) renderItem(item domain.FixItem) {
	dep := item.Dep
	target := item.TargetVersion
	if target == "" {
		fmt.Fprintf(fp.p.w, "  %s/%s@%s — %sno upstream fix%s\n",
			dep.Ecosystem, dep.Name, dep.Version,
			fp.p.yellow(), fp.p.reset())
		for _, a := range item.UnresolvedAdvisories {
			fmt.Fprintf(fp.p.w, "    %s•%s %s — %s\n",
				fp.p.dim(), fp.p.reset(), a.ID, a.Summary)
		}
		fmt.Fprintln(fp.p.w)
		return
	}

	fmt.Fprintf(fp.p.w, "  %s/%s — %s%s%s → %s%s%s\n",
		dep.Ecosystem, dep.Name,
		fp.p.dim(), dep.Version, fp.p.reset(),
		fp.p.green(), target, fp.p.reset())

	for _, a := range item.ResolvedAdvisories {
		fmt.Fprintf(fp.p.w, "    %s✓%s clears %s (%s)\n",
			fp.p.green(), fp.p.reset(), a.ID, a.Severity)
	}
	for _, a := range item.UnresolvedAdvisories {
		fmt.Fprintf(fp.p.w, "    %s!%s %s — no fixed version reported\n",
			fp.p.yellow(), fp.p.reset(), a.ID)
	}

	if cmd := domain.UpgradeCommand(dep, target); cmd != "" {
		fmt.Fprintf(fp.p.w, "    %s→%s %s\n", fp.p.dim(), fp.p.reset(), cmd)
	}
	fmt.Fprintln(fp.p.w)
}

func (fp *FixPresenter) renderScript(r usecase.FixResult) {
	for _, item := range r.Plan.Items {
		if item.TargetVersion == "" {
			continue
		}
		if cmd := domain.UpgradeCommand(item.Dep, item.TargetVersion); cmd != "" {
			fmt.Fprintln(fp.jsonOut, cmd)
		}
	}
}

// --- JSON shapes --------------------------------------------------------

type fixJSONResult struct {
	Items []fixJSONItem `json:"items"`
	Total int           `json:"total"`
}

type fixJSONItem struct {
	Ecosystem            string            `json:"ecosystem"`
	Name                 string            `json:"name"`
	CurrentVersion       string            `json:"current_version"`
	TargetVersion        string            `json:"target_version,omitempty"`
	UpgradeCommand       string            `json:"upgrade_command,omitempty"`
	ResolvedAdvisories   []fixJSONAdvisory `json:"resolved_advisories,omitempty"`
	UnresolvedAdvisories []fixJSONAdvisory `json:"unresolved_advisories,omitempty"`
}

type fixJSONAdvisory struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
	URL      string `json:"url,omitempty"`
	FixedIn  string `json:"fixed_in,omitempty"`
}

type fixErrorJSON struct {
	Error string `json:"error"`
}

func toFixJSONResult(r usecase.FixResult) fixJSONResult {
	out := fixJSONResult{Items: make([]fixJSONItem, 0, len(r.Plan.Items))}
	for _, it := range r.Plan.Items {
		j := fixJSONItem{
			Ecosystem:            string(it.Dep.Ecosystem),
			Name:                 it.Dep.Name,
			CurrentVersion:       it.Dep.Version,
			TargetVersion:        it.TargetVersion,
			UpgradeCommand:       domain.UpgradeCommand(it.Dep, it.TargetVersion),
			ResolvedAdvisories:   advisoriesToFixJSON(it.ResolvedAdvisories),
			UnresolvedAdvisories: advisoriesToFixJSON(it.UnresolvedAdvisories),
		}
		out.Items = append(out.Items, j)
	}
	out.Total = len(out.Items)
	return out
}

func advisoriesToFixJSON(advs []domain.Advisory) []fixJSONAdvisory {
	if len(advs) == 0 {
		return nil
	}
	out := make([]fixJSONAdvisory, 0, len(advs))
	for _, a := range advs {
		out = append(out, fixJSONAdvisory{
			ID:       a.ID,
			Severity: string(a.Severity),
			Summary:  a.Summary,
			URL:      a.URL,
			FixedIn:  a.FixedIn,
		})
	}
	return out
}
