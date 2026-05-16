package cli

import (
	"fmt"
	"io"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// renderSuggestions prints actionable remediation hints for every blocked
// dependency. Uses domain.BuildFixPlan to compute the upgrade target —
// the highest FixedIn across all advisories on that dep — so the user
// sees "upgrade to 4.17.21" instead of a generic "@latest".
func renderSuggestions(out io.Writer, result usecase.CIResult) {
	blocked := make([]usecase.CIFinding, 0, len(result.Findings))
	for _, f := range result.Findings {
		if f.Verdict >= result.FailOn {
			blocked = append(blocked, f)
		}
	}
	if len(blocked) == 0 {
		fmt.Fprintln(out, "no suggestions — all deps pass")
		return
	}

	// Build a per-dep lookup of fix targets from BuildFixPlan so we can
	// reuse the same algorithm aegis fix uses.
	targets := make(map[string]string, len(blocked))
	resolved := make(map[string][]domain.Advisory, len(blocked))
	for _, f := range blocked {
		item := domain.BuildFixPlan(domain.Snapshot{Deps: []domain.Dependency{f.Dep}})
		if len(item.Items) == 0 {
			continue
		}
		key := f.Dep.VersionedKey()
		targets[key] = item.Items[0].TargetVersion
		resolved[key] = item.Items[0].ResolvedAdvisories
	}

	fmt.Fprintf(out, "suggested remediation for %d blocked dep(s):\n\n", len(blocked))
	for _, f := range blocked {
		dep := f.Dep
		fmt.Fprintf(out, "  %s@%s  [%s]\n", dep.Name, dep.Version, f.Verdict)

		for _, adv := range dep.Advisories {
			if adv.VEXSuppressed {
				continue
			}
			fmt.Fprintf(out, "    ⚠  %s: %s\n", adv.ID, adv.Summary)
			if adv.URL != "" {
				fmt.Fprintf(out, "       %s\n", adv.URL)
			}
		}

		for _, flag := range f.Risk.Flags {
			if flag.Suppressed {
				continue
			}
			switch flag.Code {
			case "version-unpublished":
				fmt.Fprintf(out, "    ⚠  version was yanked from registry — upgrade immediately\n")
			case "install-hook-suspicious":
				fmt.Fprintf(out, "    ⚠  install hook matches malware pattern — remove or replace this dep\n")
			case "known-malware-ioc":
				fmt.Fprintf(out, "    ⚠  confirmed malware IOC — remove immediately\n")
			}
		}

		target := targets[dep.VersionedKey()]
		if cmd := domain.UpgradeCommand(dep, target); cmd != "" {
			fmt.Fprintf(out, "    →  %s\n", cmd)
		}
		fmt.Fprintln(out)
	}
}
