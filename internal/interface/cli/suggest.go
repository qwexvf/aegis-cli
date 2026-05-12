package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// renderSuggestions prints actionable remediation hints for every blocked
// dependency. For advisory-flagged packages it links to the advisory URL;
// for heuristic-flagged packages it suggests removing or replacing the dep.
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

	fmt.Fprintf(out, "suggested remediation for %d blocked dep(s):\n\n", len(blocked))
	for _, f := range blocked {
		dep := f.Dep
		fmt.Fprintf(out, "  %s@%s  [%s]\n", dep.Name, dep.Version, f.Verdict)

		// Advisory links.
		for _, adv := range dep.Advisories {
			fmt.Fprintf(out, "    ⚠  %s: %s\n", adv.ID, adv.Summary)
			if adv.URL != "" {
				fmt.Fprintf(out, "       %s\n", adv.URL)
			}
		}

		// Heuristic flags (non-advisory).
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

		// Upgrade command.
		if cmd := upgradeCommand(dep); cmd != "" {
			fmt.Fprintf(out, "    →  %s\n", cmd)
		}
		fmt.Fprintln(out)
	}
}

// upgradeCommand returns the ecosystem-appropriate upgrade shell command.
func upgradeCommand(dep domain.Dependency) string {
	name := dep.Name
	switch dep.Ecosystem {
	case domain.EcoNpm:
		return fmt.Sprintf("npm install %s@latest", name)
	case domain.EcoPyPI:
		return fmt.Sprintf("pip install --upgrade %s", name)
	case domain.EcoRubyGems:
		return fmt.Sprintf("bundle update %s", name)
	case domain.EcoCrates:
		return fmt.Sprintf("cargo update %s", strings.ReplaceAll(name, "/", "-"))
	case domain.EcoGo:
		return fmt.Sprintf("go get %s@latest", name)
	case domain.EcoMaven:
		// Maven coords are groupId:artifactId
		parts := strings.SplitN(name, ":", 2)
		if len(parts) == 2 {
			return fmt.Sprintf("mvn versions:use-latest-versions -Dincludes=%s:%s", parts[0], parts[1])
		}
	case domain.EcoPackagist:
		return fmt.Sprintf("composer update %s", name)
	case domain.EcoNuGet:
		return fmt.Sprintf("dotnet add package %s", name)
	case domain.EcoGleam:
		return "gleam deps update"
	}
	return ""
}
