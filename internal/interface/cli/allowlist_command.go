package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
	"github.com/qwexvf/aegis/services/cli/internal/infra/allowlist"
	presentercli "github.com/qwexvf/aegis/services/cli/internal/presenter/cli"
	"github.com/spf13/cobra"
)

// allowlistCommand wires `aegis allowlist <list|add|remove|test>`.
// loaderFactory returns a Loader rooted at the current cwd so that
// `aegis allowlist add ... --scope=project` writes to the project the
// user is actually in (not where main.go was wired).
func allowlistCommand(loaderFactory func() *allowlist.Loader, presenter *presentercli.AllowlistPresenter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "allowlist",
		Short: "Manage capability suppressions for specific packages",
	}
	cmd.AddCommand(allowlistListCommand(loaderFactory, presenter))
	cmd.AddCommand(allowlistAddCommand(loaderFactory, presenter))
	cmd.AddCommand(allowlistRemoveCommand(loaderFactory, presenter))
	cmd.AddCommand(allowlistTestCommand(loaderFactory, presenter))
	return cmd
}

func allowlistListCommand(loaderFactory func() *allowlist.Loader, p *presentercli.AllowlistPresenter) *cobra.Command {
	var sourceFilter string
	c := &cobra.Command{
		Use:   "list",
		Short: "Show all allowlist rules (builtin + user + project)",
		RunE: func(cmd *cobra.Command, args []string) error {
			rules, err := loaderFactory().LoadRaw()
			if err != nil {
				p.OnError(err)
				return err
			}
			if sourceFilter != "" {
				kept := rules[:0]
				for _, r := range rules {
					if r.Source == sourceFilter {
						kept = append(kept, r)
					}
				}
				rules = kept
			}
			p.OnList(rules)
			return nil
		},
	}
	c.Flags().StringVar(&sourceFilter, "source", "", "filter by source (builtin|user|project)")
	return c
}

func allowlistAddCommand(loaderFactory func() *allowlist.Loader, p *presentercli.AllowlistPresenter) *cobra.Command {
	var (
		ecoFlag, capFlag, versionFlag, reasonFlag, scopeFlag string
	)
	c := &cobra.Command{
		Use:   "add <name>",
		Short: "Add an allowlist rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scope, ok := allowlist.ScopeFromString(scopeFlag)
			if !ok {
				return fmt.Errorf("invalid --scope %q (use user or project)", scopeFlag)
			}
			rule := domain.AllowRule{
				Ecosystem:    domain.Ecosystem(ecoFlag),
				Name:         args[0],
				VersionRange: versionFlag,
				Reason:       reasonFlag,
			}
			if capFlag != "" && capFlag != "*" {
				cap, ok := capabilityByName(capFlag)
				if !ok {
					return fmt.Errorf("unknown capability %q", capFlag)
				}
				rule.Capability = cap
			}
			if err := loaderFactory().AddRule(scope, rule); err != nil {
				p.OnError(err)
				return err
			}
			p.OnRuleAdded(scopeFlag, rule)
			return nil
		},
	}
	c.Flags().StringVar(&ecoFlag, "ecosystem", "npm", "ecosystem (npm|pypi|crates|...)")
	c.Flags().StringVar(&capFlag, "capability", "", "capability code to suppress (omit for any)")
	c.Flags().StringVar(&versionFlag, "version", "", "semver range (omit for any)")
	c.Flags().StringVar(&reasonFlag, "reason", "", "explanation (recommended)")
	c.Flags().StringVar(&scopeFlag, "scope", "user", "user|project")
	return c
}

func allowlistRemoveCommand(loaderFactory func() *allowlist.Loader, p *presentercli.AllowlistPresenter) *cobra.Command {
	var (
		ecoFlag, capFlag, scopeFlag string
	)
	c := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove allowlist rule(s) matching name (and optionally capability)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scope, ok := allowlist.ScopeFromString(scopeFlag)
			if !ok {
				return fmt.Errorf("invalid --scope %q", scopeFlag)
			}
			name := args[0]
			eco := domain.Ecosystem(ecoFlag)
			var capFilter domain.Capability
			if capFlag != "" && capFlag != "*" {
				c, ok := capabilityByName(capFlag)
				if !ok {
					return fmt.Errorf("unknown capability %q", capFlag)
				}
				capFilter = c
			}
			n, err := loaderFactory().RemoveRule(scope, func(r domain.AllowRule) bool {
				if r.Ecosystem != eco || r.Name != name {
					return false
				}
				if capFilter != 0 && r.Capability != capFilter {
					return false
				}
				return true
			})
			if err != nil {
				p.OnError(err)
				return err
			}
			p.OnRuleRemoved(scopeFlag, n)
			return nil
		},
	}
	c.Flags().StringVar(&ecoFlag, "ecosystem", "npm", "ecosystem (npm|pypi|crates|...)")
	c.Flags().StringVar(&capFlag, "capability", "", "narrow removal to a specific capability")
	c.Flags().StringVar(&scopeFlag, "scope", "user", "user|project")
	return c
}

// allowlistTestCommand: `aegis allowlist test npm/lodash@4.17.21`.
// Emits the list of rules that suppress capabilities for that target.
func allowlistTestCommand(loaderFactory func() *allowlist.Loader, p *presentercli.AllowlistPresenter) *cobra.Command {
	return &cobra.Command{
		Use:   "test <ecosystem>/<name>@<version>",
		Short: "Show which allowlist rules suppress capabilities for a (eco, name, version)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			eco, name, version, err := parseTestSpec(args[0])
			if err != nil {
				return err
			}
			set, err := loaderFactory().Load()
			if err != nil {
				p.OnError(err)
				return err
			}
			matches := []presentercli.MatchedRule{}
			for _, c := range domain.AllCapabilities() {
				if ok, rule := set.Suppresses(eco, name, version, c); ok {
					matches = append(matches, presentercli.NewMatchedRule(c, rule))
				}
			}
			p.OnTest(eco, name, version, matches)
			return nil
		},
	}
}

// parseTestSpec accepts "ecosystem/name@version", e.g. "npm/lodash@4.17.21"
// or "npm/@scope/name@1.2.3". Scoped names retain the leading "@".
func parseTestSpec(s string) (domain.Ecosystem, string, string, error) {
	slash := strings.Index(s, "/")
	if slash <= 0 {
		return "", "", "", fmt.Errorf("expected <ecosystem>/<name>@<version>, got %q", s)
	}
	eco := domain.Ecosystem(s[:slash])
	rest := s[slash+1:]
	at := strings.LastIndex(rest, "@")
	if at <= 0 {
		return "", "", "", fmt.Errorf("expected <name>@<version> in %q", rest)
	}
	return eco, rest[:at], rest[at+1:], nil
}

// capabilityByName matches Capability.String() output. Used by add/remove
// flags so users type the same string they see in `allowlist list` output.
func capabilityByName(s string) (domain.Capability, bool) {
	for _, c := range domain.AllCapabilities() {
		if c.String() == s {
			return c, true
		}
	}
	return 0, false
}

// stub usage of os to keep imports tidy if future expansions need it.
var _ = os.Stdout
