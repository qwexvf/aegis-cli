package cli

import (
	"fmt"
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
	cmd.AddCommand(allowlistVerifyCommand(loaderFactory, presenter))
	cmd.AddCommand(allowlistSyncCommand(loaderFactory, presenter))
	return cmd
}

// allowlistSyncCommand: `aegis allowlist sync`. Pulls the org overlay
// from the server and writes it to ~/.aegis/cache/org-allowlist.yaml.
// Subsequent `aegis bun add ...` invocations layer it between user
// and project rules without further network calls.
//
// Without `--force` the cache is reused while it's younger than the
// loader's TTL (1h by default). CI pipelines should pass --force to
// guarantee they have the latest org policy.
func allowlistSyncCommand(loaderFactory func() *allowlist.Loader, p *presentercli.AllowlistPresenter) *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "sync",
		Short: "Fetch the org allowlist overlay from the API and cache it locally",
		RunE: func(cmd *cobra.Command, args []string) error {
			s := loaderFactory().Server()
			if s == nil {
				return fmt.Errorf("server allowlist not configured (set AEGIS_API_URL + AEGIS_API_KEY)")
			}
			if !force && s.IsFresh() {
				age, _ := s.CacheAge()
				p.OnSyncSkipped(age)
				return nil
			}
			n, err := s.Sync(cmd.Context())
			if err != nil {
				p.OnError(err)
				return err
			}
			p.OnSyncOK(n, s.CachePath())
			return nil
		},
	}
	c.Flags().BoolVar(&force, "force", false, "ignore cache freshness and re-fetch")
	return c
}

func allowlistVerifyCommand(loaderFactory func() *allowlist.Loader, p *presentercli.AllowlistPresenter) *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Validate user and project allowlist YAML files",
		RunE: func(cmd *cobra.Command, args []string) error {
			results := loaderFactory().Verify()
			anyFailed := false
			for _, r := range results {
				if r.Err != nil {
					anyFailed = true
					p.OnVerifyFailed(r.Source+": "+r.Path, r.Err)
				} else {
					path := r.Path
					if path == "" {
						path = "(builtin)"
					}
					p.OnVerifyOK(r.Source+": "+path, r.RuleCount)
				}
			}
			if anyFailed {
				return fmt.Errorf("one or more allowlist files failed verification")
			}
			return nil
		},
	}
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
			// Reason is required for audit trail. Allow opt-out via
			// --no-reason for one-off testing, but the default makes
			// the safe path the easy path.
			if reasonFlag == "" {
				return fmt.Errorf("--reason is required (audit trail); pass an explanation, e.g. --reason='legitimate build tool'")
			}
			rule := domain.AllowRule{
				Ecosystem:    domain.Ecosystem(ecoFlag),
				Name:         args[0],
				VersionRange: versionFlag,
				Reason:       reasonFlag,
			}
			if capFlag != "" && capFlag != "*" {
				c, ok := capabilityByName(capFlag)
				if !ok {
					return fmt.Errorf("unknown capability %q", capFlag)
				}
				rule.Capability = c
			}
			replaced, err := loaderFactory().AddRule(scope, rule)
			if err != nil {
				p.OnError(err)
				return err
			}
			if replaced {
				p.OnRuleReplaced(scopeFlag, rule)
			} else {
				p.OnRuleAdded(scopeFlag, rule)
			}
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
			// MatchAll walks rules once (not Capabilities × rules),
			// so Capability=0 rules collapse into a single
			// "any-capability" line in the output instead of
			// flooding with one line per Capability.
			matches := set.MatchAll(eco, name, version)
			out := make([]presentercli.MatchedRule, 0, len(matches))
			for _, m := range matches {
				out = append(out, presentercli.MatchedRule{
					Capability:    m.Capability,
					CapabilityAny: m.Kind == domain.MatchAny,
					Rule:          m.Rule,
				})
			}
			p.OnTest(eco, name, version, out)
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
