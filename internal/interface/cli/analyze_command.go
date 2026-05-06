package cli

import (
	"fmt"
	"strings"

	"github.com/qwexvf/aegis-cli/internal/domain"
	presentercli "github.com/qwexvf/aegis-cli/internal/presenter/cli"
	"github.com/qwexvf/aegis-cli/internal/usecase"
	"github.com/spf13/cobra"
)

// analyzeCommand wires the on-demand `aegis analyze <pkg-spec>` use
// case to argv. Spec format is [ecosystem/]name@version. Default
// ecosystem is npm.
//
// Exit codes:
//
//	0   verdict safe or review (clean enough to install)
//	1   verdict prompt or block (don't install without review)
//	2   fetch / analyze error (couldn't reach a verdict)
func analyzeCommand(uc *usecase.Analyze, presenter *presentercli.AnalyzePresenter) *cobra.Command {
	var (
		evidence  bool
		jsonOut   bool
		localPath string
	)
	cmd := &cobra.Command{
		Use:   "analyze <pkg-spec>",
		Short: "Fetch and AST-scan a single package — fallback when the incident DB has no record",
		Long: `analyze fetches the package's distribution from the registry, runs the
AST risk scanner over its source, applies the allowlist, and prints
a verdict. Spec is [ecosystem/]name@version. Default ecosystem is npm.

With --local <path>, the registry fetch is skipped and the source is
read from the on-disk directory at <path> instead. The spec is still
required as a label for the result. Useful for fixture-based testing
(examples/incidents/...) and for analysing a tree before publish.

Examples:
  aegis analyze lodash@4.17.21
  aegis analyze @solana/web3.js@1.95.4
  aegis analyze npm/event-stream@3.3.6
  aegis analyze rubygems/rest-client@1.6.13 --local examples/incidents/rubygems/rest-client-1.6.13/`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			eco, name, version, err := parsePkgSpec(args[0])
			if err != nil {
				return err
			}
			presenter.SetJSONMode(jsonOut)
			result, runErr := uc.Run(cmd.Context(), usecase.AnalyzeRequest{
				Ecosystem:    eco,
				Name:         name,
				Version:      version,
				WantEvidence: evidence || jsonOut,
				LocalPath:    localPath,
			})
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			if runErr != nil {
				// Couldn't reach a verdict (fetch / analyze error). The
				// presenter already rendered the failure; suppress the
				// duplicate "aegis: <err>" line in Execute.
				return &exitCodeError{code: 2, err: runErr, silent: true}
			}
			switch result.Verdict {
			case domain.VerdictBlock, domain.VerdictPrompt:
				// Got a verdict, it's bad. Same: presenter already
				// rendered a formatted block — exit non-zero silently.
				return &exitCodeError{code: 1,
					err:    fmt.Errorf("%s@%s: %s", name, version, result.Verdict),
					silent: true}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&evidence, "evidence", false,
		"include file:line snippets for each detected capability")
	cmd.Flags().BoolVar(&jsonOut, "json", false,
		"emit a machine-readable JSON object to stdout (suppresses human output)")
	cmd.Flags().StringVar(&localPath, "local", "",
		"read package source from this on-disk directory instead of fetching from the registry")
	return cmd
}

// parsePkgSpec parses [ecosystem/]name@version. Handles scoped
// packages (@scope/name) by using the LAST '@' as the version
// separator. Default ecosystem is npm.
//
// Examples:
//
//	"lodash@4.17.21"               → npm, lodash, 4.17.21
//	"@solana/web3.js@1.95.4"       → npm, @solana/web3.js, 1.95.4
//	"npm/event-stream@3.3.6"       → npm, event-stream, 3.3.6
//	"npm/@solana/web3.js@1.95.4"   → npm, @solana/web3.js, 1.95.4
func parsePkgSpec(s string) (domain.Ecosystem, string, string, error) {
	eco := domain.EcoNpm

	// Detect ecosystem prefix only when the spec doesn't start with
	// '@' (which means a scoped npm package, not an ecosystem name).
	if !strings.HasPrefix(s, "@") {
		if idx := strings.Index(s, "/"); idx > 0 {
			ecoStr := s[:idx]
			if isKnownEcosystem(ecoStr) {
				eco = domain.Ecosystem(ecoStr)
				s = s[idx+1:]
			}
		}
	}

	at := strings.LastIndex(s, "@")
	// at <= 0 catches both "no @" and "@scope/name" with no version.
	if at <= 0 {
		return "", "", "", fmt.Errorf("invalid package spec %q: expected [ecosystem/]name@version", s)
	}
	name := s[:at]
	version := s[at+1:]
	if name == "" || version == "" {
		return "", "", "", fmt.Errorf("invalid package spec %q: name and version both required", s)
	}
	return eco, name, version, nil
}

// isKnownEcosystem returns true for the ecosystem strings the analyzer
// recognises. The registry-fetch path only supports npm today; the
// other ecosystems are accepted so `--local` can scan their on-disk
// source via the AST scanners (pyscan / rbscan / ...).
//
// TODO(ecosystems): derive this from the set of registered fetchers
// + scanners in the composition root rather than a hand-maintained
// switch.
func isKnownEcosystem(s string) bool {
	switch s {
	case "npm", "pypi", "rubygems", "crates", "go", "maven", "packagist":
		return true
	}
	return false
}

// exitCodeError lets RunE return a specific exit code. Execute() is
// responsible for translating it via os.Exit. When silent is true,
// Execute skips the default "aegis: <err>" stderr line — used when
// the presenter has already rendered a richer message (e.g. a verdict
// block) and the bare error string would just duplicate it.
type exitCodeError struct {
	code   int
	err    error
	silent bool
}

func (e *exitCodeError) Error() string { return e.err.Error() }
func (e *exitCodeError) Unwrap() error { return e.err }
func (e *exitCodeError) ExitCode() int { return e.code }
func (e *exitCodeError) Silent() bool  { return e.silent }
