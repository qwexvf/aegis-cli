package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
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
		evidence     bool
		jsonOut      bool
		localPath    string
		ecoFlag      string
		baselinePath string
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

With --ecosystem neovim, the positional argument is interpreted as a
directory containing a Neovim plugin (Lua source, no manifest). Name is
derived from the directory basename, Version from the git HEAD SHA. No
registry fetch happens; the AST scanner is the entire signal.

With --baseline <path>, the scanner compares the resulting capabilities
against a previous --json output (cached at <path>). Exits 1 with a
diff of new capabilities when the current scan introduces any that
weren't in the baseline. Plugin managers use this for "did this update
get worse?" checks — capability shrinkage is fine, capability growth
is a regression worth surfacing.

Examples:
  aegis analyze lodash@4.17.21
  aegis analyze @solana/web3.js@1.95.4
  aegis analyze npm/event-stream@3.3.6
  aegis analyze rubygems/rest-client@1.6.13 --local examples/incidents/rubygems/rest-client-1.6.13/
  aegis analyze --ecosystem neovim ./packer.nvim
  aegis analyze --ecosystem neovim ./packer.nvim --baseline ~/.cache/aegis/packer.nvim.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			eco, name, version, err := resolveAnalyzeTarget(args[0], ecoFlag, &localPath)
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
			if baselinePath != "" {
				added, err := capabilityRegression(baselinePath, result)
				if err != nil {
					return &exitCodeError{code: 2, err: fmt.Errorf("--baseline: %w", err), silent: false}
				}
				if len(added) > 0 {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"\n! capability regression vs baseline (%s): added %s\n",
						baselinePath, strings.Join(added, ", "))
					return &exitCodeError{code: 1,
						err:    fmt.Errorf("%s@%s: new capabilities since baseline", name, version),
						silent: true}
				}
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
	cmd.Flags().StringVar(&ecoFlag, "ecosystem", "",
		"interpret the positional argument as a directory for the given ecosystem (currently: neovim)")
	cmd.Flags().StringVar(&baselinePath, "baseline", "",
		"path to a prior --json output; exits 1 when the current scan adds new capabilities")
	return cmd
}

// capabilityRegression compares the current analyze result against a
// previously-saved JSON output (the shape produced by `aegis analyze --json`).
// Returns the set of capability strings that appear in current but not in
// the baseline — capability shrinkage and unchanged sets return nil.
// Errors out only when the baseline file is unreadable or malformed; an
// absent capabilities field decodes to an empty list (no baseline caps =
// any current cap is a regression).
func capabilityRegression(baselinePath string, current usecase.AnalyzeResult) ([]string, error) {
	raw, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, err
	}
	var prior struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(raw, &prior); err != nil {
		return nil, fmt.Errorf("decode baseline JSON: %w", err)
	}
	priorSet := make(map[string]struct{}, len(prior.Capabilities))
	for _, c := range prior.Capabilities {
		priorSet[c] = struct{}{}
	}
	var added []string
	for _, c := range current.Fingerprint.Capabilities {
		name := c.String()
		if _, ok := priorSet[name]; ok {
			continue
		}
		added = append(added, name)
	}
	sort.Strings(added)
	return added, nil
}

// resolveAnalyzeTarget unifies the two analyze invocation shapes:
//
//   - `analyze [eco/]name@version [--local <dir>]` — the canonical
//     pkg-spec path, used for every registry-backed ecosystem.
//   - `analyze --ecosystem <eco> <dir>` — the manifestless-source path,
//     currently used only by EcoNeovim where plugins have no registry
//     and no pkg-spec syntax. Name is derived from the directory
//     basename, Version from the git HEAD SHA (or "unknown" when the
//     dir isn't a git checkout).
//
// When the manifestless path is taken, the localPath pointer is updated
// in place so the use case sees the directory as LocalPath without the
// caller having to also pass --local.
func resolveAnalyzeTarget(positional, ecoFlag string, localPath *string) (domain.Ecosystem, string, string, error) {
	if ecoFlag == "" {
		eco, name, version, err := parsePkgSpec(positional)
		return eco, name, version, err
	}
	if !isKnownEcosystem(ecoFlag) {
		return "", "", "", fmt.Errorf("--ecosystem %q: unknown ecosystem", ecoFlag)
	}
	eco := domain.Ecosystem(ecoFlag)
	if eco != domain.EcoNeovim {
		return "", "", "", fmt.Errorf("--ecosystem %s: manifestless dir mode is only implemented for neovim today", eco)
	}
	dir := positional
	if *localPath == "" {
		*localPath = dir
	}
	name := filepath.Base(strings.TrimRight(dir, "/"))
	if name == "" || name == "." || name == "/" {
		return "", "", "", fmt.Errorf("--ecosystem %s: could not derive plugin name from %q", eco, dir)
	}
	version := gitHeadSHA(dir)
	if version == "" {
		version = "unknown"
	}
	return eco, name, version, nil
}

// gitHeadSHA returns the short commit SHA at HEAD of the given dir, or
// the empty string when dir isn't a git checkout. Best-effort: any git
// failure (missing binary, detached HEAD without commits, bare repo)
// yields "" and the caller falls back to a placeholder version.
func gitHeadSHA(dir string) string {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--short", "HEAD")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return ""
	}
	return strings.TrimSpace(out.String())
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

// isKnownEcosystem reports whether s is one of the ecosystems the CLI
// recognises. Registry-fetch only supports npm; others are valid for
// --local AST scans (py / ruby / gleam / ...).
func isKnownEcosystem(s string) bool {
	return slices.Contains(domain.AllEcosystems(), domain.Ecosystem(s))
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
