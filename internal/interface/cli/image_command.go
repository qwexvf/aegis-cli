package cli

import (
	"fmt"

	"github.com/qwexvf/aegis-cli/internal/domain"
	presentercli "github.com/qwexvf/aegis-cli/internal/presenter/cli"
	"github.com/qwexvf/aegis-cli/internal/usecase"
	"github.com/spf13/cobra"
)

// imageCommand wires `aegis image scan` — supply-chain analysis on
// OCI / Docker image tars.
//
// v1 input: local tar file (`docker save -o image.tar` output, or
// any OCI-format archive).
// v2 will add registry pull (`aegis image scan ubuntu:22.04`).
func imageCommand(uc *usecase.Image, presenter *presentercli.ImagePresenter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "image",
		Short: "Scan OCI / Docker container images for supply-chain risks",
	}
	cmd.AddCommand(imageScanCommand(uc, presenter))
	return cmd
}

func imageScanCommand(uc *usecase.Image, presenter *presentercli.ImagePresenter) *cobra.Command {
	var (
		enrich         bool
		capabilities   bool
		jsonOut        bool
		noManifestWalk bool
		failOnStr      string
	)
	c := &cobra.Command{
		Use:   "scan <image.tar>",
		Short: "Extract lockfiles from an OCI image tar and (optionally) run OSV vuln lookup",
		Long: `scan reads a local Docker save / OCI image tar, overlays every layer
(whiteout-aware), extracts any lockfile the locksnap registry recognises,
and reports the resulting dependency set.

By default the scanner also walks per-package manifests
(node_modules/<pkg>/package.json, *.dist-info/METADATA, gems/<name>-<ver>/,
vendor/<v>/<p>/composer.json) and synthesizes deps that lockfiles miss —
common in distroless and multi-stage builds where lockfiles never land
in the final image. Pass --no-manifest-walk to disable.

Pass --enrich to additionally run the configured OSV.dev vulnerability
lookup against the extracted deps. Without --enrich, scan is purely
local — useful for SBOM bootstrap and offline workflows.

Examples:

  docker save my-app:latest -o my-app.tar
  aegis image scan my-app.tar
  aegis image scan my-app.tar --enrich
  aegis image scan my-app.tar --no-manifest-walk      # lockfile-only mode
  aegis image scan my-app.tar --json | jq '.deps[].name'`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			presenter.SetJSONMode(jsonOut)
			// --fail-on gates on CVE severity, which needs the OSV lookup.
			var failOn domain.Severity
			gate := failOnStr != ""
			if gate {
				var perr error
				failOn, perr = parseSeverity(failOnStr)
				if perr != nil {
					return &exitCodeError{code: 2, err: perr, silent: false}
				}
				enrich = true // severity gate requires advisories
			}
			result, err := uc.Run(cmd.Context(), usecase.ImageRequest{
				Path:           args[0],
				Enrich:         enrich,
				Capabilities:   capabilities,
				NoManifestWalk: noManifestWalk,
			})
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			if err != nil {
				return &exitCodeError{code: 2, err: err, silent: true}
			}
			if gate {
				worst := domain.SevInfo
				for _, advs := range result.Advisories {
					if s := domain.MaxSeverity(advs); domain.SeverityAtLeast(s, worst) {
						worst = s
					}
				}
				if domain.SeverityAtLeast(worst, failOn) && worst != domain.SevInfo {
					return &exitCodeError{code: 1, silent: true,
						err: fmt.Errorf("image scan: found advisories at or above %s severity", failOn)}
				}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&enrich, "enrich", false,
		"run OSV.dev vulnerability lookup against the extracted dependency set")
	c.Flags().BoolVar(&capabilities, "capabilities", false,
		"AST-scan every package found inside the image (tree-sitter capability + heuristic detection — finds malware Trivy can't)")
	c.Flags().BoolVar(&noManifestWalk, "no-manifest-walk", false,
		"skip per-package manifest scanning (node_modules/, site-packages/, gems/, vendor/) — lockfile-only mode")
	c.Flags().BoolVar(&jsonOut, "json", false,
		"emit machine-readable JSON on stdout (suppresses human output)")
	c.Flags().StringVar(&failOnStr, "fail-on", "",
		"exit non-zero when a CVE at or above this severity is found: low|medium|high|critical (implies --enrich)")
	return c
}
