package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/qwexvf/aegis-cli/internal/infra/atomicwrite"
	"github.com/qwexvf/aegis-cli/internal/usecase"
	"github.com/spf13/cobra"
)

// Human summary lands on stderr so the SBOM JSON on stdout stays
// pipe-clean (`aegis sbom | jq …` must not see "wrote N components").
func sbomCommand(uc *usecase.Sbom) *cobra.Command {
	var (
		includeVulns bool
		outputPath   string
		project      string
		pretty       bool
	)
	c := &cobra.Command{
		Use:   "sbom",
		Short: "Emit a CycloneDX 1.5 JSON SBOM from the saved snapshot",
		Long: "Emit a CycloneDX 1.5 JSON Software Bill of Materials built from " +
			"aegis.lock. License, supplier, and download-URL fields are left as " +
			"NOASSERTION in V1 (those fields are not currently collected). Pass " +
			"--include-vulns for a live re-query against the configured " +
			"vulnerability sources (OSV / GHSA / deps.dev / aegis, per config).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			opts := usecase.SbomOptions{
				Project:                project,
				IncludeVulnerabilities: includeVulns,
				Pretty:                 pretty,
			}

			if outputPath == "" {
				comps, vulns, err := uc.Generate(cmd.Context(), cwd, cmd.OutOrStdout(), opts)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "aegis: wrote SBOM with %d components, %d vulnerabilities to stdout\n", comps, vulns)
				return nil
			}

			var comps, vulns int
			err = atomicwrite.WriteFileFunc(outputPath, 0o644, func(w io.Writer) error {
				var e error
				comps, vulns, e = uc.Generate(cmd.Context(), cwd, w, opts)
				return e
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "aegis: wrote SBOM with %d components, %d vulnerabilities to %s\n", comps, vulns, outputPath)
			return nil
		},
	}
	c.Flags().BoolVar(&includeVulns, "include-vulns", false, "live re-query of configured vulnerability sources")
	c.Flags().StringVarP(&outputPath, "output", "o", "", "write SBOM to this path (default: stdout)")
	c.Flags().StringVar(&project, "project", "", "override the root component name (default: snapshot.project)")
	c.Flags().BoolVar(&pretty, "pretty", false, "pretty-print the JSON output")
	return c
}
