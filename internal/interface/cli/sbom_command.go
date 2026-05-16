package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"

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
		cdxVersion   string
		format       string
		sign         bool
	)
	c := &cobra.Command{
		Use:   "sbom",
		Short: "Emit a CycloneDX or SPDX 2.3 SBOM from the saved snapshot",
		Long: "Emit a Software Bill of Materials built from aegis.lock. " +
			"Use --format=cyclonedx (default) for CycloneDX JSON or --format=spdx " +
			"for SPDX 2.3 JSON (required by US EO 14028 / federal procurement). " +
			"Pass --include-vulns for a live re-query against the configured " +
			"vulnerability sources. Use --cdx-version=1.6 for the CycloneDX 1.6 " +
			"spec (adds lifecycles metadata; default is 1.5). " +
			"Use --sign to produce a keyless Sigstore signature alongside the SBOM " +
			"(requires cosign in PATH; uses OIDC ambient credentials).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			if format != "cyclonedx" && format != "spdx" {
				return fmt.Errorf("--format: unsupported value %q (use cyclonedx or spdx)", format)
			}
			if format == "cyclonedx" && cdxVersion != "1.5" && cdxVersion != "1.6" {
				return fmt.Errorf("--cdx-version: unsupported value %q (use 1.5 or 1.6)", cdxVersion)
			}
			if sign && outputPath == "" {
				return fmt.Errorf("--sign requires --output: cosign cannot sign stdout")
			}

			opts := usecase.SbomOptions{
				Project:                project,
				IncludeVulnerabilities: includeVulns,
				Pretty:                 pretty,
				CdxVersion:             cdxVersion,
				Format:                 format,
			}

			if outputPath == "" {
				comps, vulns, err := uc.Generate(cmd.Context(), cwd, cmd.OutOrStdout(), opts)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "aegis: wrote %s SBOM with %d components, %d vulnerabilities to stdout\n", format, comps, vulns)
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
			fmt.Fprintf(cmd.ErrOrStderr(), "aegis: wrote %s SBOM with %d components, %d vulnerabilities to %s\n", format, comps, vulns, outputPath)

			if sign {
				if err := cosignBlob(outputPath); err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "aegis: signature → %s.sig  certificate → %s.pem\n", outputPath, outputPath)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&includeVulns, "include-vulns", false, "live re-query of configured vulnerability sources")
	c.Flags().StringVarP(&outputPath, "output", "o", "", "write SBOM to this path (default: stdout)")
	c.Flags().StringVar(&project, "project", "", "override the root component name (default: snapshot.project)")
	c.Flags().BoolVar(&pretty, "pretty", false, "pretty-print the JSON output")
	c.Flags().StringVar(&cdxVersion, "cdx-version", "1.5", "CycloneDX spec version to emit: 1.5 or 1.6")
	c.Flags().StringVar(&format, "format", "cyclonedx", "output format: cyclonedx or spdx")
	c.Flags().BoolVar(&sign, "sign", false, "sign the SBOM with cosign keyless OIDC (requires --output and cosign in PATH)")
	return c
}

// cosignBlob signs path using cosign keyless OIDC, producing path.sig and path.pem.
func cosignBlob(path string) error {
	cosign, err := exec.LookPath("cosign")
	if err != nil {
		return fmt.Errorf("--sign: cosign not found in PATH — install from https://github.com/sigstore/cosign/releases")
	}
	cmd := exec.Command(cosign, "sign-blob",
		"--output-signature", path+".sig",
		"--output-certificate", path+".pem",
		path,
	)
	cmd.Stdout = os.Stderr // cosign progress goes to stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cosign sign-blob: %w", err)
	}
	return nil
}
