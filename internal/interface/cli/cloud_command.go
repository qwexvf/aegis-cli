package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/qwexvf/aegis-cli/internal/infra/aegisapi"
	"github.com/spf13/cobra"
)

// cloudCommand wires `aegis cloud <analyze>`.
func cloudCommand(api *aegisapi.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cloud",
		Short: "Cloud-backed analysis commands",
	}
	cmd.AddCommand(cloudAnalyzeCommand(api))
	return cmd
}

// cloudAnalyzeCommand implements `aegis cloud analyze <ecosystem/name@version>`.
//
// Examples:
//
//	aegis cloud analyze npm/lodash@4.17.21
//	aegis cloud analyze pypi/requests@2.31.0
//	aegis cloud analyze npm/lodash@4.17.21 --no-wait
//
// AEGIS_API_KEY must be set. The command submits the package to the cloud
// sandbox, then polls for completion (printing dots) unless --no-wait is given.
func cloudAnalyzeCommand(api *aegisapi.Client) *cobra.Command {
	var noWait bool

	c := &cobra.Command{
		Use:   "analyze <ecosystem/name@version>",
		Short: "Submit a package for cloud sandbox analysis",
		Long: `Submit a single package to the Aegis cloud sandbox for dynamic analysis.

The argument must be in the form ecosystem/name@version, e.g.:

  aegis cloud analyze npm/lodash@4.17.21
  aegis cloud analyze pypi/requests@2.31.0

Version may be omitted to analyze the latest published release:

  aegis cloud analyze npm/lodash

Requires AEGIS_API_KEY to be set.

By default the command polls for completion (up to 5 minutes) and prints
the findings count on success. Use --no-wait for fire-and-forget CI steps.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Getenv("AEGIS_API_KEY") == "" {
				fmt.Fprintln(os.Stderr, "aegis: AEGIS_API_KEY is not set — export it before running cloud analyze")
				fmt.Fprintln(os.Stderr, "  export AEGIS_API_KEY=<your-key>")
				return &exitCodeError{code: 1, err: fmt.Errorf("AEGIS_API_KEY not set"), silent: true}
			}

			ecosystem, name, version, err := parsePackageArg(args[0])
			if err != nil {
				return err
			}

			jobID, streamURL, err := api.TriggerSandbox(cmd.Context(), ecosystem, name, version)
			if err != nil {
				return fmt.Errorf("cloud analyze: %w", err)
			}

			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "cloud analyze: submitted %s/%s@%s\n", ecosystem, name, version)
			fmt.Fprintf(w, "  job id:     %s\n", jobID)
			if streamURL != "" {
				fmt.Fprintf(w, "  stream url: %s\n", streamURL)
			}

			if noWait {
				fmt.Fprintln(w, "cloud analyze: --no-wait set, exiting (job running in background)")
				return nil
			}

			fmt.Fprintf(w, "cloud analyze: waiting for results")
			const pollInterval = 3 * time.Second
			const timeout = 5 * time.Minute
			deadline := time.Now().Add(timeout)

			for time.Now().Before(deadline) {
				select {
				case <-cmd.Context().Done():
					fmt.Fprintln(w)
					return cmd.Context().Err()
				case <-time.After(pollInterval):
				}
				fmt.Fprintf(w, ".")

				status, findingsCount, err := api.SandboxStatus(cmd.Context(), jobID)
				if err != nil {
					fmt.Fprintln(w)
					return fmt.Errorf("cloud analyze: polling status: %w", err)
				}

				switch status {
				case "complete":
					fmt.Fprintln(w)
					fmt.Fprintf(w, "cloud analyze: complete — %d finding(s)\n", findingsCount)
					pkgURL := api.BaseURL() + "/packages/" + ecosystem + "/" + name
					if version != "" {
						pkgURL += "/" + version
					}
					fmt.Fprintf(w, "  details: %s\n", pkgURL)
					return nil
				case "failed":
					fmt.Fprintln(w)
					return fmt.Errorf("cloud analyze: sandbox job failed (job_id=%s)", jobID)
				}
				// "pending" — keep polling
			}

			fmt.Fprintln(w)
			return fmt.Errorf("cloud analyze: timed out after %s waiting for job %s", timeout, jobID)
		},
	}

	c.Flags().BoolVar(&noWait, "no-wait", false,
		"submit and exit without polling for results (prints job_id and stream URL)")
	return c
}

// parsePackageArg splits "ecosystem/name@version" into its three parts.
// version may be absent; ecosystem and name are required.
func parsePackageArg(arg string) (ecosystem, name, version string, err error) {
	slashIdx := strings.IndexByte(arg, '/')
	if slashIdx <= 0 {
		return "", "", "", fmt.Errorf("cloud analyze: argument must be ecosystem/name[@version], got %q", arg)
	}
	ecosystem = arg[:slashIdx]
	rest := arg[slashIdx+1:]
	if rest == "" {
		return "", "", "", fmt.Errorf("cloud analyze: argument must be ecosystem/name[@version], got %q", arg)
	}
	if atIdx := strings.IndexByte(rest, '@'); atIdx >= 0 {
		name = rest[:atIdx]
		version = rest[atIdx+1:]
	} else {
		name = rest
	}
	if name == "" {
		return "", "", "", fmt.Errorf("cloud analyze: argument must be ecosystem/name[@version], got %q", arg)
	}
	return ecosystem, name, version, nil
}
