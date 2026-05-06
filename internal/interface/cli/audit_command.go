package cli

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/qwexvf/aegis-cli/internal/infra/ndjsonaudit"
	"github.com/spf13/cobra"
)

func auditCommand(w *ndjsonaudit.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Inspect the local audit log",
	}
	cmd.AddCommand(auditTailCommand(w))
	return cmd
}

func auditTailCommand(w *ndjsonaudit.Writer) *cobra.Command {
	var n int
	var jsonOut bool
	c := &cobra.Command{
		Use:   "tail",
		Short: "Show the most recent audit entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := w.Tail(n)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if jsonOut {
				type row struct {
					Timestamp      string `json:"ts"`
					Ecosystem      string `json:"ecosystem"`
					Package        string `json:"package"`
					Version        string `json:"version"`
					Decision       string `json:"decision,omitempty"`
					Severity       string `json:"severity,omitempty"`
					Action         string `json:"action"`
					Source         string `json:"source,omitempty"`
					OverrideUsed   bool   `json:"override,omitempty"`
					OverrideReason string `json:"override_reason,omitempty"`
					AdvisoryID     string `json:"advisory_id,omitempty"`
					AegisVersion   string `json:"aegis_version,omitempty"`
					InvocationID   string `json:"cli_invocation_id,omitempty"`
					ProjectDir     string `json:"project_dir,omitempty"`
				}
				rows := make([]row, 0, len(entries))
				for _, e := range entries {
					rows = append(rows, row{
						Timestamp:      e.Timestamp.Format(time.RFC3339),
						Ecosystem:      e.Ecosystem,
						Package:        e.Package,
						Version:        e.Version,
						Decision:       e.Decision,
						Severity:       e.Severity,
						Action:         e.Action,
						Source:         e.Source,
						OverrideUsed:   e.OverrideUsed,
						OverrideReason: e.OverrideReason,
						AdvisoryID:     e.AdvisoryID,
						AegisVersion:   e.AegisVersion,
						InvocationID:   e.InvocationID,
						ProjectDir:     e.ProjectDir,
					})
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			}
			if len(entries) == 0 {
				fmt.Fprintln(out, "(empty)")
				return nil
			}
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "TIME\tECO\tPACKAGE@VERSION\tDECISION\tACTION\tSOURCE\tOVERRIDE")
			for _, e := range entries {
				override := ""
				if e.OverrideUsed {
					override = e.OverrideReason
					if override == "" {
						override = "(no reason)"
					}
				}
				fmt.Fprintf(tw, "%s\t%s\t%s@%s\t%s\t%s\t%s\t%s\n",
					e.Timestamp.Format(time.RFC3339),
					e.Ecosystem,
					e.Package, e.Version,
					e.Decision, e.Action, e.Source, override)
			}
			return tw.Flush()
		},
	}
	c.Flags().IntVarP(&n, "n", "n", 20, "show the last N entries (0 = all)")
	c.Flags().BoolVar(&jsonOut, "json", false, "emit machine-readable JSON")
	return c
}
