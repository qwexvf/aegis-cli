package cli

import (
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
	c := &cobra.Command{
		Use:   "tail",
		Short: "Show the most recent audit entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := w.Tail(n)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
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
	return c
}
