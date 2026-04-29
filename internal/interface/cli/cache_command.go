package cli

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/qwexvf/aegis/services/cli/internal/infra/diskcache"
	"github.com/spf13/cobra"
)

func cacheCommand(c *diskcache.Cache) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Inspect or clear the local decision cache",
	}
	cmd.AddCommand(cacheListCommand(c))
	cmd.AddCommand(cacheClearCommand(c))
	return cmd
}

func cacheListCommand(c *diskcache.Cache) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List cached decisions",
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := c.List()
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				fmt.Fprintln(os.Stdout, "(empty)")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "KEY\tDECISION\tSEVERITY\tEXPIRES")
			for _, e := range entries {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
					e.Key, e.Kind, e.Severity, e.ExpiresAt.Format(time.RFC3339))
			}
			return tw.Flush()
		},
	}
}

func cacheClearCommand(c *diskcache.Cache) *cobra.Command {
	return &cobra.Command{
		Use:   "clear",
		Short: "Delete the local decision cache",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.Clear(); err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, "cache cleared:", c.Path())
			return nil
		},
	}
}
