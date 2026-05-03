package cli

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/qwexvf/aegis-cli/internal/infra/diskcache"
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
	var fingerprints, all bool
	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Delete the local decision cache (and optionally the AST fingerprint cache)",
		Long: `clear deletes the per-package /check decision cache by default.

Flags:
  --fingerprints   also delete the AST fingerprint cache used by
                   'snapshot enrich' / 'analyze'. Forces the next
                   enrich / analyze to re-fetch + re-scan everything.
  --all            equivalent to passing both default-clear and
                   --fingerprints together.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			clearedDecisions := false
			clearedFingerprints := false

			// Default behavior: clear decision cache. --fingerprints
			// without --all means "ONLY fingerprints" — useful when
			// you want a fresh enrich without losing /check cache.
			if !fingerprints || all {
				if err := c.Clear(); err != nil {
					return fmt.Errorf("clear decisions: %w", err)
				}
				fmt.Fprintln(os.Stdout, "decision cache cleared:", c.Path())
				clearedDecisions = true
			}

			if fingerprints || all {
				fp := diskcache.NewFingerprintCache()
				if err := fp.Clear(); err != nil {
					return fmt.Errorf("clear fingerprints: %w", err)
				}
				fmt.Fprintln(os.Stdout, "fingerprint cache cleared:", fp.Dir())
				clearedFingerprints = true
			}

			if !clearedDecisions && !clearedFingerprints {
				// Defensive — shouldn't happen given the logic above.
				return fmt.Errorf("nothing cleared (this is a bug; report it)")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&fingerprints, "fingerprints", false,
		"clear the AST fingerprint cache instead of the decision cache")
	cmd.Flags().BoolVar(&all, "all", false,
		"clear both the decision cache and the fingerprint cache")
	return cmd
}
