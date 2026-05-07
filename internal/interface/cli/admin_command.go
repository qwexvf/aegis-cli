package cli

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// adminCommand exposes operator-side utilities that don't talk to the
// Aegis API. Currently just `gen-key` for minting a fresh submit API
// key. The actual database INSERT is done by the operator (we print
// the SQL to copy into psql) — `aegis admin` never connects anywhere.
func adminCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Operator utilities (key generation, etc.)",
	}
	cmd.AddCommand(adminGenKeyCommand())
	return cmd
}

func adminGenKeyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "gen-key",
		Short: "Generate a fresh submit API key + sha256 hex for psql install",
		Long: "Generates a random 32-byte submit API key, prints both the key " +
			"itself and its sha256 hex.\n\nPaste the printed INSERT into psql to " +
			"register the key on the server. Then export AEGIS_API_KEY in your " +
			"shell so `aegis snapshot submit` can authenticate.\n\n" +
			"This command does NOT connect to the database — key install is the " +
			"operator's responsibility, on purpose, so the CLI never holds DB " +
			"credentials.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenKey(cmd.OutOrStdout())
		},
	}
}

func runGenKey(out io.Writer) error {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Errorf("read random: %w", err)
	}
	key := "aegis_" + hex.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(key))
	digest := hex.EncodeToString(sum[:])

	fmt.Fprintln(out, "# WARNING: the key below is sensitive — pasting it into")
	fmt.Fprintln(out, "# `export AEGIS_API_KEY=...` writes it to your shell history.")
	fmt.Fprintln(out, "# Prefer `read -s AEGIS_API_KEY && export AEGIS_API_KEY` or a secret manager.")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "key:    %s\n", key)
	fmt.Fprintf(out, "sha256: %s\n\n", digest)
	fmt.Fprintln(out, "To install:")
	fmt.Fprintf(out,
		"INSERT INTO submit_api_key (key_hash, name) VALUES ('%s', 'my-laptop');\n\n",
		digest)
	fmt.Fprintln(out, "Then export:")
	fmt.Fprintf(out, "export AEGIS_API_KEY=%s\n", key)
	return nil
}
