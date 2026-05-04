// Command gendocs emits man pages and markdown reference for every
// `aegis` subcommand. Driven by the same cobra tree as the CLI, so
// the generated output never drifts from real flags / descriptions.
//
// Usage:
//
//	go run ./cmd/gendocs --man-dir=./man/man1 --md-dir=./docs/content/reference/commands
//
// Both flags are optional; defaults match the layout used by the
// docs site and the install paths the goreleaser archive expects.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/qwexvf/aegis-cli/internal/interface/cli"
	"github.com/spf13/cobra/doc"
)

func main() {
	var (
		manDir = flag.String("man-dir", "./man/man1", "output directory for man pages")
		mdDir  = flag.String("md-dir", "./docs/content/reference/commands", "output directory for markdown reference")
		date   = flag.String("date", time.Now().UTC().Format("2006-01-02"), "manpage date (YYYY-MM-DD)")
	)
	flag.Parse()

	root := cli.NewDocsRoot()
	root.DisableAutoGenTag = true

	if err := os.MkdirAll(*manDir, 0o755); err != nil {
		fail("man dir: %v", err)
	}
	if err := os.MkdirAll(*mdDir, 0o755); err != nil {
		fail("md dir: %v", err)
	}

	header := &doc.GenManHeader{
		Title:   "AEGIS",
		Section: "1",
		Date:    parseDate(*date),
		Source:  "aegis " + cli.Version,
		Manual:  "Aegis Manual",
	}
	if err := doc.GenManTree(root, header, *manDir); err != nil {
		fail("man gen: %v", err)
	}

	// Emit markdown with a Starlight-friendly frontmatter prefix so the
	// generated files drop into the docs site's content collection.
	filePrepender := func(filename string) string {
		base := strings.TrimSuffix(filepath.Base(filename), ".md")
		title := strings.ReplaceAll(base, "_", " ")
		return fmt.Sprintf("---\ntitle: %q\ndescription: %q\n---\n\n", title, "Auto-generated reference for `"+title+"`.")
	}
	linkHandler := func(name string) string {
		// Cobra default: `aegis_snapshot.md` → relative link.
		// Drop the .md so the docs site renders clean URLs.
		return strings.TrimSuffix(name, ".md") + "/"
	}
	if err := doc.GenMarkdownTreeCustom(root, *mdDir, filePrepender, linkHandler); err != nil {
		fail("md gen: %v", err)
	}

	fmt.Printf("man → %s\nmd  → %s\n", *manDir, *mdDir)
}

func parseDate(s string) *time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		fail("invalid --date %q (want YYYY-MM-DD): %v", s, err)
	}
	return &t
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gendocs: "+format+"\n", args...)
	os.Exit(1)
}
