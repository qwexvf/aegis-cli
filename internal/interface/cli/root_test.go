package cli

import (
	"path/filepath"
	"testing"

	"github.com/qwexvf/aegis/services/cli/internal/infra/allowlist"
	"github.com/qwexvf/aegis/services/cli/internal/infra/diskcache"
	"github.com/qwexvf/aegis/services/cli/internal/infra/ndjsonaudit"
	"github.com/qwexvf/aegis/services/cli/internal/infra/pmwrapper"
	presentercli "github.com/qwexvf/aegis/services/cli/internal/presenter/cli"
	"github.com/spf13/cobra"
)

// emptyDeps wires the tree with the bare minimum for command-tree
// construction: no Gate / Snapshot / managers needed unless asserted.
func emptyDeps(t *testing.T) Deps {
	t.Helper()
	return Deps{
		Cache: diskcache.NewAt(filepath.Join(t.TempDir(), "decisions.json"), 0),
		Audit: ndjsonaudit.NewAt(filepath.Join(t.TempDir(), "audit.jsonl")),
	}
}

func TestNewRoot_RegistersBuiltins(t *testing.T) {
	root := NewRoot(emptyDeps(t))
	// completion is added lazily by Cobra at Execute(), not at
	// NewRoot — so we don't assert it here. Just our own commands.
	want := map[string]bool{
		"version": false,
		"cache":   false,
		"audit":   false,
	}
	for _, c := range root.Commands() {
		if _, tracked := want[c.Name()]; tracked {
			want[c.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("missing command: %s", name)
		}
	}
}

func TestNewRoot_RegistersPMCommands(t *testing.T) {
	deps := emptyDeps(t)
	deps.Managers = []pmwrapper.PackageManager{
		pmwrapper.NewNpm(),
		pmwrapper.NewBun(),
		pmwrapper.NewYarn(),
		pmwrapper.NewPnpm(),
	}
	root := NewRoot(deps)

	want := map[string]bool{"npm": false, "bun": false, "yarn": false, "pnpm": false}
	for _, c := range root.Commands() {
		if _, tracked := want[c.Name()]; tracked {
			want[c.Name()] = true
		}
	}
	for n, found := range want {
		if !found {
			t.Errorf("PM command not registered: %s", n)
		}
	}
}

func TestNewRoot_SnapshotOptional(t *testing.T) {
	// Without a Snapshot use case, the snapshot subtree should not
	// appear (used to crash via nil pointer).
	root := NewRoot(emptyDeps(t))
	for _, c := range root.Commands() {
		if c.Name() == "snapshot" {
			t.Error("snapshot command should NOT register when Deps.Snapshot is nil")
		}
	}
}

func TestNewRoot_CacheCommandHasListAndClear(t *testing.T) {
	root := NewRoot(emptyDeps(t))
	for _, c := range root.Commands() {
		if c.Name() != "cache" {
			continue
		}
		subs := map[string]bool{"list": false, "clear": false}
		for _, sub := range c.Commands() {
			if _, tracked := subs[sub.Name()]; tracked {
				subs[sub.Name()] = true
			}
		}
		for n, found := range subs {
			if !found {
				t.Errorf("cache subcommand missing: %s", n)
			}
		}
		return
	}
	t.Error("cache command not found")
}

func TestNewRoot_AuditCommandHasTail(t *testing.T) {
	root := NewRoot(emptyDeps(t))
	for _, c := range root.Commands() {
		if c.Name() != "audit" {
			continue
		}
		found := false
		for _, sub := range c.Commands() {
			if sub.Name() == "tail" {
				found = true
			}
		}
		if !found {
			t.Errorf("audit tail command missing")
		}
		return
	}
	t.Errorf("audit command not registered")
}

func TestNewRoot_VersionCommandUsable(t *testing.T) {
	root := NewRoot(emptyDeps(t))
	for _, c := range root.Commands() {
		if c.Name() == "version" {
			if c.Run == nil {
				t.Error("version command has no Run")
			}
			return
		}
	}
	t.Error("version command not registered")
}

func TestNewRoot_AllowlistOnlyRegisteredWhenWired(t *testing.T) {
	// No AllowlistLoader / AllowlistPresenter → no allowlist command.
	root := NewRoot(emptyDeps(t))
	for _, c := range root.Commands() {
		if c.Name() == "allowlist" {
			t.Error("allowlist must NOT register without Loader+Presenter")
		}
	}
}

func TestNewRoot_AllowlistRegisteredWhenWired(t *testing.T) {
	deps := emptyDeps(t)
	deps.AllowlistLoader = func() *allowlist.Loader {
		return allowlist.New(t.TempDir())
	}
	deps.AllowlistPresenter = presentercli.NewAllowlistPresenter(presentercli.New())
	root := NewRoot(deps)

	var allowCmd *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "allowlist" {
			allowCmd = c
			break
		}
	}
	if allowCmd == nil {
		t.Fatal("allowlist command not registered when wired")
	}
	subs := map[string]bool{"list": false, "add": false, "remove": false, "test": false}
	for _, sub := range allowCmd.Commands() {
		if _, tracked := subs[sub.Name()]; tracked {
			subs[sub.Name()] = true
		}
	}
	for n, found := range subs {
		if !found {
			t.Errorf("allowlist subcommand %q missing", n)
		}
	}
}

