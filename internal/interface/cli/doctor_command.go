package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/qwexvf/aegis/services/cli/internal/infra/aegisapi"
	"github.com/qwexvf/aegis/services/cli/internal/infra/allowlist"
	"github.com/qwexvf/aegis/services/cli/internal/infra/diskcache"
	"github.com/spf13/cobra"
)

// doctorCommand wires `aegis doctor` — read-only sanity check across
// the moving parts. Designed to be the first thing a user runs when
// "something's off"; the second is to read the failed checks. Each
// check prints a PASS / WARN / FAIL line + one-line diagnostic. Exit
// 0 if every check passes (warnings allowed), 1 otherwise.
func doctorCommand(api *aegisapi.Client, allowlistLoader func() *allowlist.Loader) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Sanity-check the local environment (API, cache, allowlist, disk)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()

			results := runDoctorChecks(ctx, doctorContext{
				api:             api,
				allowlistLoader: allowlistLoader,
				cwd:             cwd,
			})
			renderDoctorResults(os.Stdout, results, jsonOut)

			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			if anyFailed(results) {
				return &exitCodeError{code: 1, err: fmt.Errorf("doctor: one or more checks failed"), silent: true}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit machine-readable JSON")
	return cmd
}

// doctorContext bundles what every check needs. Kept tiny on purpose
// — adding a check means adding a method, not threading new args.
type doctorContext struct {
	api             *aegisapi.Client
	allowlistLoader func() *allowlist.Loader
	cwd             string
}

// doctorStatus is the per-check verdict.
type doctorStatus int

const (
	doctorPass doctorStatus = iota
	doctorWarn
	doctorFail
)

func (s doctorStatus) String() string {
	switch s {
	case doctorPass:
		return "PASS"
	case doctorWarn:
		return "WARN"
	case doctorFail:
		return "FAIL"
	}
	return "?"
}

// doctorResult is one check's output.
type doctorResult struct {
	Name   string
	Status doctorStatus
	Detail string
}

// runDoctorChecks runs every check sequentially. Sequential keeps the
// output ordered (no need to sort by name); none of the checks are
// long enough for parallelism to matter.
func runDoctorChecks(ctx context.Context, c doctorContext) []doctorResult {
	return []doctorResult{
		checkRuntime(),
		checkAPI(ctx, c.api),
		checkConfigDirWritable(),
		checkFingerprintCache(),
		checkAllowlist(c.allowlistLoader),
		checkProjectDir(c.cwd),
	}
}

func checkRuntime() doctorResult {
	return doctorResult{
		Name:   "runtime",
		Status: doctorPass,
		Detail: fmt.Sprintf("aegis %s on %s/%s, Go %s",
			Version, runtime.GOOS, runtime.GOARCH, runtime.Version()),
	}
}

func checkAPI(ctx context.Context, api *aegisapi.Client) doctorResult {
	if api == nil {
		return doctorResult{Name: "api", Status: doctorWarn, Detail: "API client not configured"}
	}
	status, err := api.Ping(ctx)
	if err != nil {
		return doctorResult{
			Name: "api", Status: doctorFail,
			Detail: fmt.Sprintf("%s unreachable: %v", api.BaseURL(), err),
		}
	}
	// Any 2xx-4xx means the server replied. 5xx hints at server-side
	// trouble but the network path works — flag as WARN, not FAIL.
	switch {
	case status >= 200 && status < 500:
		return doctorResult{
			Name: "api", Status: doctorPass,
			Detail: fmt.Sprintf("%s reachable (HTTP %d)", api.BaseURL(), status),
		}
	default:
		return doctorResult{
			Name: "api", Status: doctorWarn,
			Detail: fmt.Sprintf("%s replied %d (server-side issue?)", api.BaseURL(), status),
		}
	}
}

func checkConfigDirWritable() doctorResult {
	dir := os.Getenv("AEGIS_CONFIG_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return doctorResult{
				Name: "config-dir", Status: doctorWarn,
				Detail: "no $HOME — falling back to ./.aegis (set AEGIS_CONFIG_DIR)",
			}
		}
		dir = filepath.Join(home, ".aegis")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return doctorResult{
			Name: "config-dir", Status: doctorFail,
			Detail: fmt.Sprintf("cannot create %s: %v", dir, err),
		}
	}
	probe := filepath.Join(dir, ".doctor-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o644); err != nil {
		return doctorResult{
			Name: "config-dir", Status: doctorFail,
			Detail: fmt.Sprintf("not writable: %v", err),
		}
	}
	_ = os.Remove(probe)
	return doctorResult{
		Name: "config-dir", Status: doctorPass,
		Detail: dir + " (writable)",
	}
}

func checkFingerprintCache() doctorResult {
	fp := diskcache.NewFingerprintCache()
	dir := fp.Dir()
	count, bytes, err := walkDir(dir)
	if err != nil {
		// Missing directory is fine — caches are lazily created.
		if os.IsNotExist(err) {
			return doctorResult{
				Name: "fingerprint-cache", Status: doctorPass,
				Detail: dir + " (not yet populated — fine)",
			}
		}
		return doctorResult{
			Name: "fingerprint-cache", Status: doctorWarn,
			Detail: fmt.Sprintf("scan failed: %v", err),
		}
	}
	return doctorResult{
		Name: "fingerprint-cache", Status: doctorPass,
		Detail: fmt.Sprintf("%s — %d entries, %s", dir, count, humanBytes(bytes)),
	}
}

func checkAllowlist(loader func() *allowlist.Loader) doctorResult {
	if loader == nil {
		return doctorResult{Name: "allowlist", Status: doctorWarn, Detail: "loader not wired"}
	}
	set, err := loader().Load()
	if err != nil {
		return doctorResult{
			Name: "allowlist", Status: doctorFail,
			Detail: fmt.Sprintf("parse failed: %v (run `aegis allowlist verify`)", err),
		}
	}
	return doctorResult{
		Name: "allowlist", Status: doctorPass,
		Detail: fmt.Sprintf("%d rules loaded", len(set.Rules())),
	}
}

func checkProjectDir(cwd string) doctorResult {
	// Look for any known lockfile so the user knows aegis sees their
	// project. This is informational, not a hard fail — many aegis
	// commands run outside a project (cache, audit, allowlist).
	for _, name := range []string{
		"package.json", "package-lock.json", "bun.lock", "bun.lockb",
		"yarn.lock", "pnpm-lock.yaml",
	} {
		if _, err := os.Stat(filepath.Join(cwd, name)); err == nil {
			return doctorResult{
				Name: "project-dir", Status: doctorPass,
				Detail: cwd + " (lockfile detected: " + name + ")",
			}
		}
	}
	return doctorResult{
		Name: "project-dir", Status: doctorWarn,
		Detail: cwd + " (no JS lockfile here — fine if running cache/audit/allowlist)",
	}
}

// walkDir returns (entries, totalBytes, err). Stops on first read error.
func walkDir(dir string) (int, int64, error) {
	count := 0
	var bytes int64
	err := filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		count++
		info, err := d.Info()
		if err != nil {
			return err
		}
		bytes += info.Size()
		return nil
	})
	return count, bytes, err
}

// humanBytes formats a byte count as "1.2 KB" / "456 MB".
func humanBytes(n int64) string {
	const k = 1024
	switch {
	case n < k:
		return fmt.Sprintf("%d B", n)
	case n < k*k:
		return fmt.Sprintf("%.1f KB", float64(n)/k)
	case n < k*k*k:
		return fmt.Sprintf("%.1f MB", float64(n)/(k*k))
	default:
		return fmt.Sprintf("%.1f GB", float64(n)/(k*k*k))
	}
}

// anyFailed reports whether at least one check returned FAIL. WARN
// alone doesn't trip the exit code — warnings are advisory.
func anyFailed(results []doctorResult) bool {
	for _, r := range results {
		if r.Status == doctorFail {
			return true
		}
	}
	return false
}

// renderDoctorResults prints the human (default) or JSON form.
func renderDoctorResults(w io.Writer, results []doctorResult, jsonMode bool) {
	if jsonMode {
		renderDoctorJSON(w, results)
		return
	}
	for _, r := range results {
		fmt.Fprintf(w, "%-20s %-4s  %s\n", r.Name, r.Status, r.Detail)
	}
}

// renderDoctorJSON keeps the JSON shape stable for scripts:
//
//	[{"name":"api","status":"PASS","detail":"..."}]
func renderDoctorJSON(w io.Writer, results []doctorResult) {
	fmt.Fprint(w, "[")
	for i, r := range results {
		if i > 0 {
			fmt.Fprint(w, ",")
		}
		fmt.Fprintf(w, `{"name":%q,"status":%q,"detail":%q}`,
			r.Name, r.Status, r.Detail)
	}
	fmt.Fprintln(w, "]")
}
