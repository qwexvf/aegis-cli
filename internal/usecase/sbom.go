package usecase

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/sbomcdx"
)

// Sbom emits a CycloneDX 1.5 JSON SBOM from a saved snapshot.
//
// Vulnerability data is not persisted in aegis.lock (see Dependency
// docs in domain/snapshot.go), so SbomOptions.IncludeVulnerabilities
// triggers a live OSV lookup before emission. When the lookup is
// disabled (no VulnLookup wired) the include-vulns flag is ignored
// with a clear error so the user knows their flag had no effect.
type Sbom struct {
	store        SnapshotStore
	vulns        VulnLookup
	aegisVersion string
}

// NewSbom constructs a Sbom usecase. Vuln lookup is optional and
// attached separately via WithVulnLookup to mirror the Snapshot
// constructor.
func NewSbom(store SnapshotStore, aegisVersion string) *Sbom {
	return &Sbom{store: store, aegisVersion: aegisVersion}
}

// WithVulnLookup attaches the OSV (or aggregated) vulnerability source
// used when SbomOptions.IncludeVulnerabilities is true.
func (s *Sbom) WithVulnLookup(v VulnLookup) *Sbom { s.vulns = v; return s }

// SbomOptions controls one emission.
type SbomOptions struct {
	// Project overrides the root component name. When empty, falls
	// back to the snapshot's Project field.
	Project string
	// IncludeVulnerabilities adds a vulnerabilities[] section. Requires
	// a wired VulnLookup or returns an error.
	IncludeVulnerabilities bool
	// Pretty toggles indented JSON output.
	Pretty bool
	// CdxVersion selects the CycloneDX spec version: "1.5" (default) or "1.6".
	// Only applies when Format == "cyclonedx".
	CdxVersion string
	// Format selects the output format: "cyclonedx" (default) or "spdx".
	Format string
}

// Generate loads the snapshot at projectDir, optionally enriches with
// fresh OSV advisories, and writes the SBOM JSON to out. Returns
// the number of components and vulnerabilities emitted for the caller
// to print a one-line summary.
func (s *Sbom) Generate(ctx context.Context, projectDir string, out io.Writer, opts SbomOptions) (components, vulns int, err error) {
	snap, ok, err := s.store.Load(projectDir)
	if err != nil {
		return 0, 0, fmt.Errorf("load snapshot: %w", err)
	}
	if !ok {
		return 0, 0, fmt.Errorf("no snapshot found at %s — run 'aegis snapshot save' first", s.store.Path(projectDir))
	}

	if opts.IncludeVulnerabilities {
		if s.vulns == nil {
			return 0, 0, fmt.Errorf("--include-vulns requested but no vulnerability source is configured (set AEGIS_VULN_SOURCE or configure vuln.sources)")
		}
		if err := s.attachAdvisories(ctx, &snap); err != nil {
			return 0, 0, fmt.Errorf("vuln lookup: %w", err)
		}
	}

	if opts.Format == "spdx" {
		return s.generateSPDX(snap, out, opts)
	}
	return s.generateCycloneDX(snap, out, opts)
}

func (s *Sbom) generateCycloneDX(snap domain.Snapshot, out io.Writer, opts SbomOptions) (components, vulns int, err error) {
	specVersion := cdx.SpecVersion1_5
	if opts.CdxVersion == "1.6" {
		specVersion = cdx.SpecVersion1_6
	}

	bom := sbomcdx.Build(snap, sbomcdx.Options{
		AegisVersion:           s.aegisVersion,
		Project:                opts.Project,
		Timestamp:              time.Now().UTC(),
		IncludeVulnerabilities: opts.IncludeVulnerabilities,
		SpecVersion:            specVersion,
	})

	// Encode into a buffer first so a write failure to disk doesn't
	// leave a half-written file. The caller handles atomic placement
	// when writing to disk; stdout buffering is the kernel's problem.
	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	if opts.Pretty {
		enc.SetPretty(true)
	}
	if err := enc.EncodeVersion(bom, specVersion); err != nil {
		return 0, 0, fmt.Errorf("encode bom: %w", err)
	}
	if _, err := out.Write(buf.Bytes()); err != nil {
		return 0, 0, err
	}

	components = 0
	if bom.Components != nil {
		components = len(*bom.Components)
	}
	vulns = 0
	if bom.Vulnerabilities != nil {
		vulns = len(*bom.Vulnerabilities)
	}
	return components, vulns, nil
}

func (s *Sbom) generateSPDX(snap domain.Snapshot, out io.Writer, opts SbomOptions) (components, vulns int, err error) {
	doc := sbomcdx.BuildSPDX(snap, sbomcdx.SPDXOptions{
		AegisVersion:           s.aegisVersion,
		Project:                opts.Project,
		Timestamp:              time.Now().UTC(),
		IncludeVulnerabilities: opts.IncludeVulnerabilities,
	})

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if opts.Pretty {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(doc); err != nil {
		return 0, 0, fmt.Errorf("encode spdx: %w", err)
	}
	if _, err := out.Write(buf.Bytes()); err != nil {
		return 0, 0, err
	}

	// len(doc.Packages) includes the root project package, subtract 1.
	components = max(len(doc.Packages)-1, 0)
	if opts.IncludeVulnerabilities {
		for _, d := range snap.Deps {
			for _, a := range d.Advisories {
				if !a.VEXSuppressed {
					vulns++
				}
			}
		}
	}
	return components, vulns, nil
}

// attachAdvisories overwrites Advisories on each dep with fresh lookup
// results. --include-vulns is documented as "live re-query" — stale
// pre-enriched data should not survive when the user explicitly asks
// for current advisories. Deps absent from the lookup result keep
// their existing Advisories (provider gap, not "no vulns").
func (s *Sbom) attachAdvisories(ctx context.Context, snap *domain.Snapshot) error {
	if len(snap.Deps) == 0 {
		return nil
	}
	queries := make([]domain.AdvisoryQuery, 0, len(snap.Deps))
	for _, d := range snap.Deps {
		queries = append(queries, domain.AdvisoryQuery{
			Ecosystem: d.Ecosystem,
			Name:      d.Name,
			Version:   d.Version,
		})
	}
	results, err := s.vulns.Lookup(ctx, queries)
	if err != nil {
		return err
	}
	for i := range snap.Deps {
		k := queries[i].Key()
		if advs, ok := results[k]; ok {
			snap.Deps[i].Advisories = advs
		}
	}
	return nil
}
