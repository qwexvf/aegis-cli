package usecase

import (
	"context"
	"fmt"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// Image is the use case for `aegis image scan` — read an OCI / Docker
// image tar, extract every lockfile baked into the layers, and (when
// enrich is on) run the OSV vulnerability feed against the resulting
// dependency set.
//
// MVP scope: local tar input only. Registry pull and OS-package
// databases are follow-ups.
type Image struct {
	scanner    ImageScanner
	vulnLookup VulnLookup // optional — when nil, --enrich is a no-op
	presenter  ImagePresenter
}

// NewImage wires the use case. vulnLookup may be nil; --enrich then
// reports "no vulnerability source configured" and exits without
// touching the network.
func NewImage(scanner ImageScanner, vulnLookup VulnLookup, presenter ImagePresenter) *Image {
	return &Image{scanner: scanner, vulnLookup: vulnLookup, presenter: presenter}
}

// ImageScanner is the port the use case calls. Implementation:
// internal/infra/scan/image. Pure layer walk → []domain.Dependency;
// no network.
type ImageScanner interface {
	ScanImage(path string) ([]domain.Dependency, error)
}

// ImageRequest is the input shape.
type ImageRequest struct {
	// Path is a local file system path to a Docker save / OCI image tar.
	Path string
	// Enrich, when true, runs the configured VulnLookup against the
	// extracted dep list. When the use case has no VulnLookup, the
	// presenter is told and the field is silently ignored.
	Enrich bool
}

// ImageResult is what the use case returns. Deps is always populated
// (possibly empty); Advisories is keyed by AdvisoryQuery.Key() and is
// nil when Enrich was off or VulnLookup is unconfigured.
type ImageResult struct {
	ImagePath  string
	Deps       []domain.Dependency
	Advisories map[string][]domain.Advisory
	Enriched   bool
}

// ImagePresenter renders the result. Implementation:
// internal/presenter/cli/image_render.go.
type ImagePresenter interface {
	OnImageBegin(req ImageRequest)
	OnImageResult(result ImageResult)
	OnImageError(err error)
}

// Run extracts the dep list and (optionally) enriches with vuln data.
// Failures flow through both the returned error and OnImageError so the
// CLI can map to exit code 2 distinct from "deps found but clean" (0).
func (i *Image) Run(ctx context.Context, req ImageRequest) (ImageResult, error) {
	i.presenter.OnImageBegin(req)

	deps, err := i.scanner.ScanImage(req.Path)
	if err != nil {
		i.presenter.OnImageError(fmt.Errorf("scan: %w", err))
		return ImageResult{}, err
	}

	out := ImageResult{
		ImagePath: req.Path,
		Deps:      deps,
	}

	if req.Enrich && i.vulnLookup != nil && len(deps) > 0 {
		queries := make([]domain.AdvisoryQuery, 0, len(deps))
		for _, d := range deps {
			queries = append(queries, domain.AdvisoryQuery{
				Ecosystem: d.Ecosystem,
				Name:      d.Name,
				Version:   d.Version,
			})
		}
		advs, lerr := i.vulnLookup.Lookup(ctx, queries)
		if lerr != nil {
			// Best-effort: report the error but keep the extracted dep list.
			i.presenter.OnImageError(fmt.Errorf("vuln lookup: %w", lerr))
		} else {
			out.Advisories = advs
			out.Enriched = true
			// Stamp advisories onto each Dep so the JSON output and
			// downstream consumers see them inline.
			for idx, d := range out.Deps {
				key := domain.AdvisoryQuery{
					Ecosystem: d.Ecosystem,
					Name:      d.Name,
					Version:   d.Version,
				}.Key()
				out.Deps[idx].Advisories = advs[key]
			}
		}
	}

	i.presenter.OnImageResult(out)
	return out, nil
}
