package usecase

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// Image is the use case for `aegis image scan` — read an OCI / Docker
// image tar, extract every lockfile baked into the layers, and
// (optionally) run OSV vulnerability lookup and AST capability
// analysis on every package found inside the image.
//
// MVP scope: local tar input only. Registry pull and OS-package
// databases are follow-ups.
type Image struct {
	scanner    ImageScanner
	vulnLookup VulnLookup  // optional — when nil, --enrich is a no-op
	analyzer   ASTAnalyzer // optional — when nil, --capabilities is a no-op
	presenter  ImagePresenter
}

// NewImage wires the use case. vulnLookup and analyzer may be nil; the
// corresponding flag (--enrich / --capabilities) then reports "no
// source configured" and exits without touching the network or
// running tree-sitter.
func NewImage(scanner ImageScanner, vulnLookup VulnLookup, analyzer ASTAnalyzer, presenter ImagePresenter) *Image {
	return &Image{scanner: scanner, vulnLookup: vulnLookup, analyzer: analyzer, presenter: presenter}
}

// ImageScanner is the port the use case calls. Implementation:
// internal/infra/scan/image. Pure layer walk → ImagePackages;
// no network.
type ImageScanner interface {
	// ScanImage returns just the lockfile-derived dep list (cheap path).
	ScanImage(path string) ([]domain.Dependency, error)
	// ScanImagePackages additionally captures per-package source files
	// when opts.CapturePackageSources is true, enabling downstream AST
	// capability analysis on each package.
	ScanImagePackages(path string, opts ImageScanOpts) (ImagePackageSet, error)
}

// ImageScanOpts mirrors infra/scan/image.ScanOpts at the use-case layer
// so adapter and use case can compile without an import cycle.
type ImageScanOpts struct {
	CapturePackageSources bool
}

// ImagePackageSet mirrors the adapter's return shape.
type ImagePackageSet struct {
	Deps    []domain.Dependency
	Sources map[string]domain.PackageSource
}

// ImageRequest is the input shape.
type ImageRequest struct {
	// Path is a local file system path to a Docker save / OCI image tar.
	Path string
	// Enrich, when true, runs the configured VulnLookup against the
	// extracted dep list. When the use case has no VulnLookup, the
	// presenter is told and the field is silently ignored.
	Enrich bool
	// Capabilities, when true, additionally captures per-package
	// source files from inside the image and runs the AST analyzer
	// over each. Each dep's Fingerprint.Capabilities is populated.
	// Costs more memory and CPU than --enrich.
	Capabilities bool
}

// ImageResult is what the use case returns. Deps is always populated
// (possibly empty); Advisories is keyed by AdvisoryQuery.Key() and is
// nil when Enrich was off or VulnLookup is unconfigured.
//
// CapabilitiesScanned is true when the AST analyzer ran over the
// captured package sources. Per-dep results live on Deps[i].Fingerprint.
type ImageResult struct {
	ImagePath           string
	Deps                []domain.Dependency
	Advisories          map[string][]domain.Advisory
	Enriched            bool
	CapabilitiesScanned bool
}

// ImagePresenter renders the result. Implementation:
// internal/presenter/cli/image_render.go.
type ImagePresenter interface {
	OnImageBegin(req ImageRequest)
	OnImageResult(result ImageResult)
	OnImageError(err error)
}

// Run extracts the dep list and (optionally) enriches with vuln data
// and/or runs AST capability analysis on each package found inside the
// image. Failures flow through both the returned error and
// OnImageError so the CLI can map to exit code 2 distinct from
// "deps found but clean" (0).
func (i *Image) Run(ctx context.Context, req ImageRequest) (ImageResult, error) {
	i.presenter.OnImageBegin(req)

	set, err := i.scanner.ScanImagePackages(req.Path, ImageScanOpts{
		CapturePackageSources: req.Capabilities && i.analyzer != nil,
	})
	if err != nil {
		i.presenter.OnImageError(fmt.Errorf("scan: %w", err))
		return ImageResult{}, err
	}

	out := ImageResult{
		ImagePath: req.Path,
		Deps:      set.Deps,
	}

	if req.Capabilities && i.analyzer != nil && len(set.Sources) > 0 {
		i.runCapabilityScan(ctx, &out, set.Sources)
	}

	if req.Enrich && i.vulnLookup != nil && len(set.Deps) > 0 {
		queries := make([]domain.AdvisoryQuery, 0, len(set.Deps))
		for _, d := range set.Deps {
			queries = append(queries, domain.AdvisoryQuery{
				Ecosystem: d.Ecosystem,
				Name:      d.Name,
				Version:   d.Version,
			})
		}
		advs, lerr := i.vulnLookup.Lookup(ctx, queries)
		if lerr != nil {
			i.presenter.OnImageError(fmt.Errorf("vuln lookup: %w", lerr))
		} else {
			out.Advisories = advs
			out.Enriched = true
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

// runCapabilityScan runs the AST analyzer over each captured package
// source in parallel and stamps the resulting Fingerprint onto the
// matching dep. Best-effort: a single analyzer failure on one package
// is skipped silently.
//
// Parallelism: capped at imageCapWorkers (small fixed pool) because
// tree-sitter parsing is CPU-bound; over-saturating beyond NumCPU
// fights the GC, and most images have tens-to-hundreds of packages
// where the pool quickly drains.
func (i *Image) runCapabilityScan(ctx context.Context, out *ImageResult, sources map[string]domain.PackageSource) {
	if len(sources) == 0 {
		return
	}
	// Build dep index keyed by "<eco>/<name>@<version>".
	idx := make(map[string]int, len(out.Deps))
	for k, d := range out.Deps {
		key := string(d.Ecosystem) + "/" + d.Name + "@" + d.Version
		idx[key] = k
	}
	out.CapabilitiesScanned = true

	type job struct {
		key string
		eco domain.Ecosystem
		src domain.PackageSource
	}
	jobs := make(chan job, len(sources))
	for k, src := range sources {
		// Derive ecosystem from key prefix. Required because the
		// image walker may surface sources that don't appear in the
		// lockfile (e.g. system-bundled npm packages, pip-only-in-image
		// site-packages); we still want to scan them.
		jobs <- job{key: k, eco: ecosystemFromKey(k), src: src}
	}
	close(jobs)

	workers := min(imageCapWorkers, len(sources))

	type result struct {
		depIdx int
		fp     domain.Fingerprint
	}
	results := make(chan result, len(sources))
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				// Ecosystem comes from the source-key prefix so the
				// image walker can produce caps even for packages
				// outside the lockfile (system-bundled npm, pip-only
				// site-packages). depIdx is optional: when present,
				// the fingerprint is attached to the dep; when absent
				// (no lockfile entry), the scan still runs but the
				// finding has no version to attribute to and is
				// dropped (intentional — uncorrelated noise).
				eco := j.eco
				if eco == "" || !i.analyzer.HasScanner(eco) {
					continue
				}
				depIdx, hasDep := idx[j.key]
				if !hasDep {
					continue
				}
				// Per-package timeout: tree-sitter parses untrusted
				// code from the image. A crafted file could trigger
				// a long parse loop; bound it so one bad package
				// can't tie up a worker indefinitely.
				pkgCtx, cancel := context.WithTimeout(ctx, perPackageAnalyzeTimeout)
				fp, err := i.analyzer.Analyze(pkgCtx, eco, j.src)
				cancel()
				if err != nil {
					continue
				}
				fp.Analyzed = true
				results <- result{depIdx: depIdx, fp: fp}
			}
		})
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		fp := r.fp
		out.Deps[r.depIdx].Fingerprint = &fp
	}
}

// ecosystemFromKey maps the source-key prefix produced by the image
// scanner ("<eco>/<name>...") back to a domain.Ecosystem.
func ecosystemFromKey(key string) domain.Ecosystem {
	slash := -1
	for i := 0; i < len(key); i++ {
		if key[i] == '/' {
			slash = i
			break
		}
	}
	if slash <= 0 {
		return ""
	}
	switch key[:slash] {
	case "npm":
		return domain.EcoNpm
	case "pypi":
		return domain.EcoPyPI
	case "rubygems":
		return domain.EcoRubyGems
	case "packagist":
		return domain.EcoPackagist
	}
	return ""
}

const (
	// imageCapWorkers caps parallel AST scans during --capabilities.
	// Same shape as snapshot.enrichWorkers; tree-sitter is CPU-bound.
	imageCapWorkers = 8
	// perPackageAnalyzeTimeout bounds one Analyze call. tree-sitter is
	// implemented in C (via CGo); a crafted file could in theory loop
	// for a long time. 5 s is generous — real packages parse in ms.
	perPackageAnalyzeTimeout = 5 * time.Second
)
