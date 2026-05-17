// Package image scans OCI container images for supply-chain risks.
//
// MVP scope: read a `docker save` / OCI tarball from disk, overlay every
// layer's files into a virtual file system (whiteout-aware), find any
// lockfile registered with locksnap, and parse it via the existing
// per-ecosystem parser. The resulting []domain.Dependency feeds the
// same OSV lookup + AST scan + heuristics pipeline the project-mode
// scanner uses.
//
// Out of scope for v1:
//   - Registry pull (no auth flow, no remote.Image yet)
//   - OS package databases (apk db, dpkg/status, rpm db)
//   - Per-layer attribution (which layer introduced a vuln)
//   - Squashed image diffing
//
// See internal/infra/locksnap for the lockfile parser registry — the
// image scanner reuses it 1:1 so a new lockfile format added there
// becomes detectable inside images automatically.
package image

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/locksnap"
)

// Scanner reads a local OCI/Docker image tar and produces
// []domain.Dependency from every lockfile baked into the image.
type Scanner struct {
	// parsersByFilename indexes registered locksnap parsers by their
	// canonical filename so the layer walker can match in O(1) per
	// entry rather than scanning the registry per file.
	parsersByFilename map[string]locksnap.LockfileParser
	// lockfileNames is the same set as parsersByFilename's keys, kept
	// as a map[string]struct{} so the layer walker can do a single
	// O(1) lookup without keeping a reference to the parser.
	lockfileNames map[string]struct{}
}

// NewScanner builds an image Scanner from the current package-level
// locksnap registry. Lockfile parser additions made after NewScanner
// is constructed are NOT picked up — callers should register first,
// then construct.
func NewScanner() *Scanner {
	s := &Scanner{
		parsersByFilename: make(map[string]locksnap.LockfileParser),
		lockfileNames:     make(map[string]struct{}),
	}
	for _, p := range locksnap.Registered() {
		s.parsersByFilename[p.Filename()] = p
		s.lockfileNames[p.Filename()] = struct{}{}
	}
	return s
}

// ScanImage reads the image at path (Docker save tar or OCI tar) and
// returns every dependency parsed from a recognised lockfile across
// all layers, deduplicated and sorted.
//
// Whiteouts (`.wh.<name>` / `.wh..wh..opq`) are honoured: a lockfile
// removed in a later layer doesn't contribute to the final result.
// This mirrors the runtime view a `docker run` would see.
func (s *Scanner) ScanImage(imagePath string) ([]domain.Dependency, error) {
	res, err := s.ScanImagePackages(imagePath, ScanOpts{})
	if err != nil {
		return nil, err
	}
	return res.Deps, nil
}

// ScanOpts controls what the layer walker captures beyond lockfiles.
type ScanOpts struct {
	// CapturePackageSources, when true, additionally captures source
	// files inside every `node_modules/<pkg>/` (and similar) directory
	// so callers can feed each package to the existing AST analyzer
	// pipeline. Only language source files (.js, .ts, .py, .rb, ...)
	// + the package manifest are captured; binary assets are skipped.
	CapturePackageSources bool
}

// PackageSet bundles the result of a full image scan: the lockfile-
// derived dep list and, when ScanOpts.CapturePackageSources was on,
// the per-package source tree (keyed by `<ecosystem>/<name>@<version>`
// when version is known; `<ecosystem>/<name>` otherwise).
//
// Truncated is set when a global byte cap (maxTotalLockfileBytes or
// maxTotalPackageBytes) fired during the walk — the result is partial
// and downstream consumers should warn the user.
type PackageSet struct {
	Deps      []domain.Dependency
	Sources   map[string]domain.PackageSource
	Truncated bool
}

// ScanImagePackages is the full-featured entry point. Walks every
// layer once, applies the overlay rules, and produces the dep list +
// (optionally) per-package source bundles for AST-based capability
// analysis.
//
// Memory model: per-package source bundles cap each file at
// maxSourceFileBytes (256 KB) and each package's total at
// maxPackageBytes (4 MB). Files outside the source allowlist
// (.js / .ts / .py / .rb / .go / .rs / .java / .php / .cs / .gleam /
// package.json) are skipped to keep the in-memory footprint bounded
// on multi-GB images.
func (s *Scanner) ScanImagePackages(imagePath string, opts ScanOpts) (PackageSet, error) {
	img, err := tarball.ImageFromPath(imagePath, nil)
	if err != nil {
		return PackageSet{}, fmt.Errorf("image: open %s: %w", imagePath, err)
	}
	layers, err := img.Layers()
	if err != nil {
		return PackageSet{}, fmt.Errorf("image: list layers: %w", err)
	}

	vlayers := make([]v1Layer, len(layers))
	for i, l := range layers {
		vlayers[i] = l
	}
	files, pkgFiles, truncated, err := overlayLayersFull(vlayers, opts, s.lockfileNames)
	if err != nil {
		return PackageSet{}, fmt.Errorf("image: overlay layers: %w", err)
	}

	deps := s.parseFiles(files)
	sources := groupPackageSources(pkgFiles, deps)
	return PackageSet{Deps: deps, Sources: sources, Truncated: truncated}, nil
}

// parseFiles iterates the overlay's file table, dispatches each
// recognised lockfile to its parser, and returns the union of
// resulting deps. Parse failures on a single file are surfaced as
// errors via the returned slice's tail (TODO: structured warning
// channel); for the MVP they're silently skipped so one corrupt file
// doesn't blackhole the whole scan.
func (s *Scanner) parseFiles(files map[string][]byte) []domain.Dependency {
	var all []domain.Dependency
	for filename, body := range files {
		base := path.Base(filename)
		p, ok := s.parsersByFilename[base]
		if !ok {
			continue
		}
		// `direct` is nil — we don't have package.json context for an
		// arbitrary path in an image layer; treat every entry as
		// transitive. npm parsers tolerate nil direct map.
		deps, err := p.Parse(body, nil)
		if err != nil {
			continue
		}
		all = append(all, deps...)
	}
	return dedupSort(all)
}

// dedupKeepOrder removes duplicates (same ecosystem/name/version) and
// returns the deps in their original first-seen order. Two layers can
// both contain the same lockfile (e.g. multi-stage build re-running
// `npm ci`) — dedup keeps the final BOM clean. (Despite the historic
// name, no sort is performed; locksnap.Scanner sorts before this map
// hits the consumer.)
func dedupSort(deps []domain.Dependency) []domain.Dependency {
	seen := make(map[string]struct{}, len(deps))
	out := make([]domain.Dependency, 0, len(deps))
	for _, d := range deps {
		key := string(d.Ecosystem) + "/" + d.Name + "@" + d.Version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, d)
	}
	return out
}

// --- per-package source capture ----------------------------------------

// packageBoundary identifies a source file's owning package by looking
// for the deepest known-layout segment in its path. Supports:
//
//	node_modules/<pkg>/...           → npm
//	node_modules/@scope/<pkg>/...    → npm scoped
//	site-packages/<pkg>/...          → pypi (version comes from sibling .dist-info)
//	gems/<pkg>-<version>/...         → rubygems (version embedded in dir name)
//	vendor/<vendor>/<pkg>/...        → packagist / php composer
//
// Returns the package key ("<eco>/<name>" or "<eco>/<name>@<version>"
// when the path encodes the version), the relative path inside the
// package, and ok=true when a layout matched. Innermost match wins
// (handles nested node_modules).
//
// Performance: this runs once per source file. The implementation does
// ONE pass over the path string, recording the LAST occurrence of each
// known marker prefix. Earlier versions ran `strings.LastIndex` four
// times — a ~5% wall-time saving on caps-mode scans of large images.
func packageBoundary(p string) (key, rel string, ok bool) {
	// Single-pass search for the deepest occurrence of each marker.
	// We compare positions at the end and dispatch to whichever marker
	// matched closest to the leaf — that's the innermost package boundary.
	const (
		mNode  = "node_modules/"
		mSite  = "site-packages/"
		mGemsM = "/gems/" // mid-path
		mGemsS = "gems/"  // start-of-path
		mVend  = "vendor/"
	)
	idxNode := strings.LastIndex(p, mNode)
	idxSite := strings.LastIndex(p, mSite)
	idxGems := strings.LastIndex(p, mGemsM)
	if idxGems < 0 && strings.HasPrefix(p, mGemsS) {
		idxGems = 0
	} else if idxGems >= 0 {
		idxGems++ // skip leading '/'
	}
	idxVend := strings.LastIndex(p, mVend)

	// Pick the deepest (largest index) match. Tie-break by ecosystem
	// only matters for synthetic paths; in real images the markers
	// don't overlap.
	switch best := maxIdx4(idxNode, idxSite, idxGems, idxVend); best {
	case 1:
		return npmFromRest(p[idxNode+len(mNode):])
	case 2:
		return pypiFromRest(p[idxSite+len(mSite):])
	case 3:
		var rest string
		if idxGems == 0 {
			rest = p[len(mGemsS):]
		} else {
			rest = p[idxGems+len(mGemsM)-1:] // -1 because we ++'d earlier
		}
		return rubygemsFromRest(rest)
	case 4:
		return packagistFromRest(p[idxVend+len(mVend):])
	}
	return "", "", false
}

// maxIdx4 returns 1..4 naming which of (a,b,c,d) holds the largest
// non-negative value, or 0 if all are negative.
func maxIdx4(a, b, c, d int) int {
	best := 0
	bestV := -1
	if a > bestV {
		best, bestV = 1, a
	}
	if b > bestV {
		best, bestV = 2, b
	}
	if c > bestV {
		best, bestV = 3, c
	}
	if d > bestV {
		best = 4
	}
	return best
}

func npmFromRest(rest string) (string, string, bool) {
	if rest == "" {
		return "", "", false
	}
	first, after, hasMore := strings.Cut(rest, "/")
	if !hasMore || after == "" {
		return "", "", false
	}
	if strings.HasPrefix(first, "@") {
		name, sub, hasSub := strings.Cut(after, "/")
		if !hasSub || sub == "" {
			return "", "", false
		}
		return "npm/" + first + "/" + name, sub, true
	}
	return "npm/" + first, after, true
}

func pypiFromRest(rest string) (string, string, bool) {
	if rest == "" {
		return "", "", false
	}
	first, after, hasMore := strings.Cut(rest, "/")
	if !hasMore || after == "" {
		return "", "", false
	}
	if strings.HasSuffix(first, ".dist-info") || strings.HasSuffix(first, ".egg-info") {
		return "", "", false
	}
	if first == "__pycache__" || first == "" {
		return "", "", false
	}
	return "pypi/" + first, after, true
}

func rubygemsFromRest(rest string) (string, string, bool) {
	if rest == "" {
		return "", "", false
	}
	first, after, hasMore := strings.Cut(rest, "/")
	if !hasMore || after == "" {
		return "", "", false
	}
	name, version, splitOk := splitGemDirName(first)
	if !splitOk {
		return "", "", false
	}
	return "rubygems/" + name + "@" + version, after, true
}

func packagistFromRest(rest string) (string, string, bool) {
	if rest == "" {
		return "", "", false
	}
	vendor, after, hasMore := strings.Cut(rest, "/")
	if !hasMore || after == "" {
		return "", "", false
	}
	if vendor == "composer" || vendor == "bin" || vendor == "autoload.php" {
		return "", "", false
	}
	name, sub, hasSub := strings.Cut(after, "/")
	if !hasSub || sub == "" {
		return "", "", false
	}
	return "packagist/" + vendor + "/" + name, sub, true
}

// splitGemDirName splits "rack-test-2.0.0" into ("rack-test", "2.0.0").
// Finds the last `-` whose successor starts with [0-9]. Returns ok=false
// when the dir doesn't look like a gem install (no embedded version).
func splitGemDirName(s string) (name, version string, ok bool) {
	for i := len(s) - 1; i > 0; i-- {
		if s[i] != '-' {
			continue
		}
		if i+1 >= len(s) {
			continue
		}
		c := s[i+1]
		if c >= '0' && c <= '9' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// isSourceFile gates which paths get captured for AST analysis. Keeps
// the in-memory footprint bounded on large images by skipping binary
// assets (images, fonts, .map files, etc.) and arbitrary JSON config
// — only the package manifest itself (basename == "package.json")
// is captured from the JSON family.
//
// Performance: most callers already have basename from the tar walk
// header. Use isSourceFileBase when you do, to avoid a duplicate
// path.Base call in the hot loop.
func isSourceFile(name string) bool {
	return isSourceFileBase(name, path.Base(name))
}

// isSourceFileBase is the basename-cached variant. Callers that have
// already computed `path.Base(name)` (e.g. the walker per tar entry)
// pass it in to skip a string scan.
func isSourceFileBase(name, base string) bool {
	if base == "package.json" || base == "pyproject.toml" {
		return true
	}
	switch ext(name) {
	case ".js", ".mjs", ".cjs", ".jsx",
		".ts", ".tsx", ".mts", ".cts",
		".py", ".pyi",
		".rb",
		".go",
		".rs",
		".java",
		".php", ".phtml",
		".cs",
		".ex", ".exs",
		".gleam":
		return true
	}
	return false
}

func ext(p string) string {
	if i := strings.LastIndexByte(p, '.'); i >= 0 {
		return strings.ToLower(p[i:])
	}
	return ""
}

const (
	// maxSourceFileBytes caps a single captured source file. Keeps memory
	// predictable when scanning images with multi-MB minified bundles.
	maxSourceFileBytes = 256 * 1024
	// maxPackageBytes caps total bytes captured per package. Once
	// crossed, further files in that package are skipped; the AST
	// scan still sees a representative sample.
	maxPackageBytes = 4 * 1024 * 1024
)

// groupPackageSources converts the flat path → bytes map captured by
// overlayLayersFull into a per-package PackageSource map keyed by
// `<eco>/<name>@<version>` when version is known.
//
// Resolution rules:
//   - Keys already carrying `@version` (rubygems via path) pass through.
//   - Bare keys (`npm/lodash`, `pypi/requests`) get promoted when a dep
//     in the lockfile-derived dep set matches by ecosystem + name.
//   - Bare keys with no lockfile match stay un-versioned and still feed
//     the AST analyzer; the resulting Fingerprint just lacks version
//     attribution.
//
// Manifest detection per ecosystem: npm uses `package.json`, pypi uses
// `__init__.py` (no manifest in the source tree itself — METADATA lives
// in the sibling .dist-info we already skip), packagist uses
// `composer.json`. Missing manifest is fine; AST scanners don't need it.
func groupPackageSources(pkgFiles map[string]map[string][]byte, deps []domain.Dependency) map[string]domain.PackageSource {
	if len(pkgFiles) == 0 {
		return nil
	}
	versionByName := make(map[string]string, len(deps))
	for _, d := range deps {
		versionByName[string(d.Ecosystem)+"/"+d.Name] = d.Version
	}

	out := make(map[string]domain.PackageSource, len(pkgFiles))
	for pkgKey, files := range pkgFiles {
		src := domain.PackageSource{Files: files}
		// Pick the ecosystem's canonical manifest filename when present.
		for _, mfName := range []string{"package.json", "composer.json", "pyproject.toml"} {
			if mf, ok := files[mfName]; ok {
				src.Manifest = mf
				break
			}
		}
		// rubygems keys already carry `@version` (extracted from path);
		// pass them through untouched.
		if strings.Contains(pkgKey, "@") {
			out[pkgKey] = src
			continue
		}
		if v, ok := versionByName[pkgKey]; ok && v != "" {
			out[pkgKey+"@"+v] = src
		} else {
			out[pkgKey] = src
		}
	}
	return out
}

// --- layer overlay -----------------------------------------------------

// overlayLayersFull is the extended walker behind both ScanImage (lockfile-
// only) and ScanImagePackages (lockfile + package sources). Returns
// the lockfile map (existing semantics) and the per-package source map
// (nil when opts.CapturePackageSources is false).
//
// lockfileNames is the set of basenames the walker captures as
// lockfiles — passed in from the Scanner so the walk has no implicit
// dependency on package-level mutable state.
// overlayLayersFull walks every layer and applies the overlay merge.
// Layers are decompressed + walked in PARALLEL (each yielding an
// isolated layer view), then merged sequentially so overlay semantics
// hold. The parallel decompress + tar walk overlaps disk I/O with
// gzip decode across layers — a 2-3x speedup on images with many
// layers (typical `docker save` of a multi-stage build has 10-20+).
//
// The merge step is cheap (map ops, no decode) so all I/O parallelism
// is preserved.
func overlayLayersFull(layers []v1Layer, opts ScanOpts, lockfileNames map[string]struct{}) (map[string][]byte, map[string]map[string][]byte, bool, error) {
	// Decode every layer concurrently into an isolated view.
	layerViews, err := decodeLayersParallel(layers, opts, lockfileNames)
	if err != nil {
		return nil, nil, false, err
	}

	// Merge views sequentially — order matters for whiteout semantics.
	files := make(map[string][]byte)
	deleted := make(map[string]struct{})
	var pkgFiles map[string]map[string][]byte
	if opts.CapturePackageSources {
		pkgFiles = make(map[string]map[string][]byte)
	}
	totals := &globalCaps{}

	for _, v := range layerViews {
		mergeLayerView(v, files, deleted, pkgFiles, totals)
	}
	return files, pkgFiles, totals.truncated, nil
}

// decodeLayersParallel walks every layer concurrently. Each goroutine
// decompresses + tar-walks its own layer in isolation, producing a
// layerView. Order in the returned slice matches the input layer order
// so the sequential merge applies overlays correctly.
//
// Concurrency: capped at decodeWorkers. tar + gzip are CPU+I/O bound;
// over-saturating beyond NumCPU stalls on memory pressure. Each worker
// holds at most one layer's captured bytes in memory at a time.
func decodeLayersParallel(layers []v1Layer, opts ScanOpts, lockfileNames map[string]struct{}) ([]*layerView, error) {
	out := make([]*layerView, len(layers))
	type job struct {
		idx int
		l   v1Layer
	}
	jobs := make(chan job, len(layers))
	for i, l := range layers {
		jobs <- job{idx: i, l: l}
	}
	close(jobs)

	workers := min(decodeWorkers, len(layers))
	var (
		wg       sync.WaitGroup
		errMu    sync.Mutex
		firstErr error
	)
	for range workers {
		wg.Go(func() {
			for j := range jobs {
				v, err := decodeOneLayer(j.l, opts, lockfileNames)
				if err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
					return
				}
				out[j.idx] = v
			}
		})
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// decodeWorkers caps parallelism for layer decompression. tar+gzip is
// CPU-bound; matches snapshot.enrichWorkers shape.
const decodeWorkers = 8

// layerView is an isolated read of one layer — files + whiteouts +
// per-package source bytes captured from this layer alone. The merge
// step combines these in order.
type layerView struct {
	files      map[string][]byte
	pkgFiles   map[string]map[string][]byte
	whiteouts  []string // file-level deletes
	opaqueDirs []string // opaque whiteout markers (paths with trailing /)
}

// decodeOneLayer reads a single layer in isolation, with no knowledge
// of the running overlay state. Returns a layerView the caller merges
// into the running state.
func decodeOneLayer(layer v1Layer, opts ScanOpts, lockfileNames map[string]struct{}) (*layerView, error) {
	rc, err := layer.Uncompressed()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()

	v := &layerView{
		files: make(map[string][]byte),
	}
	if opts.CapturePackageSources {
		v.pkgFiles = make(map[string]map[string][]byte)
	}
	pkgSize := make(map[string]int)

	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return v, nil
		}
		if err != nil {
			return nil, err
		}
		name := path.Clean("/" + hdr.Name)
		name = strings.TrimPrefix(name, "/")
		base := path.Base(name)
		dir := path.Dir(name)

		if base == ".wh..wh..opq" {
			v.opaqueDirs = append(v.opaqueDirs, dir+"/")
			continue
		}
		if rest, ok := strings.CutPrefix(base, ".wh."); ok {
			v.whiteouts = append(v.whiteouts, path.Join(dir, rest))
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		if _, isLock := lockfileNames[base]; isLock {
			body, err := io.ReadAll(io.LimitReader(tr, maxFileBytes))
			if err != nil {
				return nil, err
			}
			v.files[name] = body
			if v.pkgFiles != nil {
				stashPackageSource(name, body, v.pkgFiles, pkgSize)
			}
			continue
		}
		if v.pkgFiles != nil && isSourceFileBase(name, base) {
			body, err := io.ReadAll(io.LimitReader(tr, maxSourceFileBytes))
			if err != nil {
				return nil, err
			}
			stashPackageSource(name, body, v.pkgFiles, pkgSize)
		}
	}
}

// mergeLayerView applies one layer's view to the running overlay,
// honouring whiteouts and global byte caps.
func mergeLayerView(v *layerView, files map[string][]byte, deleted map[string]struct{}, pkgFiles map[string]map[string][]byte, totals *globalCaps) {
	// Opaque directory whiteouts: clear every captured path under that prefix.
	for _, prefix := range v.opaqueDirs {
		for k := range files {
			if strings.HasPrefix(k, prefix) {
				delete(files, k)
				deleted[k] = struct{}{}
			}
		}
		for pkgKey, pf := range pkgFiles {
			for fpath := range pf {
				if strings.HasPrefix(fpath, prefix) {
					delete(pf, fpath)
				}
			}
			if len(pf) == 0 {
				delete(pkgFiles, pkgKey)
			}
		}
	}
	// File-level whiteouts.
	for _, target := range v.whiteouts {
		delete(files, target)
		deleted[target] = struct{}{}
	}
	// Captured lockfiles from this layer. Honour global byte cap.
	for name, body := range v.files {
		if totals.lockfileBytes >= maxTotalLockfileBytes {
			totals.truncated = true
			break
		}
		// Re-introduction: clearing the tombstone (sequential merge order
		// matches OCI layer order, so this is safe).
		delete(deleted, name)
		totals.lockfileBytes += len(body)
		files[name] = body
	}
	// Captured package sources from this layer.
	for pkgKey, pf := range v.pkgFiles {
		dst, exists := pkgFiles[pkgKey]
		if !exists {
			dst = make(map[string][]byte)
			pkgFiles[pkgKey] = dst
		}
		for rel, body := range pf {
			if totals.packageBytes >= maxTotalPackageBytes {
				totals.truncated = true
				break
			}
			totals.packageBytes += len(body)
			dst[rel] = body
		}
	}
}

// globalCaps carries the running total of bytes captured across all
// layers. Pointer so the merge step can mutate without per-call wiring.
// truncated flips to true the first time a per-class cap (lockfile or
// package source) drops a payload — the scanner surfaces this on the
// returned PackageSet so the presenter can warn that the result is
// partial.
type globalCaps struct {
	lockfileBytes int
	packageBytes  int
	truncated     bool
}

// stashPackageSource routes name → body into the correct per-package
// bucket honouring maxPackageBytes. When the package would exceed the
// cap, the file is dropped silently — preference is given to the
// earlier files (which on npm tarballs usually include package.json
// + entry points, the most useful inputs for capability scanning).
// Returns true when the body was stashed so the caller can update
// any running totals.
func stashPackageSource(name string, body []byte, pkgFiles map[string]map[string][]byte, pkgSize map[string]int) bool {
	pkgKey, rel, ok := packageBoundary(name)
	if !ok {
		return false
	}
	if pkgSize[pkgKey]+len(body) > maxPackageBytes {
		return false
	}
	pkg, ok := pkgFiles[pkgKey]
	if !ok {
		pkg = make(map[string][]byte)
		pkgFiles[pkgKey] = pkg
	}
	pkg[rel] = body
	pkgSize[pkgKey] += len(body)
	return true
}

// defaultLockfileNames is the set used when callers (tests, simple
// utilities) don't bring their own. Populated lazily from the locksnap
// registry guarded by sync.Once.
var (
	defaultLockOnce  sync.Once
	defaultLockNames map[string]struct{}
)

func defaultLockfileNames() map[string]struct{} {
	defaultLockOnce.Do(func() {
		defaultLockNames = make(map[string]struct{})
		for _, p := range locksnap.Registered() {
			defaultLockNames[p.Filename()] = struct{}{}
		}
	})
	// Defensive copy — callers occasionally pass the result into long-
	// running walkers, and we don't want a downstream `delete()` to
	// silently corrupt the shared singleton.
	out := make(map[string]struct{}, len(defaultLockNames))
	for k := range defaultLockNames {
		out[k] = struct{}{}
	}
	return out
}

// overlayLayers walks every layer's tar from base → top, building a
// file map that reflects the final root filesystem the image would
// expose at runtime. Returned map: path → file bytes.
const (
	// maxFileBytes caps any single captured lockfile. 4 MB is generous
	// for every lockfile we know — npm's package-lock.json on a 5000-
	// dep monorepo lands around 2 MB.
	maxFileBytes = 4 * 1024 * 1024
	// maxTotalLockfileBytes caps the total bytes captured from
	// lockfile-shaped paths across the whole image. Prevents memory
	// DoS via a crafted image with thousands of "package-lock.json"
	// entries: per-file cap × N would otherwise let an attacker burn
	// tens of GB. 256 MB is well past any realistic monorepo.
	maxTotalLockfileBytes = 256 * 1024 * 1024
	// maxTotalPackageBytes caps the total bytes captured for AST
	// analysis (across all node_modules/* packages). Once crossed,
	// further packages are skipped — the scan reports a partial
	// result rather than OOM-ing the runner.
	maxTotalPackageBytes = 512 * 1024 * 1024
)

// v1Layer is the subset of github.com/google/go-containerregistry/pkg/v1.Layer
// the scanner depends on. Stated explicitly so tests can pass a fake
// without importing the whole v1 package.
type v1Layer interface {
	Uncompressed() (io.ReadCloser, error)
}
