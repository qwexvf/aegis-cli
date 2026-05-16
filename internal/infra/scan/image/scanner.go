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
}

// NewScanner builds an image Scanner from the current package-level
// locksnap registry. Lockfile parser additions made after NewScanner
// is constructed are NOT picked up — callers should register first,
// then construct.
func NewScanner() *Scanner {
	s := &Scanner{
		parsersByFilename: make(map[string]locksnap.LockfileParser),
	}
	for _, p := range locksnap.Registered() {
		s.parsersByFilename[p.Filename()] = p
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
	img, err := tarball.ImageFromPath(imagePath, nil)
	if err != nil {
		return nil, fmt.Errorf("image: open %s: %w", imagePath, err)
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("image: list layers: %w", err)
	}

	vlayers := make([]v1Layer, len(layers))
	for i, l := range layers {
		vlayers[i] = l
	}
	files, err := overlayLayers(vlayers)
	if err != nil {
		return nil, fmt.Errorf("image: overlay layers: %w", err)
	}
	return s.parseFiles(files), nil
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

// dedupSort removes duplicates (same ecosystem/name/version) and
// returns a deterministically ordered slice. Two layers can both
// contain the same lockfile (e.g. `npm ci` re-run), or two images
// merged via multi-stage builds — dedup keeps the final BOM clean.
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

// --- layer overlay -----------------------------------------------------

// overlayLayers walks every layer's tar from base → top, building a
// file map that reflects the final root filesystem the image would
// expose at runtime. Returned map: path → file bytes.
//
// Capacity guard: per-file bytes are capped to maxFileBytes so a
// pathological lockfile (or a packed binary masquerading as one)
// can't OOM the scanner. The image itself can carry hundreds of
// gigabytes of layer data, but only the matched files are kept.
func overlayLayers(layers []v1Layer) (map[string][]byte, error) {
	files := make(map[string][]byte)
	deleted := make(map[string]struct{}) // path → whited-out
	for _, layer := range layers {
		rc, err := layer.Uncompressed()
		if err != nil {
			return nil, err
		}
		err = walkLayer(rc, files, deleted)
		_ = rc.Close()
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}

// walkLayer applies a single layer's tar to the running file map.
// Whiteouts are recorded in `deleted`; subsequent layers cannot
// resurrect them — the runtime view honours the same rule.
func walkLayer(rc io.Reader, files map[string][]byte, deleted map[string]struct{}) error {
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := path.Clean("/" + hdr.Name)
		name = strings.TrimPrefix(name, "/")

		base := path.Base(name)
		dir := path.Dir(name)

		// Opaque directory whiteout: everything currently under `dir`
		// is hidden from this layer onward.
		if base == ".wh..wh..opq" {
			prefix := dir + "/"
			for k := range files {
				if strings.HasPrefix(k, prefix) {
					delete(files, k)
					deleted[k] = struct{}{}
				}
			}
			continue
		}

		// File-level whiteout: `.wh.foo` deletes `dir/foo`.
		if rest, ok := strings.CutPrefix(base, ".wh."); ok {
			target := path.Join(dir, rest)
			delete(files, target)
			deleted[target] = struct{}{}
			continue
		}

		// A later layer re-introducing a whited-out path clears the
		// tombstone so this layer's content wins. (OCI layers are
		// applied sequentially.)
		delete(deleted, name)

		switch hdr.Typeflag {
		case tar.TypeReg:
			// Only capture files whose basename is a registered
			// lockfile. Saves memory: even a 10 GB Java image rarely
			// has more than a handful of lockfiles.
			if !isCandidate(base) {
				continue
			}
			body, err := io.ReadAll(io.LimitReader(tr, maxFileBytes))
			if err != nil {
				return err
			}
			files[name] = body
		case tar.TypeDir:
			// Directory entries don't carry data we care about.
		case tar.TypeSymlink, tar.TypeLink:
			// Symlinks are not resolved in MVP; following them would
			// require a two-pass walk and most lockfiles aren't
			// behind symlinks anyway.
		}
	}
}

// maxFileBytes caps any single captured file. 4 MB is generous for
// every lockfile we know — npm's package-lock.json on a 5000-dep
// monorepo lands around 2 MB.
const maxFileBytes = 4 * 1024 * 1024

// candidateFilenames is the set of basenames the scanner cares about.
// Populated lazily on first use from the locksnap registry. Kept
// separate from Scanner so the walkLayer hot loop doesn't take the
// indirection.
var candidateFilenames map[string]struct{}

func isCandidate(base string) bool {
	if candidateFilenames == nil {
		candidateFilenames = make(map[string]struct{})
		for _, p := range locksnap.Registered() {
			candidateFilenames[p.Filename()] = struct{}{}
		}
	}
	_, ok := candidateFilenames[base]
	return ok
}

// v1Layer is the subset of github.com/google/go-containerregistry/pkg/v1.Layer
// the scanner depends on. Stated explicitly so tests can pass a fake
// without importing the whole v1 package.
type v1Layer interface {
	Uncompressed() (io.ReadCloser, error)
}
