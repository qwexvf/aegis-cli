package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/infra/tarballdrift"
)

// repoTreeAdapter bridges the usecase.RepoTreeFetcher port to the
// infra/tarballdrift package: parses package.json for the repository
// URL, picks the best matching tag from the candidate list, fetches
// the recursive git tree, and surfaces the file paths.
//
// All failure modes (no repo field, unsupported host, no matching
// tag, rate-limited, network error) collapse to a (nil, "", nil)
// return — the use case treats that as "no signal", never as a
// verdict-pushing error. Errors are returned only for caller-side
// programming bugs that aren't expected at runtime.
type repoTreeAdapter struct {
	client *tarballdrift.Client
}

func newRepoTreeAdapter() *repoTreeAdapter {
	var opts []tarballdrift.Option
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		opts = append(opts, tarballdrift.WithToken(t))
	}
	return &repoTreeAdapter{client: tarballdrift.New(opts...)}
}

// FetchRepoTree resolves the repo from package.json, walks the tag
// candidate list, and returns the file paths on first hit. Only
// implemented for the npm ecosystem today — other ecosystems return
// (nil, "", nil) and the heuristic skips.
func (a *repoTreeAdapter) FetchRepoTree(
	ctx context.Context,
	eco domain.Ecosystem,
	name, version string,
	manifestRaw []byte,
) (files []string, subdir string, err error) {
	if eco != domain.EcoNpm || len(manifestRaw) == 0 {
		return nil, "", nil
	}

	var pkg struct {
		Repository json.RawMessage `json:"repository"`
	}
	if err := json.Unmarshal(manifestRaw, &pkg); err != nil {
		return nil, "", nil
	}

	field, ok := decodeRepositoryField(pkg.Repository)
	if !ok {
		return nil, "", nil
	}

	owner, repo, parseErr := tarballdrift.ParseRepository(field)
	if parseErr != nil {
		return nil, "", nil // unsupported host or invalid format — skip
	}

	// Walk candidate tags; first one that resolves wins.
	for _, ref := range tarballdrift.TagCandidates(name, version) {
		if !tarballdrift.LooksLikeVersion(ref) && !looksLikePkgScopedTag(ref) {
			continue
		}
		tree, fetchErr := a.client.Tree(ctx, owner, repo, ref)
		if fetchErr != nil {
			if errors.Is(fetchErr, tarballdrift.ErrTreeNotFound) {
				continue
			}
			// Rate-limit, network, or unexpected error — skip the
			// drift check for this dep, don't fail the scan.
			return nil, "", nil
		}
		// Truncated trees (>100k entries) are an incomplete file
		// list; comparing the tarball against the partial set
		// produces silent false-negatives — a payload in the
		// unreturned tail looks like it matches because we never
		// see it. Skip the drift check on truncation rather than
		// emit a misleading "clean" verdict.
		if tree.Truncated {
			return nil, "", nil
		}
		paths := make([]string, 0, len(tree.Tree))
		for _, n := range tree.Tree {
			if n.Type == "blob" {
				paths = append(paths, n.Path)
			}
		}
		return paths, repositorySubdir(pkg.Repository), nil
	}
	return nil, "", nil
}

// decodeRepositoryField accepts either the string form or the object
// form npm allows for package.json "repository".
func decodeRepositoryField(raw json.RawMessage) (tarballdrift.RepositoryField, bool) {
	if len(raw) == 0 {
		return tarballdrift.RepositoryField{}, false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return tarballdrift.RepositoryField{Raw: s}, true
	}
	var obj struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil && obj.URL != "" {
		return tarballdrift.RepositoryField{Type: obj.Type, Raw: obj.URL}, true
	}
	return tarballdrift.RepositoryField{}, false
}

// repositorySubdir returns the optional "directory" field from the
// object form of package.json `repository` — points at the package's
// subdir inside a monorepo. Used by the diff layer to strip the
// prefix before path comparison.
func repositorySubdir(raw json.RawMessage) string {
	var obj struct {
		Directory string `json:"directory"`
	}
	_ = json.Unmarshal(raw, &obj)
	return obj.Directory
}

// looksLikePkgScopedTag accepts strings like "@scope/name@1.2.3" or
// "name@1.2.3" — TagCandidates produces these for monorepo packages
// and LooksLikeVersion alone would reject them. Cheap pre-filter so
// the network only fires for plausible tag shapes.
func looksLikePkgScopedTag(ref string) bool {
	if i := lastByte(ref, '@'); i > 0 && i < len(ref)-1 {
		return tarballdrift.LooksLikeVersion(ref[i+1:])
	}
	return false
}

func lastByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}
