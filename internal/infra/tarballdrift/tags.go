package tarballdrift

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// ParseRepository takes a package.json "repository" field and returns
// the (owner, repo) pair if it points at a GitHub host. The npm schema
// permits a few shapes:
//
//	"repository": "github:owner/repo"
//	"repository": "git+https://github.com/owner/repo.git"
//	"repository": { "type": "git", "url": "git+ssh://git@github.com/owner/repo.git" }
//
// We accept all of them, plus bare "owner/repo" (legal under the
// "shortcut" alias). Non-GitHub hosts return ErrUnsupportedHost — the
// detector treats that the same as "no repo" and skips.
//
// Returned owner/repo are lower-case-preserved (GitHub is case-
// insensitive but APIs canonicalize on the server).
func ParseRepository(field RepositoryField) (owner, repo string, err error) {
	raw := strings.TrimSpace(field.URL())
	if raw == "" {
		return "", "", ErrNoRepository
	}

	// Shorthand: "github:owner/repo" or "owner/repo"
	if rest, ok := strings.CutPrefix(raw, "github:"); ok {
		return splitOwnerRepo(rest)
	}
	if strings.Count(raw, "/") == 1 && !strings.Contains(raw, ":") {
		return splitOwnerRepo(raw)
	}

	// Strip the "git+" prefix npm sometimes adds.
	raw = strings.TrimPrefix(raw, "git+")
	// Convert "git@github.com:owner/repo.git" → URL parser-friendly form.
	if strings.HasPrefix(raw, "git@") {
		raw = strings.Replace(raw, ":", "/", 1)
		raw = "ssh://" + raw
	}

	u, parseErr := url.Parse(raw)
	if parseErr != nil {
		return "", "", parseErr
	}
	host := strings.ToLower(u.Host)
	// Strip user-info from ssh URLs ("git@github.com").
	if at := strings.LastIndex(host, "@"); at >= 0 {
		host = host[at+1:]
	}
	if host != "github.com" && host != "www.github.com" {
		return "", "", ErrUnsupportedHost
	}
	return splitOwnerRepo(strings.TrimPrefix(u.Path, "/"))
}

// ErrNoRepository — package.json has no usable repository field.
var ErrNoRepository = errors.New("no repository field")

// ErrUnsupportedHost — repository is hosted somewhere we can't query
// (gitlab, bitbucket, self-hosted gitea, ...). Skip cleanly.
var ErrUnsupportedHost = errors.New("repository host not supported")

func splitOwnerRepo(path string) (string, string, error) {
	path = strings.Trim(path, "/")
	path = strings.TrimSuffix(path, ".git")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", errors.New("invalid owner/repo path: " + path)
	}
	return parts[0], parts[1], nil
}

// RepositoryField is the union of the two shapes npm allows for the
// package.json "repository" field. Use ReadRepositoryField to unmarshal
// either form into this struct.
type RepositoryField struct {
	Type string
	Raw  string
}

// URL returns the underlying URL or shorthand string. Type is unused
// downstream — we keep it for completeness / debugging.
func (r RepositoryField) URL() string { return r.Raw }

// TagCandidates enumerates the ref patterns we'll try, in priority
// order, when looking for the upstream tag for (pkg, version). Most
// modern packages publish `v{version}` or bare `{version}`; monorepos
// often use `{pkgname}@{version}` (changesets-style). Returned slice
// is deduped, preserving input order.
//
// For scoped packages like `@scope/name`, the leading `@` is stripped
// when forming the monorepo-style tag to match changesets' actual
// output (`name@1.2.3`, not `@scope/name@1.2.3`).
func TagCandidates(pkgName, version string) []string {
	pkgName = strings.TrimSpace(pkgName)
	version = strings.TrimSpace(version)
	if version == "" {
		return nil
	}

	short := pkgName
	if strings.HasPrefix(short, "@") {
		if slash := strings.IndexByte(short, '/'); slash >= 0 {
			short = short[slash+1:]
		}
	}

	candidates := []string{
		"v" + version,
		version,
	}
	if pkgName != "" {
		candidates = append(candidates,
			pkgName+"@"+version,
			pkgName+"-v"+version,
			pkgName+"-"+version,
		)
		if short != pkgName {
			candidates = append(candidates,
				short+"@"+version,
				short+"-v"+version,
				short+"-"+version,
			)
		}
	}

	seen := make(map[string]bool, len(candidates))
	out := candidates[:0]
	for _, c := range candidates {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

// semverLike matches plausible-semver strings used by ResolveTag to
// short-circuit obvious non-version refs.
var semverLike = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:[-+].*)?$`)

// LooksLikeVersion reports whether `ref` is plausibly a semver tag.
// Used as a cheap pre-filter so callers don't fire HTTP for input
// like "main" or "HEAD".
func LooksLikeVersion(ref string) bool {
	return semverLike.MatchString(strings.TrimSpace(ref))
}
