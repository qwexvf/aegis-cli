// Package sbomcdx builds CycloneDX SBOMs from aegis snapshot data.
// Pure transformation — no I/O, no network. Constructors are
// deterministic so two runs over the same input produce byte-identical
// output (modulo a UUID + timestamp the caller can stamp).
package sbomcdx

import (
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/qwexvf/aegis-cli/internal/domain"
)

// PURL builds a canonical package-url for one dependency. Returns the
// empty string when the ecosystem is unknown — callers should treat
// that as a programming error (every ecosystem in domain.Ecosystem
// should be mapped here).
//
// Maven names arrive as "groupId:artifactId" from the locksnap parser;
// PURL spec wants them as separate namespace + name fields.
// Composer (packagist) names arrive as "vendor/name" and PURL wants
// that as namespace + name too.
// Scoped npm names ("@scope/name") become namespace="@scope" + name.
// The packageurl-go library handles percent-encoding on .ToString().
func PURL(d domain.Dependency) string {
	ns, name := splitName(d.Ecosystem, d.Name)
	t, ok := purlType(d.Ecosystem)
	if !ok {
		return ""
	}
	p := packageurl.NewPackageURL(t, ns, name, d.Version, nil, "")
	return p.ToString()
}

func splitName(eco domain.Ecosystem, raw string) (namespace, name string) {
	switch eco {
	case domain.EcoNpm:
		if strings.HasPrefix(raw, "@") {
			if i := strings.IndexByte(raw, '/'); i > 0 {
				return raw[:i], raw[i+1:]
			}
		}
		return "", raw
	case domain.EcoMaven:
		if i := strings.IndexByte(raw, ':'); i > 0 {
			return raw[:i], raw[i+1:]
		}
		return "", raw
	case domain.EcoPackagist:
		if i := strings.IndexByte(raw, '/'); i > 0 {
			return raw[:i], raw[i+1:]
		}
		return "", raw
	case domain.EcoGo:
		// PURL convention: namespace is the path prefix before the
		// final segment ("github.com/spf13" + "cobra"). The
		// packageurl-go library percent-encodes "/" inside the name,
		// which is wrong for golang — splitting here keeps the
		// canonical "pkg:golang/host/owner/name@v" form.
		if i := strings.LastIndexByte(raw, '/'); i > 0 {
			return raw[:i], raw[i+1:]
		}
		return "", raw
	}
	return "", raw
}

func purlType(eco domain.Ecosystem) (string, bool) {
	switch eco {
	case domain.EcoNpm:
		return packageurl.TypeNPM, true
	case domain.EcoPyPI:
		return packageurl.TypePyPi, true
	case domain.EcoCrates:
		return packageurl.TypeCargo, true
	case domain.EcoGo:
		return packageurl.TypeGolang, true
	case domain.EcoMaven:
		return packageurl.TypeMaven, true
	case domain.EcoRubyGems:
		return packageurl.TypeGem, true
	case domain.EcoPackagist:
		return packageurl.TypeComposer, true
	case domain.EcoNuGet:
		return packageurl.TypeNuget, true
	case domain.EcoGleam:
		return packageurl.TypeHex, true
	case domain.EcoNeovim:
		// Neovim plugins are git-distributed with no canonical registry.
		// PURL spec recommends `pkg:generic/<name>@<commit-sha>` for this
		// shape. A future enhancement could promote to `pkg:github/...`
		// when the source URL is known (requires plumbing URL through
		// domain.Dependency — Cloud schema bump, deferred).
		return packageurl.TypeGeneric, true
	}
	return "", false
}
