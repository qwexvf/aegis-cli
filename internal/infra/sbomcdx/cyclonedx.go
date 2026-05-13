package sbomcdx

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/qwexvf/aegis-cli/internal/domain"
)

// Options controls one BOM build. Fields the caller may want stable
// (Timestamp, SerialNumber) are explicit so tests can pin them.
type Options struct {
	// AegisVersion is stamped onto the BOM's tool record. Required.
	AegisVersion string
	// Project is the root component name. When empty, falls back to
	// the snapshot's Project field, then to "project".
	Project string
	// Timestamp is stamped on metadata.timestamp. When zero, time.Now()
	// in UTC is used.
	Timestamp time.Time
	// SerialNumber is the urn:uuid for this BOM. When empty, a fresh
	// v4-ish urn is generated from crypto/rand.
	SerialNumber string
	// IncludeVulnerabilities maps each Dependency.Advisories[] entry
	// into the BOM's vulnerabilities section. Off by default — the
	// caller decides whether the snapshot has been enriched.
	IncludeVulnerabilities bool
}

// Build turns a snapshot into a CycloneDX 1.5 BOM document. Pure
// function — no I/O, no goroutines, deterministic given a fixed
// SerialNumber + Timestamp.
func Build(snap domain.Snapshot, opts Options) *cdx.BOM {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_5
	bom.SerialNumber = opts.SerialNumber
	if bom.SerialNumber == "" {
		bom.SerialNumber = newSerial()
	}
	bom.Version = 1

	ts := opts.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	rootName := opts.Project
	if rootName == "" {
		rootName = snap.Project
	}
	if rootName == "" {
		rootName = "project"
	}
	rootRef := "aegis:root:" + rootName

	bom.Metadata = &cdx.Metadata{
		Timestamp: ts.Format(time.RFC3339),
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{{
				Type:    cdx.ComponentTypeApplication,
				Name:    "aegis-cli",
				Version: opts.AegisVersion,
			}},
		},
		Component: &cdx.Component{
			BOMRef: rootRef,
			Type:   cdx.ComponentTypeApplication,
			Name:   rootName,
		},
	}

	components := make([]cdx.Component, 0, len(snap.Deps))
	for _, d := range snap.Deps {
		components = append(components, componentFromDep(d))
	}
	bom.Components = &components

	if opts.IncludeVulnerabilities {
		if vulns := vulnerabilitiesFromDeps(snap.Deps); len(vulns) > 0 {
			bom.Vulnerabilities = &vulns
		}
	}

	return bom
}

// bomRefFor returns a stable component reference for a dep. PURL is
// preferred; the fallback handles future Ecosystem values that haven't
// been mapped in purl.go yet (string enum can grow without compile
// error), keeping the BOM well-formed instead of emitting an empty ref.
func bomRefFor(d domain.Dependency) string {
	if p := PURL(d); p != "" {
		return p
	}
	return string(d.Ecosystem) + ":" + d.Name + "@" + d.Version
}

func componentFromDep(d domain.Dependency) cdx.Component {
	purl := PURL(d)

	scope := cdx.ScopeOptional
	if d.Direct {
		scope = cdx.ScopeRequired
	}

	c := cdx.Component{
		BOMRef:     bomRefFor(d),
		Type:       cdx.ComponentTypeLibrary,
		Name:       d.Name,
		Version:    d.Version,
		PackageURL: purl,
		Scope:      scope,
	}

	if h := hashFromIntegrity(d.Integrity); h != nil {
		c.Hashes = &[]cdx.Hash{*h}
	}

	if d.License != "" {
		c.Licenses = &cdx.Licenses{
			cdx.LicenseChoice{Expression: d.License},
		}
	}

	if props := aegisProperties(d); len(props) > 0 {
		c.Properties = &props
	}

	return c
}

// maxIntegrityLen caps a single integrity string before base64 decode.
// SHA-512 in SRI form is ~95 bytes ("sha512-" + 88 b64 chars); 512
// leaves headroom for future hash algos. The cap blocks a DoS where a
// malicious aegis.lock (PR-checked-in) ships a multi-MB integrity
// field that would allocate proportionally during decode.
const maxIntegrityLen = 512

// hashFromIntegrity decodes the "sha512-<base64>" integrity strings
// npm-style lockfiles ship. Returns nil for empty / unrecognised /
// over-long inputs — the BOM stays valid, just without a hash for
// that dep.
func hashFromIntegrity(integrity string) *cdx.Hash {
	if integrity == "" || len(integrity) > maxIntegrityLen {
		return nil
	}
	algo, b64, ok := strings.Cut(integrity, "-")
	if !ok {
		return nil
	}
	var alg cdx.HashAlgorithm
	switch strings.ToLower(algo) {
	case "sha512":
		alg = cdx.HashAlgoSHA512
	case "sha384":
		alg = cdx.HashAlgoSHA384
	case "sha256":
		alg = cdx.HashAlgoSHA256
	case "sha1":
		alg = cdx.HashAlgoSHA1
	default:
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil
	}
	return &cdx.Hash{Algorithm: alg, Value: hex.EncodeToString(raw)}
}

func aegisProperties(d domain.Dependency) []cdx.Property {
	var props []cdx.Property
	if d.Reachability != domain.ReachabilityUnknown {
		props = append(props, cdx.Property{
			Name:  "aegis:reachability",
			Value: d.Reachability.String(),
		})
	}
	if d.Fingerprint != nil && len(d.Fingerprint.Capabilities) > 0 {
		caps := make([]string, 0, len(d.Fingerprint.Capabilities))
		for _, c := range d.Fingerprint.Capabilities {
			caps = append(caps, c.String())
		}
		sort.Strings(caps)
		props = append(props, cdx.Property{
			Name:  "aegis:capabilities",
			Value: strings.Join(caps, ","),
		})
	}
	return props
}

func vulnerabilitiesFromDeps(deps []domain.Dependency) []cdx.Vulnerability {
	var out []cdx.Vulnerability
	for _, d := range deps {
		if len(d.Advisories) == 0 {
			continue
		}
		ref := bomRefFor(d)
		for _, a := range d.Advisories {
			v := cdx.Vulnerability{
				ID:          a.ID,
				Description: a.Summary,
				Affects:     &[]cdx.Affects{{Ref: ref}},
			}
			if a.Source != "" || a.URL != "" {
				v.Source = &cdx.Source{Name: a.Source, URL: a.URL}
			}
			if sev := mapSeverity(a.Severity); sev != cdx.SeverityUnknown {
				v.Ratings = &[]cdx.VulnerabilityRating{{Severity: sev}}
			}
			out = append(out, v)
		}
	}
	return out
}

func mapSeverity(s domain.Severity) cdx.Severity {
	switch s {
	case domain.SevCritical:
		return cdx.SeverityCritical
	case domain.SevHigh:
		return cdx.SeverityHigh
	case domain.SevMedium:
		return cdx.SeverityMedium
	case domain.SevLow:
		return cdx.SeverityLow
	case domain.SevInfo:
		return cdx.SeverityInfo
	}
	return cdx.SeverityUnknown
}

func newSerial() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand should never fail; fall back to a stable string
		// to keep the BOM well-formed.
		return "urn:uuid:00000000-0000-0000-0000-000000000000"
	}
	// RFC 4122 v4 variant bits.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
