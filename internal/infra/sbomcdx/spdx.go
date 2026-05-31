package sbomcdx

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// SPDXOptions mirrors Options but without CycloneDX-specific fields.
type SPDXOptions struct {
	AegisVersion string
	Project      string
	Timestamp    time.Time
	SerialNumber string // used as the UUID suffix in documentNamespace
	// IncludeVulnerabilities attaches each Dependency.Advisories[] entry as
	// an SPDX 2.3 SECURITY externalRef (referenceType "advisory") on the
	// package — SPDX's native way to carry vulnerability data.
	IncludeVulnerabilities bool
}

// spdxDocument is the top-level SPDX 2.3 JSON document.
type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SpdxElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSpdxElement string `json:"relatedSpdxElement"`
}

// BuildSPDX turns a snapshot into an SPDX 2.3 JSON document value.
// Pure function — no I/O, no goroutines.
func BuildSPDX(snap domain.Snapshot, opts SPDXOptions) spdxDocument {
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

	serial := opts.SerialNumber
	if serial == "" {
		// reuse the same random serial generator
		serial = newSerial()
	}
	// strip "urn:uuid:" prefix for the namespace URI
	uuidPart := strings.TrimPrefix(serial, "urn:uuid:")

	rootID := spdxSanitizeID("Package-" + rootName)
	ns := fmt.Sprintf("https://aegis-cli.dev/sbom/%s/%s", url.PathEscape(rootName), uuidPart)

	doc := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              rootName,
		DocumentNamespace: ns,
		CreationInfo: spdxCreationInfo{
			Created: ts.UTC().Format(time.RFC3339),
			Creators: []string{
				"Tool: aegis-cli-" + opts.AegisVersion,
			},
		},
	}

	// Root package (the scanned project itself).
	rootPkg := spdxPackage{
		SPDXID:           "SPDXRef-" + rootID,
		Name:             rootName,
		VersionInfo:      "NOASSERTION",
		DownloadLocation: "NOASSERTION",
		FilesAnalyzed:    false,
		LicenseConcluded: "NOASSERTION",
		LicenseDeclared:  "NOASSERTION",
		CopyrightText:    "NOASSERTION",
	}
	doc.Packages = append(doc.Packages, rootPkg)

	// DOCUMENT DESCRIBES root.
	doc.Relationships = append(doc.Relationships, spdxRelationship{
		SpdxElementID:      "SPDXRef-DOCUMENT",
		RelationshipType:   "DESCRIBES",
		RelatedSpdxElement: "SPDXRef-" + rootID,
	})

	for _, d := range snap.Deps {
		pkgID := spdxPackageID(d)
		rel := "DYNAMIC_LINK" // transitive
		if d.Direct {
			rel = "DEPENDS_ON"
		}
		doc.Relationships = append(doc.Relationships, spdxRelationship{
			SpdxElementID:      "SPDXRef-" + rootID,
			RelationshipType:   rel,
			RelatedSpdxElement: "SPDXRef-" + pkgID,
		})

		pkg := spdxPackage{
			SPDXID:           "SPDXRef-" + pkgID,
			Name:             d.Name,
			VersionInfo:      d.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			LicenseConcluded: "NOASSERTION",
			LicenseDeclared:  spdxLicense(d.License),
			CopyrightText:    "NOASSERTION",
		}

		if purl := PURL(d); purl != "" {
			pkg.ExternalRefs = append(pkg.ExternalRefs, spdxExternalRef{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  purl,
			})
		}

		if opts.IncludeVulnerabilities {
			for _, a := range d.Advisories {
				if a.VEXSuppressed {
					continue
				}
				pkg.ExternalRefs = append(pkg.ExternalRefs, spdxExternalRef{
					ReferenceCategory: "SECURITY",
					ReferenceType:     "advisory",
					ReferenceLocator:  advisoryLocator(a),
				})
			}
		}

		doc.Packages = append(doc.Packages, pkg)
	}

	return doc
}

func spdxLicense(license string) string {
	if license == "" {
		return "NOASSERTION"
	}
	return license
}

// advisoryLocator returns the SECURITY externalRef locator for an advisory:
// its canonical URL, falling back to the osv.dev page for the ID.
func advisoryLocator(a domain.Advisory) string {
	if a.URL != "" {
		return a.URL
	}
	if a.ID != "" {
		return "https://osv.dev/vulnerability/" + a.ID
	}
	return "NOASSERTION"
}

// spdxIDInvalid matches characters not allowed in SPDX identifiers.
// SPDX 2.3 §2.2: only [a-zA-Z0-9-.] after "SPDXRef-".
var spdxIDInvalid = regexp.MustCompile(`[^a-zA-Z0-9\-.]`)

func spdxSanitizeID(s string) string {
	return spdxIDInvalid.ReplaceAllLiteralString(s, "-")
}

func spdxPackageID(d domain.Dependency) string {
	return spdxSanitizeID(fmt.Sprintf("Package-%s-%s-%s", d.Ecosystem, d.Name, d.Version))
}
