package sbomcdx

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestBuildSPDX_BasicShape(t *testing.T) {
	snap := domain.Snapshot{
		Project: "myapp",
		Deps: []domain.Dependency{
			{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21", Direct: true, License: "MIT"},
			{Ecosystem: domain.EcoPyPI, Name: "requests", Version: "2.31.0", Direct: false},
		},
	}
	doc := BuildSPDX(snap, SPDXOptions{
		AegisVersion: "v0.0.0-test",
		Timestamp:    time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
		SerialNumber: "urn:uuid:00000000-0000-0000-0000-000000000003",
	})

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Fatalf("spdxVersion: %s", doc.SPDXVersion)
	}
	if doc.DataLicense != "CC0-1.0" {
		t.Fatalf("dataLicense: %s", doc.DataLicense)
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Fatalf("SPDXID: %s", doc.SPDXID)
	}
	if doc.Name != "myapp" {
		t.Fatalf("name: %s", doc.Name)
	}
	if !strings.Contains(doc.DocumentNamespace, "myapp") {
		t.Fatalf("namespace missing project: %s", doc.DocumentNamespace)
	}
	if !strings.Contains(doc.DocumentNamespace, "00000000-0000-0000-0000-000000000003") {
		t.Fatalf("namespace missing uuid: %s", doc.DocumentNamespace)
	}

	// root package + 2 deps = 3 packages
	if len(doc.Packages) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(doc.Packages))
	}

	// creator stamped
	if len(doc.CreationInfo.Creators) == 0 || !strings.Contains(doc.CreationInfo.Creators[0], "aegis-cli") {
		t.Fatalf("creator not set: %v", doc.CreationInfo.Creators)
	}
}

func TestBuildSPDX_PackageFields(t *testing.T) {
	snap := domain.Snapshot{
		Project: "proj",
		Deps: []domain.Dependency{
			{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21", Direct: true, License: "MIT"},
		},
	}
	doc := BuildSPDX(snap, SPDXOptions{AegisVersion: "v0.0.0-test"})

	// find lodash package
	var lodash *spdxPackage
	for i := range doc.Packages {
		if doc.Packages[i].Name == "lodash" {
			lodash = &doc.Packages[i]
			break
		}
	}
	if lodash == nil {
		t.Fatal("lodash package not found")
	}
	if lodash.VersionInfo != "4.17.21" {
		t.Fatalf("versionInfo: %s", lodash.VersionInfo)
	}
	if lodash.LicenseDeclared != "MIT" {
		t.Fatalf("licenseDeclared: %s", lodash.LicenseDeclared)
	}
	if len(lodash.ExternalRefs) != 1 || lodash.ExternalRefs[0].ReferenceLocator != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("externalRefs: %+v", lodash.ExternalRefs)
	}
	if lodash.ExternalRefs[0].ReferenceCategory != "PACKAGE-MANAGER" {
		t.Fatalf("referenceCategory: %s", lodash.ExternalRefs[0].ReferenceCategory)
	}
}

func TestBuildSPDX_Relationships(t *testing.T) {
	snap := domain.Snapshot{
		Project: "proj",
		Deps: []domain.Dependency{
			{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21", Direct: true},
			{Ecosystem: domain.EcoNpm, Name: "tslib", Version: "2.6.0", Direct: false},
		},
	}
	doc := BuildSPDX(snap, SPDXOptions{AegisVersion: "v0.0.0-test"})

	// must have DESCRIBES + DEPENDS_ON (direct) + DYNAMIC_LINK (transitive)
	types := map[string]int{}
	for _, r := range doc.Relationships {
		types[r.RelationshipType]++
	}
	if types["DESCRIBES"] != 1 {
		t.Fatalf("expected 1 DESCRIBES, got %d: %v", types["DESCRIBES"], doc.Relationships)
	}
	if types["DEPENDS_ON"] != 1 {
		t.Fatalf("expected 1 DEPENDS_ON (direct), got %d", types["DEPENDS_ON"])
	}
	if types["DYNAMIC_LINK"] != 1 {
		t.Fatalf("expected 1 DYNAMIC_LINK (transitive), got %d", types["DYNAMIC_LINK"])
	}
}

func TestBuildSPDX_NoLicense(t *testing.T) {
	snap := domain.Snapshot{
		Deps: []domain.Dependency{
			{Ecosystem: domain.EcoNpm, Name: "x", Version: "1.0.0"},
		},
	}
	doc := BuildSPDX(snap, SPDXOptions{AegisVersion: "v0.0.0-test"})
	for _, p := range doc.Packages {
		if p.Name == "x" && p.LicenseDeclared != "NOASSERTION" {
			t.Fatalf("missing license should be NOASSERTION, got %q", p.LicenseDeclared)
		}
	}
}

func TestBuildSPDX_ValidJSON(t *testing.T) {
	snap := domain.Snapshot{
		Project: "json-test",
		Deps: []domain.Dependency{
			{Ecosystem: domain.EcoCrates, Name: "serde", Version: "1.0.0", Direct: true},
		},
	}
	doc := BuildSPDX(snap, SPDXOptions{AegisVersion: "v0.0.0-test"})
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not valid json: %v", err)
	}
	if m["spdxVersion"] != "SPDX-2.3" {
		t.Fatalf("spdxVersion in json: %v", m["spdxVersion"])
	}
}

func TestBuildSPDX_NamespaceEncoding(t *testing.T) {
	// project names with spaces or slashes must produce valid URIs.
	// baseline: https://aegis-cli.dev/sbom/<project>/<uuid> = 5 slashes.
	// An unescaped slash in the project segment would push the count above 5.
	cases := []string{"my project", "org/repo", "hello world"}
	for _, name := range cases {
		snap := domain.Snapshot{Project: name}
		doc := BuildSPDX(snap, SPDXOptions{AegisVersion: "v0.0.0-test"})
		if strings.ContainsAny(doc.DocumentNamespace, " ") {
			t.Fatalf("namespace has unencoded space for project %q: %s", name, doc.DocumentNamespace)
		}
		if strings.Count(doc.DocumentNamespace, "/") > 5 {
			t.Fatalf("namespace has unescaped slash in project name %q: %s", name, doc.DocumentNamespace)
		}
	}
}

func TestBuildSPDX_IDSanitization(t *testing.T) {
	// scoped npm names and slashes must produce valid SPDX IDs
	snap := domain.Snapshot{
		Project: "proj",
		Deps: []domain.Dependency{
			{Ecosystem: domain.EcoNpm, Name: "@scope/pkg", Version: "1.0.0", Direct: true},
		},
	}
	doc := BuildSPDX(snap, SPDXOptions{AegisVersion: "v0.0.0-test"})
	for _, p := range doc.Packages {
		for _, c := range p.SPDXID {
			valid := c == '-' || c == '.' ||
				(c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9')
			if !valid {
				t.Fatalf("invalid char %q in SPDXID %q", c, p.SPDXID)
			}
		}
	}
}
