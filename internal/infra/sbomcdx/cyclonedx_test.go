package sbomcdx

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/qwexvf/aegis-cli/internal/domain"
)

func TestBuild_BasicShape(t *testing.T) {
	sum := sha512.Sum512([]byte("hello"))
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
	snap := domain.Snapshot{
		AegisVersion: "v0.0.0-test",
		Project:      "demo",
		Deps: []domain.Dependency{
			{
				Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21",
				Direct:    true,
				Integrity: integrity,
			},
			{Ecosystem: domain.EcoPyPI, Name: "requests", Version: "2.31.0", Direct: false},
		},
	}
	bom := Build(snap, Options{
		AegisVersion: "v0.0.0-test",
		Timestamp:    time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC),
		SerialNumber: "urn:uuid:00000000-0000-0000-0000-000000000001",
	})

	if bom.BOMFormat != "CycloneDX" {
		t.Fatalf("BOMFormat: %s", bom.BOMFormat)
	}
	if bom.SpecVersion != cdx.SpecVersion1_5 {
		t.Fatalf("SpecVersion: %v", bom.SpecVersion)
	}
	if bom.SerialNumber != "urn:uuid:00000000-0000-0000-0000-000000000001" {
		t.Fatalf("SerialNumber not pinned: %s", bom.SerialNumber)
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil || bom.Metadata.Component.Name != "demo" {
		t.Fatalf("metadata.component.name not set")
	}
	if bom.Components == nil || len(*bom.Components) != 2 {
		t.Fatalf("expected 2 components, got %v", bom.Components)
	}
	got := (*bom.Components)[0]
	if got.PackageURL != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("purl: %s", got.PackageURL)
	}
	if got.Scope != cdx.ScopeRequired {
		t.Fatalf("direct dep should be scope=required, got %s", got.Scope)
	}
	if (*bom.Components)[1].Scope != cdx.ScopeOptional {
		t.Fatalf("transitive dep should be scope=optional")
	}
	if got.Hashes == nil || len(*got.Hashes) != 1 || (*got.Hashes)[0].Algorithm != cdx.HashAlgoSHA512 {
		t.Fatalf("expected SHA-512 hash on lodash, got %v", got.Hashes)
	}
}

func TestBuild_EncodesToJSON15(t *testing.T) {
	snap := domain.Snapshot{
		Deps: []domain.Dependency{
			{Ecosystem: domain.EcoNpm, Name: "x", Version: "1.0.0", Direct: true},
		},
	}
	bom := Build(snap, Options{AegisVersion: "v0.0.0-test"})
	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	if err := enc.EncodeVersion(bom, cdx.SpecVersion1_5); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not valid json: %v\n%s", err, buf.String())
	}
	if got["specVersion"] != "1.5" {
		t.Fatalf("specVersion: %v", got["specVersion"])
	}
}

func TestBuild_VulnerabilitiesIncluded(t *testing.T) {
	snap := domain.Snapshot{
		Deps: []domain.Dependency{
			{
				Ecosystem: domain.EcoNpm, Name: "x", Version: "1.0.0", Direct: true,
				Advisories: []domain.Advisory{{
					ID: "GHSA-test", Severity: domain.SevHigh, Summary: "demo", URL: "https://x", Source: "osv",
				}},
			},
		},
	}
	bom := Build(snap, Options{AegisVersion: "test", IncludeVulnerabilities: true})
	if bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability")
	}
	v := (*bom.Vulnerabilities)[0]
	if v.ID != "GHSA-test" {
		t.Fatalf("id: %s", v.ID)
	}
	if v.Affects == nil || len(*v.Affects) != 1 || (*v.Affects)[0].Ref != "pkg:npm/x@1.0.0" {
		t.Fatalf("affects ref: %+v", v.Affects)
	}
	if v.Ratings == nil || (*v.Ratings)[0].Severity != cdx.SeverityHigh {
		t.Fatalf("severity not mapped: %+v", v.Ratings)
	}
}

func TestBuild_VulnerabilitiesOmittedByDefault(t *testing.T) {
	snap := domain.Snapshot{
		Deps: []domain.Dependency{
			{
				Ecosystem: domain.EcoNpm, Name: "x", Version: "1", Direct: true,
				Advisories: []domain.Advisory{{ID: "X"}},
			},
		},
	}
	bom := Build(snap, Options{AegisVersion: "test"})
	if bom.Vulnerabilities != nil {
		t.Fatalf("vulnerabilities should be nil when IncludeVulnerabilities=false")
	}
}

func TestHashFromIntegrity_OversizeRejected(t *testing.T) {
	// 700-byte b64 payload would decode to ~525 bytes; well under any
	// real SRI hash. Cap should reject pre-decode so we never allocate.
	huge := "sha512-" + strings.Repeat("A", 700)
	if got := hashFromIntegrity(huge); got != nil {
		t.Fatalf("oversize integrity must return nil, got %+v", got)
	}
}

func TestHashFromIntegrity(t *testing.T) {
	if got := hashFromIntegrity(""); got != nil {
		t.Fatalf("empty integrity should yield nil")
	}
	if got := hashFromIntegrity("notahash"); got != nil {
		t.Fatalf("malformed integrity should yield nil")
	}
	if got := hashFromIntegrity("md5-aGVsbG8="); got != nil {
		t.Fatalf("unknown algo should yield nil")
	}
	// "hello" base64-encoded under a recognised algo prefix; we only
	// check the algorithm + non-empty content here, not the hex value.
	h := hashFromIntegrity("sha256-aGVsbG8=")
	if h == nil || h.Algorithm != cdx.HashAlgoSHA256 || h.Value == "" {
		t.Fatalf("expected SHA-256 hash with hex value, got %+v", h)
	}
}
