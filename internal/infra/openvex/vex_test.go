package openvex

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFile_ParsesOpenVEX(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "doc.vex")
	body := `{
	  "@context": "https://openvex.dev/ns/v0.2.0",
	  "@id": "https://example.com/vex/example-2024-001",
	  "author": "test",
	  "timestamp": "2026-05-16T00:00:00Z",
	  "version": 1,
	  "statements": [
	    {
	      "vulnerability": {"name": "CVE-2024-1234"},
	      "products": [{"@id": "pkg:npm/lodash@4.17.21"}],
	      "status": "not_affected",
	      "justification": "vulnerable_code_not_present"
	    }
	  ]
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	doc, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("statements = %d, want 1", len(doc.Statements))
	}
	s := doc.Statements[0]
	if s.Status != StatusNotAffected {
		t.Errorf("status = %q, want %q", s.Status, StatusNotAffected)
	}
	if s.Vulnerability.ID != "CVE-2024-1234" {
		t.Errorf("vuln id = %q", s.Vulnerability.ID)
	}
}

func TestLoadFile_MissingFile(t *testing.T) {
	_, err := LoadFile("/nonexistent/path/to/vex.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.vex")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestSuppressedAdvisories_ExtractsIDsAndAliases(t *testing.T) {
	doc := &Document{
		Statements: []Statement{
			{
				Status: StatusNotAffected,
				Vulnerability: Vulnerability{
					ID:      "CVE-2024-1",
					Aliases: []string{"GHSA-aaaa", "OSV-1"},
				},
			},
			{
				Status: StatusAffected, // should NOT be in set
				Vulnerability: Vulnerability{
					ID: "CVE-2024-2",
				},
			},
			{
				Status: StatusNotAffected,
				Vulnerability: Vulnerability{
					AtID: "https://osv.dev/GHSA-bbbb-cccc-dddd",
				},
			},
		},
	}
	set := SuppressedAdvisories(doc)

	mustHave := []string{"CVE-2024-1", "GHSA-AAAA", "OSV-1", "GHSA-BBBB-CCCC-DDDD"}
	for _, id := range mustHave {
		if _, ok := set[id]; !ok {
			t.Errorf("expected %q in suppressed set", id)
		}
	}
	if _, ok := set["CVE-2024-2"]; ok {
		t.Errorf("affected status should NOT add to suppressed set")
	}
}

func TestSuppressedAdvisories_NilDocument(t *testing.T) {
	if set := SuppressedAdvisories(nil); len(set) != 0 {
		t.Errorf("nil doc returned %d entries, want 0", len(set))
	}
}

func TestSuppressedAdvisories_CaseInsensitive(t *testing.T) {
	doc := &Document{
		Statements: []Statement{{
			Status:        StatusNotAffected,
			Vulnerability: Vulnerability{ID: "cve-2024-lower"},
		}},
	}
	set := SuppressedAdvisories(doc)
	if _, ok := set["CVE-2024-LOWER"]; !ok {
		t.Errorf("expected case-folded entry in suppressed set; got keys: %v", set)
	}
}

func TestIDFromAtID(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"https://osv.dev/GHSA-x-y-z", "GHSA-x-y-z"},
		{"GHSA-bare", "GHSA-bare"},
		{"CVE-2024-1", "CVE-2024-1"},
	}
	for _, tt := range tests {
		if got := idFromAtID(tt.in); got != tt.want {
			t.Errorf("idFromAtID(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
