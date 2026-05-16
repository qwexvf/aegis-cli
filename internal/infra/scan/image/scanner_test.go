package image

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// fakeLayer is an in-memory v1Layer for tests. Constructs a synthetic
// uncompressed tar stream from a map of path → bytes (or whiteouts).
type fakeLayer struct {
	entries []tarEntry
}

type tarEntry struct {
	name     string
	body     []byte
	typeflag byte
}

func (l *fakeLayer) Uncompressed() (io.ReadCloser, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range l.entries {
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     0o644,
			Size:     int64(len(e.body)),
			Typeflag: e.typeflag,
		}
		if hdr.Typeflag == 0 {
			hdr.Typeflag = tar.TypeReg
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.body); err != nil {
			return nil, err
		}
	}
	_ = tw.Close()
	return io.NopCloser(&buf), nil
}

func TestOverlayLayers_AddsFiles(t *testing.T) {
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: []byte(`{"name":"x"}`)},
		}},
	}
	files, err := overlayLayers(layers)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["app/package-lock.json"]; !ok {
		t.Errorf("expected app/package-lock.json in overlay, got %v", keys(files))
	}
}

func TestOverlayLayers_LaterLayerOverwrites(t *testing.T) {
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: []byte(`{"v":1}`)},
		}},
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: []byte(`{"v":2}`)},
		}},
	}
	files, _ := overlayLayers(layers)
	if string(files["app/package-lock.json"]) != `{"v":2}` {
		t.Errorf("later layer should win; got %q", files["app/package-lock.json"])
	}
}

func TestOverlayLayers_FileWhiteoutRemoves(t *testing.T) {
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: []byte(`{"v":1}`)},
		}},
		&fakeLayer{entries: []tarEntry{
			{name: "app/.wh.package-lock.json", body: nil},
		}},
	}
	files, _ := overlayLayers(layers)
	if _, ok := files["app/package-lock.json"]; ok {
		t.Errorf("whiteout should remove file; still present: %v", keys(files))
	}
}

func TestOverlayLayers_OpaqueDirWhiteoutClearsSubtree(t *testing.T) {
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: []byte(`{}`)},
			{name: "app/sub/Gemfile.lock", body: []byte(`Gemfile`)},
			{name: "other/package-lock.json", body: []byte(`other`)},
		}},
		&fakeLayer{entries: []tarEntry{
			{name: "app/.wh..wh..opq", body: nil},
		}},
	}
	files, _ := overlayLayers(layers)
	if _, ok := files["app/package-lock.json"]; ok {
		t.Errorf("opaque whiteout should clear app/*; got %v", keys(files))
	}
	if _, ok := files["app/sub/Gemfile.lock"]; ok {
		t.Errorf("opaque whiteout should clear app/sub/*; got %v", keys(files))
	}
	if _, ok := files["other/package-lock.json"]; !ok {
		t.Errorf("opaque whiteout on app/ should NOT clear other/; got %v", keys(files))
	}
}

func TestOverlayLayers_ReintroductionAfterWhiteout(t *testing.T) {
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: []byte(`old`)},
		}},
		&fakeLayer{entries: []tarEntry{
			{name: "app/.wh.package-lock.json", body: nil},
		}},
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: []byte(`new`)},
		}},
	}
	files, _ := overlayLayers(layers)
	if string(files["app/package-lock.json"]) != "new" {
		t.Errorf("re-introduced file should win; got %q", files["app/package-lock.json"])
	}
}

func TestOverlayLayers_IgnoresNonCandidateFiles(t *testing.T) {
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "etc/hostname", body: []byte(`host`)},
			{name: "var/log/syslog", body: bytes.Repeat([]byte("x"), 10*1024*1024)},
			{name: "app/package-lock.json", body: []byte(`{}`)},
		}},
	}
	files, _ := overlayLayers(layers)
	if len(files) != 1 {
		t.Errorf("only registered lockfile should be captured; got %v", keys(files))
	}
}

func TestOverlayLayers_FileSizeCap(t *testing.T) {
	// 5 MB file — should be truncated to maxFileBytes (4 MB).
	big := bytes.Repeat([]byte("x"), 5*1024*1024)
	layers := []v1Layer{
		&fakeLayer{entries: []tarEntry{
			{name: "app/package-lock.json", body: big},
		}},
	}
	files, _ := overlayLayers(layers)
	body := files["app/package-lock.json"]
	if len(body) > maxFileBytes {
		t.Errorf("file size cap not enforced: got %d bytes, cap %d", len(body), maxFileBytes)
	}
}

func TestDedupSort_RemovesDuplicates(t *testing.T) {
	// Two layers both containing the same lockfile (e.g. multi-stage
	// build re-running `npm ci`) shouldn't double-count.
	deps := []domain.Dependency{
		{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21"},
		{Ecosystem: domain.EcoNpm, Name: "lodash", Version: "4.17.21"},
		{Ecosystem: domain.EcoNpm, Name: "axios", Version: "1.0.0"},
	}
	out := dedupSort(deps)
	if len(out) != 2 {
		t.Errorf("expected 2 unique deps after dedup, got %d", len(out))
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
