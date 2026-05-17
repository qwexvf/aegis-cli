package image

import (
	"archive/tar"
	"bytes"
	"path/filepath"
	"testing"
)

func BenchmarkOverlayLayers_Tiny(b *testing.B) {
	files := map[string][]byte{
		"app/package-lock.json": []byte(`{"name":"x","lockfileVersion":3,"packages":{}}`),
	}
	tarball := buildTarBytes(b, files)
	for b.Loop() {
		_, _, _ = overlayLayersFull([]v1Layer{&fakeLayer{entries: tarballToEntries(tarball)}}, ScanOpts{}, defaultLockfileNames())
	}
}

func BenchmarkOverlayLayers_1000Files(b *testing.B) {
	files := make(map[string][]byte, 1000)
	for i := range 1000 {
		files[filepath.Join("app", "p", string(rune('a'+i%26)), "src", "f.js")] = []byte("var x = 1;\n")
	}
	files["app/package-lock.json"] = []byte(`{"name":"x","lockfileVersion":3,"packages":{}}`)
	tarball := buildTarBytes(b, files)
	b.ReportAllocs()
	for b.Loop() {
		_, _, _ = overlayLayersFull([]v1Layer{&fakeLayer{entries: tarballToEntries(tarball)}}, ScanOpts{CapturePackageSources: true}, defaultLockfileNames())
	}
}

func buildTarBytes(b *testing.B, files map[string][]byte) []byte {
	b.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(body)
	}
	_ = tw.Close()
	return buf.Bytes()
}

func tarballToEntries(raw []byte) []tarEntry {
	tr := tar.NewReader(bytes.NewReader(raw))
	var out []tarEntry
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		body := make([]byte, hdr.Size)
		_, _ = tr.Read(body)
		out = append(out, tarEntry{name: hdr.Name, body: body, typeflag: hdr.Typeflag})
	}
	return out
}
