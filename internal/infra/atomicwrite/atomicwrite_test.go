package atomicwrite

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")
	want := []byte(`{"k":"v"}`)

	if err := WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	// Permission check is best-effort; umask can mask bits on some setups.
	if info.Mode().Perm()&0o600 != 0o600 {
		t.Fatalf("perm: got %v, want at least 0o600", info.Mode().Perm())
	}
}

func TestWriteFile_NoTempLeaks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.json")
	if err := WriteFile(path, []byte("ok"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "x.json" {
			t.Fatalf("unexpected entry: %s (temp file leaked?)", e.Name())
		}
	}
}

func TestWriteFileFunc_StreamingError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "y.json")
	wantErr := errors.New("stream boom")

	err := WriteFileFunc(path, 0o600, func(w io.Writer) error { return wantErr })
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped %v, got %v", wantErr, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("destination should not exist after streaming error")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		t.Fatalf("temp file leaked after error: %s", e.Name())
	}
}

func TestWriteFile_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "z.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := WriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Fatalf("got %q, want %q", got, "new")
	}
}

func TestWriteFile_MissingDir(t *testing.T) {
	dir := t.TempDir()
	// Subdir does not exist — caller is responsible for MkdirAll.
	path := filepath.Join(dir, "missing", "z.json")
	err := WriteFile(path, []byte("x"), 0o600)
	if err == nil {
		t.Fatal("expected error when parent dir is missing")
	}
}
