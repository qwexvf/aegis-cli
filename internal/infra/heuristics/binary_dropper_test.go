package heuristics

import (
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

func TestDetectBinaryDropper(t *testing.T) {
	tests := []struct {
		name  string
		eco   domain.Ecosystem
		files map[string][]byte
		want  domain.Capability
	}{
		{
			name:  ".exe in npm package",
			eco:   domain.EcoNpm,
			files: map[string][]byte{"package.json": {}, "tools/install.exe": {}},
			want:  domain.CapBinaryDropper,
		},
		{
			name:  ".dll in npm package",
			eco:   domain.EcoNpm,
			files: map[string][]byte{"native.dll": {}, "index.js": {}},
			want:  domain.CapBinaryDropper,
		},
		{
			name:  ".ps1 (PowerShell) in npm package",
			eco:   domain.EcoNpm,
			files: map[string][]byte{"setup.ps1": {}, "index.js": {}},
			want:  domain.CapBinaryDropper,
		},
		{
			name:  "AppleScript in npm package",
			eco:   domain.EcoNpm,
			files: map[string][]byte{"helper.scpt": {}, "index.js": {}},
			want:  domain.CapBinaryDropper,
		},
		{
			name:  "case-insensitive (.EXE)",
			eco:   domain.EcoNpm,
			files: map[string][]byte{"x.EXE": {}},
			want:  domain.CapBinaryDropper,
		},
		{
			name:  "pure JS package — no signal",
			eco:   domain.EcoNpm,
			files: map[string][]byte{"index.js": {}, "package.json": {}, "README.md": {}},
			want:  0,
		},
		{
			name:  "non-npm ecosystem — heuristic doesn't apply (Python wheels legit ship .so)",
			eco:   domain.EcoPyPI,
			files: map[string][]byte{"native.so": {}},
			want:  0,
		},
		{
			name:  "empty source",
			eco:   domain.EcoNpm,
			files: nil,
			want:  0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectBinaryDropper(tc.eco, usecase.PackageSource{Files: tc.files})
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
