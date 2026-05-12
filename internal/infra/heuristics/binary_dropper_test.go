package heuristics

import (
	"slices"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

func TestDetectBinaryDropper(t *testing.T) {
	tests := []struct {
		name  string
		eco   domain.Ecosystem
		files map[string][]byte
		want  domain.Capability // 0 means no capability expected
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
		// --- PyPI carve-outs (Plan I) ---
		{
			name:  "pypi: cpython ABI-tagged .so — legitimate C extension",
			eco:   domain.EcoPyPI,
			files: map[string][]byte{"pillow/_imaging.cpython-310-x86_64-linux-gnu.so": {}},
			want:  0,
		},
		{
			name:  "pypi: abi3.so — legitimate stable-ABI extension",
			eco:   domain.EcoPyPI,
			files: map[string][]byte{"cryptography/_rust.abi3.so": {}},
			want:  0,
		},
		{
			name:  "pypi: .pyd (Windows extension) — legitimate",
			eco:   domain.EcoPyPI,
			files: map[string][]byte{"numpy/_core.pyd": {}},
			want:  0,
		},
		{
			name:  "pypi: bundled libs in .libs/ (auditwheel) — legitimate",
			eco:   domain.EcoPyPI,
			files: map[string][]byte{"numpy/.libs/libopenblas.so.0": {}},
			want:  0,
		},
		{
			name:  "pypi: .so OUTSIDE expected paths — flag",
			eco:   domain.EcoPyPI,
			files: map[string][]byte{"ultralytics/data/.cache/xmrig.so": {}},
			want:  domain.CapBinaryDropper,
		},
		{
			name:  "pypi: .exe in package — flag (no legitimate carve-out)",
			eco:   domain.EcoPyPI,
			files: map[string][]byte{"pkg/payload.exe": {}},
			want:  domain.CapBinaryDropper,
		},

		// --- crates.io rules (Plan J) ---
		{
			name:  "crates: .so in crate — flag (no legitimate shape)",
			eco:   domain.EcoCrates,
			files: map[string][]byte{"native/payload.so": {}},
			want:  domain.CapBinaryDropper,
		},
		{
			name:  "crates: .dll in crate — flag",
			eco:   domain.EcoCrates,
			files: map[string][]byte{"vendor/win.dll": {}},
			want:  domain.CapBinaryDropper,
		},
		{
			name:  "crates: pure rust source — no signal",
			eco:   domain.EcoCrates,
			files: map[string][]byte{"src/lib.rs": {}, "Cargo.toml": {}},
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
			src := usecase.PackageSource{Files: tc.files}
			pkg := NormalizedPackage{Eco: tc.eco, Files: src.Files}
			got := checkBinaryDropper(pkg)
			if tc.want == 0 {
				if len(got) != 0 {
					t.Errorf("got %v, want []", got)
				}
			} else {
				if !slices.Contains(got, tc.want) {
					t.Errorf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}
