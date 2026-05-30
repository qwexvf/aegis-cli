package licensefetch

import (
	"context"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

// With all clients nil, every supported ecosystem degrades to ("", nil)
// rather than panicking on a nil receiver.
func TestFetchLicense_NilClientsDegrade(t *testing.T) {
	f := New(nil, nil, nil, nil, nil)
	ecos := []domain.Ecosystem{
		domain.EcoNpm, domain.EcoPyPI, domain.EcoCrates,
		domain.EcoRubyGems, domain.EcoNuGet,
	}
	for _, eco := range ecos {
		lic, err := f.FetchLicense(context.Background(), eco, "pkg", "1.0.0")
		if err != nil {
			t.Errorf("%v: unexpected error %v", eco, err)
		}
		if lic != "" {
			t.Errorf("%v: license = %q, want empty", eco, lic)
		}
	}
}

// Ecosystems with no configured client (Go, Maven, CRAN, Hex, Pub,
// CocoaPods, ...) hit the default arm and return "" without error.
func TestFetchLicense_UnsupportedEcosystem(t *testing.T) {
	f := New(nil, nil, nil, nil, nil)
	for _, eco := range []domain.Ecosystem{
		domain.EcoGo, domain.EcoMaven, domain.EcoCRAN,
		domain.EcoHackage, domain.EcoCPAN, domain.EcoCocoaPods,
		domain.EcoGleam, domain.EcoPub, domain.EcoSwiftPM,
	} {
		lic, err := f.FetchLicense(context.Background(), eco, "pkg", "1.0.0")
		if err != nil {
			t.Errorf("%v: unexpected error %v", eco, err)
		}
		if lic != "" {
			t.Errorf("%v: license = %q, want empty", eco, lic)
		}
	}
}
