package main

import (
	"github.com/qwexvf/aegis-cli/internal/domain"
	imagescan "github.com/qwexvf/aegis-cli/internal/infra/scan/image"
	"github.com/qwexvf/aegis-cli/internal/usecase"
)

// imageScannerAdapter bridges the infra image.Scanner to the
// usecase.ImageScanner port. The two types live in different layers
// to keep the use case independent of go-containerregistry; the
// adapter is the only file that knows both.
type imageScannerAdapter struct {
	inner *imagescan.Scanner
}

func (a imageScannerAdapter) ScanImage(path string) ([]domain.Dependency, error) {
	return a.inner.ScanImage(path)
}

func (a imageScannerAdapter) ScanImagePackages(path string, opts usecase.ImageScanOpts) (usecase.ImagePackageSet, error) {
	res, err := a.inner.ScanImagePackages(path, imagescan.ScanOpts{
		CapturePackageSources: opts.CapturePackageSources,
	})
	if err != nil {
		return usecase.ImagePackageSet{}, err
	}
	return usecase.ImagePackageSet{
		Deps:    res.Deps,
		Sources: res.Sources,
	}, nil
}
