package domain

// PackageSource is the extracted content of a published package distribution.
// Passed from the registry fetcher through heuristics and AST scanning.
//
// TarballSha256 is the hex sha256 of the raw distribution tarball (npm: .tgz).
// Empty when the source didn't come from a tarball (cache reload, ecosystems
// without tarballs). The submit pipeline uses it for provenance verification.
type PackageSource struct {
	Files         map[string][]byte
	Manifest      []byte
	TarballSha256 string
}
