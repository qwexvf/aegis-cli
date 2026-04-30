package domain

// Evidence is one capture's location + snippet — the per-match
// detail behind a Capability flag. Produced by per-language scanners
// when the use case asks for it (today: only `aegis snapshot submit`)
// and posted to the API verbatim. The API builds graphs from these
// records; the local risk engine doesn't need them.
type Evidence struct {
	Capability Capability
	File       string // path within the package source tree
	Line       int    // 1-based line number
	Snippet    string // truncated, single-line source excerpt
}
