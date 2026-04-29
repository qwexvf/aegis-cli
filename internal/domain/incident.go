package domain

// Incident is the documented historical context for a Decision. It's
// optional — a decision can stand on its own (e.g. heuristic block)
// without naming a specific incident — but when present it lets the
// presenter show advisory IDs and references that make a buyer say
// "OK that's a real attack."
type Incident struct {
	AdvisoryID string   // e.g. "GHSA-pjwm-rvh2-c87w"
	Date       string   // "2021-10"
	Summary    string   // 1-line plain-English description
	References []string // URLs to advisories, postmortems, etc.
}
