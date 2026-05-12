package domain

// MaintainerSignal bundles the registry-side metadata that the
// maintainer-hijack heuristic needs to score a (name, version):
//
//   - When was THIS version published?
//   - When was the PREVIOUS version published?  (long gap = abandonment-then-handover)
//   - How many people use this package?         (small = easier hijack target)
//
// Lives in domain because both usecase (the orchestrator) and
// the heuristics adapter need to share the shape; defining it in an
// infra adapter would mean usecase importing infra. Empty fields are
// the "unknown" sentinel — heuristic degrades gracefully when the
// registry response was incomplete.
//
// Adapter: infra/npmregistry. The adapter returns its own struct
// today and the use case translates; future ecosystems (PyPI,
// crates.io) plug into the same shape via their own fetchers.
type MaintainerSignal struct {
	// PublishedAt is the registry-reported publish time of the
	// queried version, in RFC3339. Empty when the registry doesn't
	// expose it.
	PublishedAt string

	// WeeklyDownloads is the package's last-week download count.
	// Zero means "unknown" (lookup failed / scoped package without
	// public stats), NOT "no users". The heuristic treats zero as
	// "no signal", not "low downloads".
	WeeklyDownloads int64

	// PreviousVersion is the most-recent version BEFORE PublishedAt.
	// Empty when this is the first publish.
	PreviousVersion string

	// PreviousPublishedAt is RFC3339 of PreviousVersion's publish.
	// Pair with PublishedAt to compute the gap (in days).
	PreviousPublishedAt string

	// Publisher is the npm user who pushed the queried version
	// (registry's per-version _npmUser.name). Empty when the
	// registry didn't expose it. Used by the maintainer-transfer
	// heuristic to spot the canonical compromise shape:
	// event-stream@3.3.5 was published by `dominictarr`, but
	// event-stream@3.3.6 by `right9ctrl`. A changed publisher on a
	// long-lived package is a high-precision signal.
	Publisher string

	// PreviousPublisher is the npm user who pushed PreviousVersion.
	// Empty when PreviousVersion is empty or the registry didn't
	// expose the field. Compare against Publisher to detect a
	// maintainer transfer between consecutive releases.
	PreviousPublisher string

	// VersionUnpublished is true when the registry's time map contains
	// an entry for the queried version (proving it was published) but
	// the versions map does not (proving it was subsequently yanked).
	// npm removes versions only under its security policy — a lockfile
	// pinning a yanked version means the package was installed during
	// an active or resolved incident window.
	VersionUnpublished bool
}
