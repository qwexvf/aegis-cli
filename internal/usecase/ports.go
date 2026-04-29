// Package usecase orchestrates the install gate. It depends on domain
// types and a small set of port interfaces (defined here). All concrete
// I/O lives in internal/infra/.
package usecase

import (
	"context"

	"github.com/qwexvf/aegis/services/cli/internal/domain"
)

// VersionResolver turns a range/tag into a concrete version.
// Implementation: infra/npmregistry.
type VersionResolver interface {
	Resolve(ctx context.Context, eco domain.Ecosystem, name, rangeOrTag string) (string, error)
}

// DecisionChecker asks the Aegis API what to do about (eco, name, version).
// Implementation: infra/aegisapi.
type DecisionChecker interface {
	Check(ctx context.Context, eco domain.Ecosystem, name, version string) (domain.Decision, error)
}

// DecisionCache is a local store for decisions keyed by ecosystem+name+version.
// Implementation: infra/diskcache.
type DecisionCache interface {
	Get(key string) (domain.Decision, bool)
	Put(key string, d domain.Decision) error
}

// CacheKey builds the canonical cache key. Lives in usecase (not infra)
// so every adapter agrees on the format.
func CacheKey(eco domain.Ecosystem, name, version string) string {
	return string(eco) + "/" + name + "@" + version
}

// AuditWriter persists one outcome row. Best-effort; failures must not
// abort the install. Implementation: infra/ndjsonaudit.
type AuditWriter interface {
	Write(o domain.Outcome) error
}

// ConfirmResult reports a human's answer to a yes/no prompt.
type ConfirmResult int

const (
	ConfirmDeny        ConfirmResult = iota // explicit no
	ConfirmAllow                            // explicit yes
	ConfirmUnavailable                      // no TTY / cannot prompt
)

// Confirmer asks the human one yes/no question. Implementation:
// infra/ttyprompt.
type Confirmer interface {
	Confirm(question string) ConfirmResult
}

// EnvProbe surfaces runtime context that affects policy: CI mode,
// override flag, override reason. Implementation: infra/envprobe.
type EnvProbe interface {
	IsCI() bool
	Override() (allow bool, reason string)
}

// Presenter renders progress and results to the user. The use case
// never formats strings itself — it calls these methods at well-defined
// points so the presenter (or a test fake) can choose what to show.
type Presenter interface {
	OnResolveStart(spec domain.PackageSpec, resolved string, fromCache bool)
	OnResolveError(spec domain.PackageSpec, err error)
	OnSkipped(spec domain.PackageSpec)
	OnDecision(d domain.Decision)
	OnOutcome(o domain.Outcome, pmName, installVerb string)
	OnAPIError(spec domain.PackageSpec, version string, err error)
	OnInfo(message string) // generic line, e.g. "AEGIS_OVERRIDE_REASON required"
}
