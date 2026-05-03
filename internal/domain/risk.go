package domain

// Risk scoring is a deliberately simple weighted-sum heuristic. We
// chose this over ML / rule-engines for three reasons:
//
//   1. Output is explainable: every flag has a name and a number.
//   2. Tunable in code review (one constant per signal).
//   3. Testable as pure functions (this file has zero I/O).
//
// Two scores feed the final Verdict:
//
//   RiskScore(fp)              — "how dangerous is this version on its own?"
//   DriftScore(prev, next)     — "how much did the danger profile change?"
//
// Both are 0..∞ but typical values land in 0..150. Verdict bucketizes.

// --- per-Capability weights ------------------------------------------
//
// Constants are exported so risk reports / docs / future config can
// reference them by name. Numbers are deliberately round; tune as
// signal quality improves.

const (
	WeightInstallHook    = 30 // postinstall / setup.py / build.rs declared
	WeightShellSpawn     = 20 // child_process.exec, subprocess.run, etc.
	WeightDynamicEval    = 25 // eval, new Function, exec/compile()
	WeightBase64Decode   = 20 // obfuscation primitive (esp. with eval/spawn)
	WeightNetEgress      = 10 // outbound network (low — many libs do this)
	WeightEnvCredRead    = 25 // process.env reads of credential-shaped names
	WeightFSWrite        = 15 // fs writes outside package root
	WeightRawIPLiteral   = 15 // string literal with raw-IP URL
	WeightSizeAnomaly    = 5  // suspicious source-size delta (drift only)
	WeightHookContent    = 30 // hook script content sha256 changed (drift only)
	WeightCapabilityAdd  = 15 // each new capability since previous version
	WeightMaintainerSwap = 30 // (later) maintainer change between versions

	// --- v0.4 heuristic weights (high signal — these patterns are
	// strongly correlated with malware in observed npm incidents) ---

	// WeightInstallHookSuspicious is intentionally large enough that
	// any package combining a postinstall hook with `curl|sh` or
	// `node -e` style content crosses the Block threshold on its own.
	// Every documented ua-parser-js / event-stream / coa attack used
	// exactly this pattern.
	WeightInstallHookSuspicious = 70
	// WeightObfuscatedPayload — eval(atob(...)) and friends. Benign
	// code essentially never does this; when it does, the user wants
	// to be told.
	WeightObfuscatedPayload = 60
	// WeightSuspiciousURL — Pastebin / Discord webhook / ngrok /
	// Telegram bot / IDN homoglyph in source. These are the C2
	// callback patterns. Hard to imagine a legitimate use.
	WeightSuspiciousURL = 50
	// WeightBinaryDropper — npm package containing .exe/.dll/.so/etc.
	// Some legitimate packages do this (esbuild ships native bins),
	// so the weight is moderate — pair with allowlist for known
	// good toolchains.
	WeightBinaryDropper = 35
	// WeightTyposquatRisk — name within edit distance 2 of a top-1000
	// package. Confidence is heuristic, not certain; the weight pushes
	// to Prompt rather than Block by itself.
	WeightTyposquatRisk = 40
)

// credentialEnvVarRoots is the list of env var name prefixes that, when
// read by package code, lift CapEnvRead from "boring" to "credential
// theft pattern". Order/case sensitive — names are matched case-insensitively.
var credentialEnvVarRoots = []string{
	"AWS_", "AZURE_", "GOOGLE_", "GCP_",
	"NPM_TOKEN", "NPM_AUTH",
	"GITHUB_TOKEN", "GH_TOKEN",
	"DOCKER_AUTH", "DOCKERHUB_",
	"DATABASE_URL", "DB_PASS", "POSTGRES_", "MYSQL_",
	"PRIVATE_KEY", "SSH_",
	"STRIPE_", "TWILIO_", "SENDGRID_",
	"CIRCLE_TOKEN", "GITLAB_TOKEN",
}

// RiskFlag is one explainable contribution to a score. Presenter
// renders these alongside the total so the user sees *why* a version
// got blocked.
//
// Suppressed flags are kept in the assessment (so the user sees what
// was found) but their Weight is removed from the aggregate Score
// when the rule applies — see RiskAssessment.ApplyAllowlist.
type RiskFlag struct {
	Code   string // stable identifier ("shell-spawn", "install-hook", ...)
	Detail string // human-readable explanation
	Weight int    // numeric contribution to the score (0 if Suppressed)

	// Suppressed is true when an allowlist rule excused this flag.
	// The flag is still rendered (transparency: users see what was
	// found) but its Weight no longer contributes to Score.
	Suppressed bool
	// SuppressBy is the AllowRule.Reason from the matching rule.
	// Empty when Suppressed is false.
	SuppressBy string
}

// RiskAssessment bundles a Fingerprint's score with the flags that
// produced it. Both RiskScore and DriftScore return this shape.
type RiskAssessment struct {
	Score int
	Flags []RiskFlag
}

// RiskScore evaluates a Fingerprint in isolation. Pure function — no
// I/O, no time, no env. Empty / unanalyzed fingerprints return zero.
func RiskScore(fp *Fingerprint) RiskAssessment {
	if fp == nil || !fp.Analyzed {
		return RiskAssessment{}
	}

	var ra RiskAssessment

	add := func(code, detail string, weight int) {
		ra.Score += weight
		ra.Flags = append(ra.Flags, RiskFlag{Code: code, Detail: detail, Weight: weight})
	}

	// Install hooks first — these are the highest-leverage signal in
	// supply-chain attacks (every published payload runs through one).
	if len(fp.Hooks) > 0 {
		for _, h := range fp.Hooks {
			add("install-hook",
				"declares "+h.Phase.String()+" hook ("+h.Source+")",
				WeightInstallHook)
		}
	}

	// Capabilities: each turns into one flag.
	for _, c := range fp.Capabilities {
		switch c {
		case CapShellSpawn:
			add(c.String(), "spawns subprocess (shell/exec/spawn)", WeightShellSpawn)
		case CapDynamicEval:
			add(c.String(), "constructs and runs code dynamically (eval/Function)", WeightDynamicEval)
		case CapBase64Decode:
			add(c.String(), "decodes base64 at runtime", WeightBase64Decode)
		case CapNetEgress:
			add(c.String(), "opens outbound network connection", WeightNetEgress)
		case CapFSWriteOutsideRoot:
			add(c.String(), "writes to filesystem outside its install root", WeightFSWrite)
		case CapRawIPLiteral:
			add(c.String(), "embeds raw IP address in a URL", WeightRawIPLiteral)
		case CapEnvRead:
			// Special-case: only flag when env names look credential-shaped.
			if names := credentialLikeEnvReads(fp.EnvReads); len(names) > 0 {
				add("env-cred-read",
					"reads credential-shaped env vars: "+joinNames(names, 5),
					WeightEnvCredRead)
			}
		case CapInstallHookExec:
			// Already accounted for via Hooks above; skip to avoid double-counting.
		case CapInstallHookSuspicious:
			add(c.String(),
				"install hook downloads-and-executes (curl|sh / wget|bash / node -e / base64|sh)",
				WeightInstallHookSuspicious)
		case CapObfuscatedPayload:
			add(c.String(),
				"decodes-then-executes (eval(atob(...)) / Function(decode(...)))",
				WeightObfuscatedPayload)
		case CapSuspiciousURL:
			add(c.String(),
				"string literal points at a paste / chat-relay / tunnel host",
				WeightSuspiciousURL)
		case CapBinaryDropper:
			add(c.String(),
				"package ships an executable file (.exe/.dll/.so/.scpt) — unusual for a JS dep",
				WeightBinaryDropper)
		case CapTyposquatRisk:
			add(c.String(),
				"name is within edit distance 2 of a top-1000 package",
				WeightTyposquatRisk)
		}
	}

	return ra
}

// DriftScore evaluates how much the *new* version's behavioral profile
// differs from the *prev* version. Captures the "behavioral diff"
// product narrative: a clean v_old that suddenly grows install hooks +
// new capabilities in v_new is the strongest possible compromise
// signal short of an actual incident-DB hit.
//
// Both fingerprints must be Analyzed. If either is missing or empty,
// returns zero (we can't reason about drift).
func DriftScore(prev, next *Fingerprint) RiskAssessment {
	if prev == nil || next == nil || !prev.Analyzed || !next.Analyzed {
		return RiskAssessment{}
	}

	var ra RiskAssessment
	add := func(code, detail string, weight int) {
		ra.Score += weight
		ra.Flags = append(ra.Flags, RiskFlag{Code: code, Detail: detail, Weight: weight})
	}

	// 1. Install hooks: addition of a hook is alarming. Content change
	// of an existing hook is also alarming (new payload swapped in).
	hookDiff(prev.Hooks, next.Hooks, add)

	// 2. New capabilities (in next but not prev) add WeightCapabilityAdd
	// each, plus the per-Capability weight to reflect "this new
	// behavior is worth this much by itself".
	for _, c := range next.Capabilities.Difference(prev.Capabilities) {
		switch c {
		case CapInstallHookExec:
			// Counted by hookDiff; skip.
			continue
		}
		add("capability-added", capabilityAddedDetail(c), WeightCapabilityAdd)
	}

	// 3. Source size delta. We flag massive jumps either direction —
	// a +200% jump may carry payload, a -90% drop may indicate the
	// real package was wiped (faker@6.6.6 sabotage pattern).
	if d := sizeDeltaSignal(prev.SourceSizeBytes, next.SourceSizeBytes); d != "" {
		add("size-anomaly", d, WeightSizeAnomaly)
	}

	return ra
}

// hookDiff emits flags for hook additions and content changes.
func hookDiff(prev, next []InstallHook, add func(code, detail string, weight int)) {
	prevByPhase := map[HookPhase]InstallHook{}
	for _, h := range prev {
		prevByPhase[h.Phase] = h
	}
	for _, h := range next {
		old, existed := prevByPhase[h.Phase]
		switch {
		case !existed:
			add("install-hook-added",
				"new "+h.Phase.String()+" hook (none in prior version)",
				WeightInstallHook)
		case old.Sha256 != "" && h.Sha256 != "" && old.Sha256 != h.Sha256:
			add("install-hook-changed",
				h.Phase.String()+" hook content changed",
				WeightHookContent)
		}
	}
}

// sizeDeltaSignal returns a non-empty description when the source size
// changed by more than 100% (either direction). Returns empty string
// otherwise. Threshold is intentionally generous to keep false-positive
// rate low — small fixes commonly add 10-30%.
func sizeDeltaSignal(prev, next int) string {
	if prev == 0 || next == 0 {
		return ""
	}
	if next >= 2*prev {
		return "source size doubled or more vs prior version"
	}
	if next*2 <= prev {
		return "source size dropped by more than half vs prior version"
	}
	return ""
}

// credentialLikeEnvReads returns env-var names from envReads that match
// any credentialEnvVarRoots prefix.
func credentialLikeEnvReads(envReads []string) []string {
	if len(envReads) == 0 {
		return nil
	}
	var out []string
	for _, name := range envReads {
		upper := upperASCII(name)
		for _, root := range credentialEnvVarRoots {
			if hasPrefix(upper, root) {
				out = append(out, name)
				break
			}
		}
	}
	return out
}

func hasPrefix(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return s[:len(prefix)] == prefix
}

// upperASCII uppercases ASCII letters in s. Avoids importing "strings"
// to keep this file dependency-free for clarity.
func upperASCII(s string) string {
	buf := []byte(s)
	for i, c := range buf {
		if c >= 'a' && c <= 'z' {
			buf[i] = c - 32
		}
	}
	return string(buf)
}

// capabilityAddedDetailPrefix is the literal prefix prepended to the
// Capability name in the Detail field of a "capability-added" drift
// flag. Defined as a const so producer (DriftScore in this file) and
// parser (allowlist_apply.go) stay in sync — changing it in one place
// would break the allowlist match.
const capabilityAddedDetailPrefix = "new capability since prior version: "

// capabilityAddedDetail produces the Detail string for a
// "capability-added" drift flag. allowlist_apply.go's
// parseCapabilityFromDetail is the matching reader.
func capabilityAddedDetail(c Capability) string {
	return capabilityAddedDetailPrefix + c.String()
}

func joinNames(names []string, max int) string {
	if len(names) == 0 {
		return ""
	}
	if len(names) > max {
		names = names[:max]
	}
	out := names[0]
	for _, n := range names[1:] {
		out += ", " + n
	}
	return out
}

// --- Verdict ----------------------------------------------------------

// VerdictKind buckets a combined score into a UX category.
type VerdictKind int

const (
	VerdictSafe   VerdictKind = iota // no concerning signals
	VerdictReview                    // worth a glance, install proceeds
	VerdictPrompt                    // ask the user before proceeding
	VerdictBlock                     // refuse without an audited override
)

// String is the canonical name for serialization.
func (v VerdictKind) String() string {
	switch v {
	case VerdictSafe:
		return "safe"
	case VerdictReview:
		return "review"
	case VerdictPrompt:
		return "prompt"
	case VerdictBlock:
		return "block"
	}
	return "unknown"
}

// VerdictThresholdReview is the lowest combined score that triggers
// "review" output (warn but allow).
const VerdictThresholdReview = 21

// VerdictThresholdPrompt requires interactive confirmation.
const VerdictThresholdPrompt = 61

// VerdictThresholdBlock refuses outright.
const VerdictThresholdBlock = 100

// Verdict combines a per-version risk and a drift assessment into a
// final UX bucket. Combined = max(risk, drift) so a clean upgrade of
// a benign-but-flagged dep doesn't get falsely escalated, while a
// dangerous new version OR a sudden behavioral drift either one trips
// the verdict.
func Verdict(risk, drift RiskAssessment) VerdictKind {
	combined := risk.Score
	if drift.Score > combined {
		combined = drift.Score
	}
	switch {
	case combined >= VerdictThresholdBlock:
		return VerdictBlock
	case combined >= VerdictThresholdPrompt:
		return VerdictPrompt
	case combined >= VerdictThresholdReview:
		return VerdictReview
	default:
		return VerdictSafe
	}
}
