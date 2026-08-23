//! Maintainer-metadata detectors. Port of `maintainer.go`.
//!
//! These score registry-side metadata (publish times, downloads, publisher
//! identity) carried in a [`MaintainerSignal`]. Unlike the source/manifest
//! detectors they don't read a [`crate::NormalizedPackage`] — the registry
//! adapter fetches the signal and the pipeline calls these directly. The
//! clock is injected so the time-based logic is deterministic in tests.
//!
//! Three shapes, each a documented npm compromise pattern:
//!  - maintainer-hijack-risk: fresh + long-gap + low-download (2-of-3)
//!  - version-unpublished: the pinned version was yanked
//!  - maintainer-changed: publisher differs from the previous release

use aegis_domain::Capability;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

/// Versions younger than this are "fresh" — the typical publish-and-ride
/// attack window.
const FRESH_PUBLISH_WINDOW: Duration = Duration::days(7);
/// Minimum gap since the previous publish to count as "abandoned then handed
/// over" (the event-stream shape).
const LONG_GAP_THRESHOLD: Duration = Duration::days(180);
/// Weekly downloads below this are "low traffic" (more attractive to hijack).
const LOW_DOWNLOADS_THRESHOLD: i64 = 1000;
/// How many of the three hijack signals must hold to fire.
const HIJACK_SIGNAL_THRESHOLD: usize = 2;

/// Registry-side metadata for one package version. Mirrors Go's
/// `domain.MaintainerSignal`. All fields are best-effort: an empty string /
/// zero / false means "no data", and the detectors never fire on absence.
#[derive(Debug, Clone, Default)]
pub struct MaintainerSignal {
    /// RFC3339 publish time of the queried version. Empty if unexposed.
    pub published_at: String,
    /// Last-week download count. Zero means "unknown", not "no users".
    pub weekly_downloads: i64,
    /// Most-recent version before `published_at`. Empty on first publish.
    pub previous_version: String,
    /// RFC3339 publish time of `previous_version`.
    pub previous_published_at: String,
    /// npm user who pushed the queried version. Empty if unexposed.
    pub publisher: String,
    /// npm user who pushed `previous_version`.
    pub previous_publisher: String,
    /// True when the queried version was published then yanked.
    pub version_unpublished: bool,
}

fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).ok()
}

/// Fires [`Capability::MaintainerHijackRisk`] when at least
/// `HIJACK_SIGNAL_THRESHOLD` of three known-bad shapes hold: fresh publish,
/// long gap since the previous version, and low weekly downloads. `now` is
/// injected for deterministic tests.
pub fn detect_maintainer_hijack_risk(
    sig: &MaintainerSignal,
    now: OffsetDateTime,
) -> Option<Capability> {
    let publish_t = parse_rfc3339(&sig.published_at)?;
    let mut signals = 0;

    // 1. Fresh publish?
    if now - publish_t <= FRESH_PUBLISH_WINDOW {
        signals += 1;
    }
    // 2. Long gap from the previous publish?
    if let Some(prev_t) = parse_rfc3339(&sig.previous_published_at) {
        if publish_t - prev_t >= LONG_GAP_THRESHOLD {
            signals += 1;
        }
    }
    // 3. Low weekly downloads? (Zero = unknown, don't count.)
    if sig.weekly_downloads > 0 && sig.weekly_downloads < LOW_DOWNLOADS_THRESHOLD {
        signals += 1;
    }

    (signals >= HIJACK_SIGNAL_THRESHOLD).then_some(Capability::MaintainerHijackRisk)
}

/// Fires [`Capability::VersionUnpublished`] when the pinned version was
/// published then yanked. Missing data (false) never fires.
pub fn detect_version_unpublished(sig: &MaintainerSignal) -> Option<Capability> {
    sig.version_unpublished
        .then_some(Capability::VersionUnpublished)
}

/// Fires [`Capability::MaintainerChanged`] when the publisher of this version
/// differs from the previous release's — the canonical maintainer-handover
/// compromise shape (event-stream@3.3.5 `dominictarr` → @3.3.6 `right9ctrl`).
/// Only fires on a concrete mismatch, never on absent data.
pub fn detect_maintainer_changed(sig: &MaintainerSignal) -> Option<Capability> {
    if sig.publisher.is_empty() || sig.previous_publisher.is_empty() {
        return None;
    }
    (sig.publisher != sig.previous_publisher).then_some(Capability::MaintainerChanged)
}

/// Like [`check_maintainer`] but reads the wall clock, so callers that aren't
/// testing time don't have to depend on `time` themselves.
pub fn check_maintainer_now(sig: &MaintainerSignal) -> Vec<Capability> {
    check_maintainer(sig, OffsetDateTime::now_utc())
}

/// Run every maintainer detector and return the union of fired capabilities.
pub fn check_maintainer(sig: &MaintainerSignal, now: OffsetDateTime) -> Vec<Capability> {
    [
        detect_maintainer_hijack_risk(sig, now),
        detect_version_unpublished(sig),
        detect_maintainer_changed(sig),
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // fixed "now": 2026-05-04T12:00:00Z
    fn now() -> OffsetDateTime {
        parse_rfc3339("2026-05-04T12:00:00Z").unwrap()
    }
    fn rfc(offset_days: i64) -> String {
        (now() + Duration::days(offset_days))
            .format(&Rfc3339)
            .unwrap()
    }

    #[test]
    fn all_three_signals_fire() {
        let sig = MaintainerSignal {
            published_at: rfc(-1),                // 1d old — fresh
            previous_published_at: rfc(-3 * 365), // ~3y ago — long gap
            weekly_downloads: 500,                // low
            ..Default::default()
        };
        assert_eq!(
            detect_maintainer_hijack_risk(&sig, now()),
            Some(Capability::MaintainerHijackRisk)
        );
    }

    #[test]
    fn fresh_plus_long_gap_downloads_unknown_fires() {
        let sig = MaintainerSignal {
            published_at: rfc(-3),
            previous_published_at: rfc(-365),
            weekly_downloads: 0, // unknown — doesn't count, but 2 of 3 still hold
            ..Default::default()
        };
        assert_eq!(
            detect_maintainer_hijack_risk(&sig, now()),
            Some(Capability::MaintainerHijackRisk)
        );
    }

    #[test]
    fn fresh_plus_low_downloads_no_prev_fires() {
        let sig = MaintainerSignal {
            published_at: rfc(-2),
            weekly_downloads: 200, // low; no prev-publish → fresh + low = 2 signals
            ..Default::default()
        };
        assert_eq!(
            detect_maintainer_hijack_risk(&sig, now()),
            Some(Capability::MaintainerHijackRisk)
        );
    }

    #[test]
    fn fresh_but_high_downloads_no_gap_does_not_fire() {
        let sig = MaintainerSignal {
            published_at: rfc(-2),
            weekly_downloads: 100_000, // high cancels low; only 1 signal (fresh)
            ..Default::default()
        };
        assert_eq!(detect_maintainer_hijack_risk(&sig, now()), None);
    }

    #[test]
    fn old_low_download_only_one_signal() {
        let sig = MaintainerSignal {
            published_at: rfc(-2 * 365), // old — not fresh
            weekly_downloads: 100,       // low → 1 signal only
            ..Default::default()
        };
        assert_eq!(detect_maintainer_hijack_risk(&sig, now()), None);
    }

    #[test]
    fn short_gap_millions_downloads_does_not_fire() {
        let sig = MaintainerSignal {
            published_at: rfc(-3),
            previous_published_at: rfc(-30), // 30d gap — not "long"
            weekly_downloads: 5_000_000,
            ..Default::default()
        };
        assert_eq!(detect_maintainer_hijack_risk(&sig, now()), None);
    }

    #[test]
    fn empty_or_bad_published_at_no_signal() {
        assert_eq!(
            detect_maintainer_hijack_risk(&MaintainerSignal::default(), now()),
            None
        );
        let bad = MaintainerSignal {
            published_at: "yesterday".into(),
            ..Default::default()
        };
        assert_eq!(detect_maintainer_hijack_risk(&bad, now()), None);
    }

    #[test]
    fn version_unpublished_flag() {
        let mut sig = MaintainerSignal::default();
        assert_eq!(detect_version_unpublished(&sig), None);
        sig.version_unpublished = true;
        assert_eq!(
            detect_version_unpublished(&sig),
            Some(Capability::VersionUnpublished)
        );
    }

    #[test]
    fn maintainer_changed_on_mismatch() {
        let sig = MaintainerSignal {
            publisher: "right9ctrl".into(),
            previous_publisher: "dominictarr".into(),
            ..Default::default()
        };
        assert_eq!(
            detect_maintainer_changed(&sig),
            Some(Capability::MaintainerChanged)
        );
    }

    #[test]
    fn maintainer_same_or_missing_no_signal() {
        let same = MaintainerSignal {
            publisher: "alice".into(),
            previous_publisher: "alice".into(),
            ..Default::default()
        };
        assert_eq!(detect_maintainer_changed(&same), None);
        // missing previous publisher
        let missing = MaintainerSignal {
            publisher: "alice".into(),
            ..Default::default()
        };
        assert_eq!(detect_maintainer_changed(&missing), None);
    }
}
