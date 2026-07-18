//! Network CVE-enrichment path: OSV/GHSA lookup with EPSS + KEV enrichment,
//! SARIF conversion, and the on-disk advisory caches.

use std::collections::BTreeMap;

use aegis_domain::{Advisory, AdvisoryQuery, Severity};
use aegis_net::{DiskCache, UreqClient};
use aegis_vuln::{EpssClient, KevCatalog, OsvClient};

use crate::commands::FindingView;
use crate::util::parse_severity;

/// Base cache directory: `$XDG_CACHE_HOME/aegis` (or `$HOME/.cache/aegis`),
/// falling back to the OS temp dir.
fn cache_base() -> std::path::PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir)
        .join("aegis")
}

/// On-disk cache for the CISA KEV feed (24h TTL). The ~1 MB feed is fetched at
/// most once per day across runs.
fn kev_disk_cache() -> DiskCache {
    DiskCache::new(
        cache_base().join("kev"),
        Some(std::time::Duration::from_secs(24 * 60 * 60)),
    )
}

/// On-disk cache for OSV advisory documents (7d TTL). Advisory docs are
/// effectively immutable, so the same GHSA/CVE isn't re-fetched across runs.
pub(crate) fn osv_disk_cache() -> DiskCache {
    DiskCache::new(
        cache_base().join("osv"),
        Some(std::time::Duration::from_secs(7 * 24 * 60 * 60)),
    )
}

/// OSV CVE lookup + EPSS/KEV enrichment for a set of queries. Shared by
/// `ci` and the config runner. Uses the real network.
pub(crate) fn cve_findings(queries: &[AdvisoryQuery]) -> Result<Vec<FindingView>, String> {
    let client = UreqClient::new();
    let results = OsvClient::default()
        .with_cache(osv_disk_cache())
        .lookup(&client, queries)?;

    // GHSA runs alongside OSV when a token is present — GitHub publishes
    // advisories before OSV's sync picks them up. Empty/absent token → no-op.
    let ghsa_results = match std::env::var("GITHUB_TOKEN") {
        Ok(tok) if !tok.is_empty() => aegis_vuln::GhsaClient::default()
            .with_token(&tok)
            .lookup(&client, queries),
        _ => std::collections::HashMap::new(),
    };

    let mut advisories = Vec::new();
    let mut context: Vec<(String, String, String)> = Vec::new();
    for q in queries {
        let key = q.key();
        // OSV first, then any GHSA advisory not already seen (dedup by id/alias).
        let osv = results.get(&key).map(|v| v.as_slice()).unwrap_or(&[]);
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let merged = osv.iter().cloned().chain(
            ghsa_results
                .get(&key)
                .map(|v| v.as_slice())
                .unwrap_or(&[])
                .iter()
                .cloned(),
        );
        for adv in merged {
            // Skip if this advisory's id or any alias was already recorded.
            if seen.contains(&adv.id) || adv.aliases.iter().any(|a| seen.contains(a)) {
                continue;
            }
            seen.insert(adv.id.clone());
            for a in &adv.aliases {
                seen.insert(a.clone());
            }
            advisories.push(adv);
            context.push((
                q.ecosystem.as_str().to_string(),
                q.name.clone(),
                q.version.clone(),
            ));
        }
    }
    advisories = EpssClient::default().enrich_advisories(&client, advisories);
    advisories = KevCatalog::default()
        .with_cache(kev_disk_cache())
        .enrich_advisories(&client, advisories);

    Ok(advisories
        .into_iter()
        .zip(context)
        .map(|(adv, (eco, name, version))| FindingView {
            ecosystem: eco,
            name,
            version,
            advisory: adv.id,
            severity: adv.severity.as_str().to_string(),
            summary: adv.summary,
            fixed_in: adv.fixed_in,
            epss: adv.epss,
            in_kev: adv.in_kev,
        })
        .collect())
}

/// Fetch known advisories for `queries`, keyed by `AdvisoryQuery::key()`
/// (= `Dependency::versioned_key`), with full [`Advisory`] records (OSV +
/// GHSA merged, then EPSS + KEV enriched). This is the SBOM-side counterpart
/// to [`cve_findings`], which flattens to `FindingView`; here callers need the
/// whole advisory (id, url, source, severity) for the SBOM vuln section.
pub(crate) fn advisories_by_key(
    queries: &[AdvisoryQuery],
) -> Result<BTreeMap<String, Vec<Advisory>>, String> {
    let client = UreqClient::new();
    let results = OsvClient::default()
        .with_cache(osv_disk_cache())
        .lookup(&client, queries)?;
    let ghsa_results = match std::env::var("GITHUB_TOKEN") {
        Ok(tok) if !tok.is_empty() => aegis_vuln::GhsaClient::default()
            .with_token(&tok)
            .lookup(&client, queries),
        _ => std::collections::HashMap::new(),
    };

    // Merge OSV + GHSA per key, deduping by id/alias, then flat-enrich.
    let mut flat: Vec<Advisory> = Vec::new();
    let mut owners: Vec<String> = Vec::new();
    for q in queries {
        let key = q.key();
        let osv = results.get(&key).map(|v| v.as_slice()).unwrap_or(&[]);
        let ghsa = ghsa_results.get(&key).map(|v| v.as_slice()).unwrap_or(&[]);
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for adv in osv.iter().chain(ghsa.iter()).cloned() {
            if seen.contains(&adv.id) || adv.aliases.iter().any(|a| seen.contains(a)) {
                continue;
            }
            seen.insert(adv.id.clone());
            for a in &adv.aliases {
                seen.insert(a.clone());
            }
            flat.push(adv);
            owners.push(key.clone());
        }
    }
    flat = EpssClient::default().enrich_advisories(&client, flat);
    flat = KevCatalog::default()
        .with_cache(kev_disk_cache())
        .enrich_advisories(&client, flat);

    let mut out: BTreeMap<String, Vec<Advisory>> = BTreeMap::new();
    for (adv, key) in flat.into_iter().zip(owners) {
        out.entry(key).or_default().push(adv);
    }
    Ok(out)
}

/// Map a domain severity string to a SARIF result level.
fn sarif_level(severity: &str) -> &'static str {
    match parse_severity(severity) {
        Some(Severity::Critical | Severity::High) => "error",
        Some(Severity::Medium) => "warning",
        _ => "note",
    }
}

/// Convert CI CVE findings to a SARIF 2.1.0 log. Every advisory becomes one
/// result under the `vulnerable-dependency` rule, located at its package.
pub(crate) fn ci_findings_to_sarif(findings: &[FindingView]) -> String {
    let rules = vec![aegis_sbom::sarif::RuleDef {
        id: "vulnerable-dependency".into(),
        description: "dependency has a known security advisory (CVE/GHSA)".into(),
        level: "error".into(),
    }];
    let results: Vec<aegis_sbom::sarif::FindingRef> = findings
        .iter()
        .map(|f| aegis_sbom::sarif::FindingRef {
            rule_id: "vulnerable-dependency".into(),
            level: sarif_level(&f.severity).into(),
            message: format!("{}: {} ({})", f.advisory, f.summary, f.severity),
            location: Some(format!("{}/{}@{}", f.ecosystem, f.name, f.version)),
            suppressed: false,
        })
        .collect();
    aegis_sbom::sarif::build_json(env!("CARGO_PKG_VERSION"), &rules, &results)
}
