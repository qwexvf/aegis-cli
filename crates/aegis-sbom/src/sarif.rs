//! SARIF 2.1.0 emitter. Port of `internal/infra/sarif`.
//!
//! SARIF (Static Analysis Results Interchange Format) is the OASIS standard
//! consumed by GitHub Code Scanning, VS Code, and CI security dashboards. This
//! builds a SARIF log from a caller-supplied rule set + finding list — the
//! mapping from aegis findings (CVE advisories, capability flags) to SARIF
//! results lives in the CLI. Pure, deterministic.

use serde::Serialize;

const VERSION: &str = "2.1.0";
const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// A detector definition referenced by results. `level` is one of
/// "error" | "warning" | "note" | "none".
#[derive(Debug, Clone)]
pub struct RuleDef {
    pub id: String,
    pub description: String,
    pub level: String,
}

/// One finding. `location` is a fully-qualified package identity (e.g.
/// "npm/lodash@4.17.4") — the package scanner has no file:line, so results use
/// a logical location. `suppressed` marks a finding suppressed but visible.
#[derive(Debug, Clone)]
pub struct FindingRef {
    pub rule_id: String,
    pub level: String,
    pub message: String,
    pub location: Option<String>,
    pub suppressed: bool,
}

/// Build a SARIF 2.1.0 log as a pretty-printed JSON string.
pub fn build_json(tool_version: &str, rules: &[RuleDef], findings: &[FindingRef]) -> String {
    serde_json::to_string_pretty(&build(tool_version, rules, findings)).unwrap_or_default()
}

/// Build the typed SARIF log.
pub fn build(tool_version: &str, rules: &[RuleDef], findings: &[FindingRef]) -> Log {
    let rule_objs = rules
        .iter()
        .map(|r| Rule {
            id: r.id.clone(),
            short_description: Message {
                text: r.description.clone(),
            },
            default_configuration: RuleConfig {
                level: r.level.clone(),
            },
        })
        .collect();

    let results = findings
        .iter()
        .map(|f| Result_ {
            rule_id: f.rule_id.clone(),
            level: f.level.clone(),
            message: Message {
                text: f.message.clone(),
            },
            locations: f.location.as_ref().map(|loc| {
                vec![Location {
                    logical_locations: vec![LogicalLocation {
                        fully_qualified_name: loc.clone(),
                        kind: "package".into(),
                    }],
                }]
            }),
            suppressions: f.suppressed.then(|| {
                vec![Suppression {
                    kind: "external",
                    justification: "suppressed by allowlist",
                }]
            }),
        })
        .collect();

    Log {
        version: VERSION,
        schema: SCHEMA,
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "aegis-cli",
                    version: tool_version.to_string(),
                    information_uri: "https://github.com/qwexvf/aegis-cli",
                    rules: rule_objs,
                },
            },
            results,
        }],
    }
}

// --- SARIF 2.1.0 schema (subset) --------------------------------------------

#[derive(Serialize)]
pub struct Log {
    version: &'static str,
    #[serde(rename = "$schema")]
    schema: &'static str,
    runs: Vec<Run>,
}

#[derive(Serialize)]
struct Run {
    tool: Tool,
    results: Vec<Result_>,
}

#[derive(Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Serialize)]
struct Driver {
    name: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rules: Vec<Rule>,
}

#[derive(Serialize)]
struct Rule {
    id: String,
    #[serde(rename = "shortDescription")]
    short_description: Message,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: RuleConfig,
}

#[derive(Serialize)]
struct RuleConfig {
    level: String,
}

#[derive(Serialize)]
struct Result_ {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: Message,
    #[serde(skip_serializing_if = "Option::is_none")]
    locations: Option<Vec<Location>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suppressions: Option<Vec<Suppression>>,
}

#[derive(Serialize)]
struct Message {
    text: String,
}

#[derive(Serialize)]
struct Location {
    #[serde(rename = "logicalLocations")]
    logical_locations: Vec<LogicalLocation>,
}

#[derive(Serialize)]
struct LogicalLocation {
    #[serde(rename = "fullyQualifiedName")]
    fully_qualified_name: String,
    kind: String,
}

#[derive(Serialize)]
struct Suppression {
    kind: &'static str,
    justification: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn rule(id: &str, level: &str) -> RuleDef {
        RuleDef {
            id: id.into(),
            description: format!("{id} desc"),
            level: level.into(),
        }
    }

    #[test]
    fn log_shape_and_result() {
        let rules = vec![rule("vulnerable-dependency", "error")];
        let findings = vec![FindingRef {
            rule_id: "vulnerable-dependency".into(),
            level: "error".into(),
            message: "GHSA-x: bad (high)".into(),
            location: Some("npm/lodash@4.17.4".into()),
            suppressed: false,
        }];
        let json = build_json("0.1.0", &rules, &findings);
        let v: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "aegis-cli");
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"][0]["id"],
            "vulnerable-dependency"
        );
        let r = &v["runs"][0]["results"][0];
        assert_eq!(r["ruleId"], "vulnerable-dependency");
        assert_eq!(r["level"], "error");
        assert_eq!(
            r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"],
            "npm/lodash@4.17.4"
        );
        // no suppressions key when not suppressed
        assert!(r.get("suppressions").is_none());
    }

    #[test]
    fn suppressed_finding_marked() {
        let findings = vec![FindingRef {
            rule_id: "vulnerable-dependency".into(),
            level: "error".into(),
            message: "x".into(),
            location: None,
            suppressed: true,
        }];
        let json = build_json("0.1.0", &[], &findings);
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["runs"][0]["results"][0]["suppressions"][0]["kind"],
            "external"
        );
        // no location key when absent
        assert!(v["runs"][0]["results"][0].get("locations").is_none());
    }

    #[test]
    fn empty_findings_valid_log() {
        let json = build_json("0.1.0", &[], &[]);
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
    }
}
