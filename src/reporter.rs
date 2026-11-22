use crate::verifier::DiagnosticReport;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryStatistics {
    pub status: String,
    pub total_nodes: usize,
    pub authorized_nodes: usize,
    pub missing_auth: usize,
    pub violation_count: usize,
}

pub struct JsonSummaryReporter;

impl JsonSummaryReporter {
    pub fn summarize(report: &DiagnosticReport) -> SummaryStatistics {
        SummaryStatistics {
            status: if report.is_clean() { "PASS".into() } else { "FAIL".into() },
            total_nodes: report.total_nodes_scanned,
            authorized_nodes: report.authorized_nodes,
            missing_auth: report.missing_auth_nodes,
            violation_count: report.violations.len(),
        }
    }

    pub fn to_json_string(report: &DiagnosticReport) -> Result<String, serde_json::Error> {
        let stats = Self::summarize(report);
        serde_json::to_string_pretty(&stats)
    }
}

pub struct MarkdownReporter;

impl MarkdownReporter {
    pub fn format(report: &DiagnosticReport) -> String {
        let mut out = String::new();
        out.push_str("# Soroban AuthScope Audit Report\n\n");

        if report.is_clean() {
            out.push_str("✅ **Status: VERIFIED SECURE**\n\n");
            out.push_str("- All invocation nodes carry explicit authorizations.\n");
            out.push_str("- No wildcard argument scopes or circular calls detected.\n\n");
        } else {
            out.push_str("⚠️ **Status: AUTHORIZATION MISMATCH DETECTED**\n\n");
            out.push_str(&format!("- Total Nodes Scanned: {}\n", report.total_nodes_scanned));
            out.push_str(&format!("- Authorized Nodes: {}\n", report.authorized_nodes));
            out.push_str(&format!("- Missing Authorizations: {}\n", report.missing_auth_nodes));
            out.push_str(&format!("- Total Violations: {}\n\n", report.violations.len()));

            out.push_str("### Violations Breakdown\n\n");
            for (idx, v) in report.violations.iter().enumerate() {
                out.push_str(&format!("{}. {}\n", idx + 1, v));
            }
            out.push('\n');
        }

        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifReport {
    pub version: String,
    #[serde(rename = "$schema")]
    pub schema: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    pub information_uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifResult {
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

pub struct SarifReporter;

impl SarifReporter {
    pub fn generate(report: &DiagnosticReport) -> SarifReport {
        let results = report
            .violations
            .iter()
            .map(|v| SarifResult {
                rule_id: "AUTH001".into(),
                level: "error".into(),
                message: SarifMessage {
                    text: v.to_string(),
                },
            })
            .collect();

        SarifReport {
            version: "2.1.0".into(),
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".into(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "soroban-authscope".into(),
                        version: env!("CARGO_PKG_VERSION").into(),
                        information_uri: "https://github.com/mxrtins04/soroban-authscope".into(),
                    },
                },
                results,
            }],
        }
    }

    pub fn to_json_string(report: &DiagnosticReport) -> Result<String, serde_json::Error> {
        let sarif = Self::generate(report);
        serde_json::to_string_pretty(&sarif)
    }
}

pub struct TerminalReporter;

impl TerminalReporter {
    pub fn format_colored(report: &DiagnosticReport) -> String {
        let mut out = String::new();
        if report.is_clean() {
            out.push_str("\x1b[32m✔ PASS: Authorization verification passed with 0 violations\x1b[0m\n");
            out.push_str(&format!("  Scanned {} invocation nodes.\n", report.total_nodes_scanned));
        } else {
            out.push_str(&format!("\x1b[31m✖ FAIL: Detected {} authorization violation(s)\x1b[0m\n", report.violations.len()));
            for (i, v) in report.violations.iter().enumerate() {
                out.push_str(&format!("  \x1b[31m[{}]\x1b[0m {}\n", i + 1, v));
            }
        }
        out
    }
}


