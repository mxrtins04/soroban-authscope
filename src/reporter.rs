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
