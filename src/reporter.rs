use crate::verifier::DiagnosticReport;

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
