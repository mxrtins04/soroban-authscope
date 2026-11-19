use crate::types::{AuthVal, InvocationNode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationPolicy {
    /// Every node in the invocation DAG must have explicit authorization recorded.
    StrictAll,
    /// Disallows any wildcard or unbounded argument authorizations.
    DisallowWildcards,
    /// Requires exact match between authorized argument filters and runtime execution parameters.
    ExactArgsOnly,
    /// Combines StrictAll and DisallowWildcards.
    StrictNonWildcard,
}

#[derive(Error, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMismatch {
    #[error("Missing explicit authorization at contract '{contract}' for function '{function}'")]
    MissingAuthorization {
        contract: String,
        function: String,
        depth: usize,
    },

    #[error("Wildcard authorization detected at contract '{contract}' function '{function}' (disallowed by policy)")]
    WildcardDisallowed {
        contract: String,
        function: String,
    },

    #[error("Argument count mismatch at contract '{contract}' function '{function}': expected {expected}, got {actual}")]
    ArgumentCountMismatch {
        contract: String,
        function: String,
        expected: usize,
        actual: usize,
    },

    #[error("Over-privileged authorization scope detected at '{contract}' function '{function}': parameter {parameter_index} uses unbounded wildcard")]
    OverPrivilegedScope {
        contract: String,
        function: String,
        parameter_index: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiagnosticReport {
    pub total_nodes_scanned: usize,
    pub authorized_nodes: usize,
    pub missing_auth_nodes: usize,
    pub violations: Vec<AuthMismatch>,
}

impl DiagnosticReport {
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty() && self.missing_auth_nodes == 0
    }
}

pub struct StrictVerifier {
    policy: VerificationPolicy,
}

impl StrictVerifier {
    pub fn new(policy: VerificationPolicy) -> Self {
        Self { policy }
    }

    pub fn verify(&self, root: &InvocationNode) -> Result<DiagnosticReport, DiagnosticReport> {
        let mut report = DiagnosticReport::default();
        self.verify_recursive(root, 0, &mut report);

        if report.is_clean() {
            Ok(report)
        } else {
            Err(report)
        }
    }

    fn verify_recursive(&self, node: &InvocationNode, depth: usize, report: &mut DiagnosticReport) {
        report.total_nodes_scanned += 1;

        if node.is_authorized {
            report.authorized_nodes += 1;
        } else if matches!(
            self.policy,
            VerificationPolicy::StrictAll | VerificationPolicy::StrictNonWildcard
        ) {
            report.missing_auth_nodes += 1;
            report.violations.push(AuthMismatch::MissingAuthorization {
                contract: node.function.contract.to_string(),
                function: node.function.function_name.clone(),
                depth,
            });
        }

        // Check for wildcards and over-privileged scopes
        if matches!(
            self.policy,
            VerificationPolicy::DisallowWildcards | VerificationPolicy::StrictNonWildcard | VerificationPolicy::ExactArgsOnly
        ) {
            for (idx, arg) in node.function.args.iter().enumerate() {
                if matches!(arg, AuthVal::Wildcard) {
                    report.violations.push(AuthMismatch::OverPrivilegedScope {
                        contract: node.function.contract.to_string(),
                        function: node.function.function_name.clone(),
                        parameter_index: idx,
                    });
                }
            }
        }

        for sub in &node.sub_invocations {
            self.verify_recursive(sub, depth + 1, report);
        }
    }
}
