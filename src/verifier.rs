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

    #[error("Circular contract invocation loop detected involving contract '{contract}': path={cycle_path:?}")]
    CircularInvocation {
        contract: String,
        cycle_path: Vec<String>,
    },

    #[error("Invocation call depth {depth} exceeds configured maximum threshold {max_depth} at '{contract}' function '{function}'")]
    MaxDepthExceeded {
        contract: String,
        function: String,
        depth: usize,
        max_depth: usize,
    },

    #[error("Invalid function identifier '{function}' at contract '{contract}': function names must be 1..32 ascii alphanumeric or underscore characters")]
    InvalidFunctionIdentifier {
        contract: String,
        function: String,
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
    max_depth: Option<usize>,
}

impl StrictVerifier {
    pub fn new(policy: VerificationPolicy) -> Self {
        Self {
            policy,
            max_depth: None,
        }
    }

    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = Some(max_depth);
        self
    }

    pub fn verify(&self, root: &InvocationNode) -> Result<DiagnosticReport, DiagnosticReport> {
        let mut report = DiagnosticReport::default();
        let mut call_stack = Vec::new();
        self.verify_recursive(root, 0, &mut call_stack, &mut report);

        if report.is_clean() {
            Ok(report)
        } else {
            Err(report)
        }
    }

    fn verify_recursive(
        &self,
        node: &InvocationNode,
        depth: usize,
        call_stack: &mut Vec<String>,
        report: &mut DiagnosticReport,
    ) {
        report.total_nodes_scanned += 1;
        let contract_str = node.function.contract.to_string();

        if let Some(limit) = self.max_depth {
            if depth > limit {
                report.violations.push(AuthMismatch::MaxDepthExceeded {
                    contract: contract_str.clone(),
                    function: node.function.function_name.clone(),
                    depth,
                    max_depth: limit,
                });
            }
        }

        if !node.function.is_valid_identifier() {
            report.violations.push(AuthMismatch::InvalidFunctionIdentifier {
                contract: contract_str.clone(),
                function: node.function.function_name.clone(),
            });
        }

        if call_stack.contains(&contract_str) {
            let mut cycle = call_stack.clone();
            cycle.push(contract_str.clone());
            report.violations.push(AuthMismatch::CircularInvocation {
                contract: contract_str.clone(),
                cycle_path: cycle,
            });
        }

        call_stack.push(contract_str);

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
            self.verify_recursive(sub, depth + 1, call_stack, report);
        }

        call_stack.pop();
    }
}
