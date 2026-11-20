pub mod filter;
pub mod parser;
pub mod reporter;
pub mod types;
pub mod verifier;
pub mod visualizer;

pub use filter::InvocationFilter;
pub use parser::{ParseError, TraceEnvelope, TraceParser};
pub use reporter::MarkdownReporter;
pub use types::{AuthContractId, AuthVal, InvocationFunction, InvocationNode};
pub use verifier::{AuthMismatch, DiagnosticReport, StrictVerifier, VerificationPolicy};
pub use visualizer::TreeVisualizer;

/// High-level diagnostic engine for inspecting Soroban authorization trees.
pub struct AuthScope {
    verifier: StrictVerifier,
}

impl AuthScope {
    pub fn new(policy: VerificationPolicy) -> Self {
        Self {
            verifier: StrictVerifier::new(policy),
        }
    }

    pub fn strict() -> Self {
        Self::new(VerificationPolicy::StrictAll)
    }

    pub fn strict_non_wildcard() -> Self {
        Self::new(VerificationPolicy::StrictNonWildcard)
    }

    pub fn analyze(&self, root: &InvocationNode) -> Result<DiagnosticReport, DiagnosticReport> {
        self.verifier.verify(root)
    }

    pub fn print_tree(root: &InvocationNode) {
        println!("{}", TreeVisualizer::format_ascii(root));
    }
}
