pub mod filter;
pub mod host_capture;
pub mod parser;
pub mod reporter;
pub mod types;
pub mod verifier;
pub mod visualizer;
pub mod xdr_decoder;

pub use filter::InvocationFilter;
pub use host_capture::HostAuthCapture;
pub use parser::{ParseError, TraceEnvelope, TraceParser};
pub use reporter::{JsonSummaryReporter, MarkdownReporter, SarifReport, SarifReporter, SummaryStatistics, TerminalReporter};
pub use types::{AuthContractId, AuthVal, InvocationFunction, InvocationNode};
pub use verifier::{AuthMismatch, DiagnosticReport, StrictVerifier, VerificationPolicy};
pub use visualizer::TreeVisualizer;
pub use xdr_decoder::XdrAuthDecoder;

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

    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.verifier = self.verifier.with_max_depth(max_depth);
        self
    }

    pub fn with_require_caller_auth(mut self, require: bool) -> Self {
        self.verifier = self.verifier.with_require_caller_auth(require);
        self
    }

    pub fn analyze(&self, root: &InvocationNode) -> Result<DiagnosticReport, DiagnosticReport> {
        self.verifier.verify(root)
    }

    pub fn print_tree(root: &InvocationNode) {
        println!("{}", TreeVisualizer::format_ascii(root));
    }
}
