use crate::types::InvocationNode;

/// Query filter for searching through invocation trees.
#[derive(Debug, Clone, Default)]
pub struct InvocationFilter<'a> {
    contract: Option<&'a str>,
    function: Option<&'a str>,
}

impl<'a> InvocationFilter<'a> {
    pub fn new() -> Self {
        Self {
            contract: None,
            function: None,
        }
    }

    pub fn with_contract(mut self, contract: &'a str) -> Self {
        self.contract = Some(contract);
        self
    }

    pub fn with_function(mut self, function: &'a str) -> Self {
        self.function = Some(function);
        self
    }

    pub fn matches(&self, node: &InvocationNode) -> bool {
        if let Some(c) = self.contract {
            if node.function.contract.0 != c {
                return false;
            }
        }
        if let Some(f) = self.function {
            if node.function.function_name != f {
                return false;
            }
        }
        true
    }

    pub fn find_matches<'b>(&self, node: &'b InvocationNode) -> Vec<&'b InvocationNode> {
        let mut results = Vec::new();
        self.collect_matches(node, &mut results);
        results
    }

    fn collect_matches<'b>(&self, node: &'b InvocationNode, results: &mut Vec<&'b InvocationNode>) {
        if self.matches(node) {
            results.push(node);
        }
        for sub in &node.sub_invocations {
            self.collect_matches(sub, results);
        }
    }
}
