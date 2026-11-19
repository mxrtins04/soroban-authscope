use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthContractId(pub String);

impl AuthContractId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for AuthContractId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthVal {
    Symbol(String),
    Address(String),
    U128(u128),
    I128(i128),
    Bytes(Vec<u8>),
    Wildcard,
}

impl std::fmt::Display for AuthVal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Symbol(s) => write!(f, "Symbol(\"{}\")", s),
            Self::Address(a) => write!(f, "Address(\"{}\")", a),
            Self::U128(n) => write!(f, "U128({})", n),
            Self::I128(n) => write!(f, "I128({})", n),
            Self::Bytes(b) => write!(f, "Bytes(len={})", b.len()),
            Self::Wildcard => write!(f, "* (Wildcard)"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationFunction {
    pub contract: AuthContractId,
    pub function_name: String,
    pub args: Vec<AuthVal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationNode {
    pub function: InvocationFunction,
    pub sub_invocations: Vec<InvocationNode>,
    pub is_authorized: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invoker: Option<String>,
}

impl InvocationNode {
    pub fn new(contract: impl Into<String>, function_name: impl Into<String>, args: Vec<AuthVal>) -> Self {
        Self {
            function: InvocationFunction {
                contract: AuthContractId::new(contract),
                function_name: function_name.into(),
                args,
            },
            sub_invocations: Vec::new(),
            is_authorized: false,
            invoker: None,
        }
    }

    pub fn with_invoker(mut self, invoker: impl Into<String>) -> Self {
        self.invoker = Some(invoker.into());
        self
    }

    pub fn with_sub_invocation(mut self, sub: InvocationNode) -> Self {
        self.sub_invocations.push(sub);
        self
    }

    pub fn set_authorized(mut self, authorized: bool) -> Self {
        self.is_authorized = authorized;
        self
    }

    pub fn total_nodes(&self) -> usize {
        1 + self.sub_invocations.iter().map(InvocationNode::total_nodes).sum::<usize>()
    }

    pub fn max_depth(&self) -> usize {
        if self.sub_invocations.is_empty() {
            1
        } else {
            1 + self.sub_invocations.iter().map(InvocationNode::max_depth).max().unwrap_or(0)
        }
    }
}
