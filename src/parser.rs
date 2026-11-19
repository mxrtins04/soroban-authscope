use crate::types::InvocationNode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    #[error("Invalid JSON trace structure: {0}")]
    JsonError(String),
    #[error("Unsupported schema version '{version}'. Expected '1.0' or '2.0'")]
    UnsupportedSchema { version: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEnvelope {
    pub schema_version: String,
    pub network_passphrase: Option<String>,
    pub root: InvocationNode,
}

pub struct TraceParser;

impl TraceParser {
    pub fn parse_json(json_str: &str) -> Result<InvocationNode, ParseError> {
        // Try parsing enveloped schema first
        if let Ok(env) = serde_json::from_str::<TraceEnvelope>(json_str) {
            if env.schema_version != "1.0" && env.schema_version != "2.0" {
                return Err(ParseError::UnsupportedSchema {
                    version: env.schema_version,
                });
            }
            return Ok(env.root);
        }

        // Fall back to direct InvocationNode
        serde_json::from_str::<InvocationNode>(json_str)
            .map_err(|e| ParseError::JsonError(e.to_string()))
    }
}
