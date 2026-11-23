use crate::types::{AuthContractId, AuthVal, InvocationFunction, InvocationNode};
use stellar_xdr::{
    Limits, ReadXdr, ScVal, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, WriteXdr,
};

/// Real Stellar XDR decoder translating `SorobanAuthorizationEntry` and
/// `SorobanAuthorizedInvocation` trees into `AuthScope` `InvocationNode` structures.
pub struct XdrAuthDecoder;

impl XdrAuthDecoder {
    /// Decode a base64-encoded XDR `SorobanAuthorizationEntry` into an `InvocationNode` tree.
    pub fn decode_entry_base64(b64: &str) -> Result<InvocationNode, String> {
        let entry = SorobanAuthorizationEntry::from_xdr_base64(b64.trim(), Limits::none())
            .map_err(|e| format!("failed to decode SorobanAuthorizationEntry base64 XDR: {e}"))?;
        Ok(Self::invocation_to_node(&entry.root_invocation))
    }

    /// Encode a `SorobanAuthorizationEntry` to base64 XDR (useful for test fixtures and tooling).
    pub fn encode_entry_base64(entry: &SorobanAuthorizationEntry) -> Result<String, String> {
        entry
            .to_xdr_base64(Limits::none())
            .map_err(|e| format!("failed to encode SorobanAuthorizationEntry to base64 XDR: {e}"))
    }

    /// Recursively convert a real XDR `SorobanAuthorizedInvocation` tree into an `InvocationNode`.
    pub fn invocation_to_node(inv: &SorobanAuthorizedInvocation) -> InvocationNode {
        let (contract_id, function_name, args) = match &inv.function {
            SorobanAuthorizedFunction::ContractFn(args_fn) => {
                let cid = format!("{:?}", args_fn.contract_address);
                let fname = args_fn.function_name.0.to_utf8_string_lossy();
                let mapped_args: Vec<AuthVal> = args_fn.args.iter().map(Self::scval_to_authval).collect();
                (AuthContractId(cid), fname, mapped_args)
            }
            SorobanAuthorizedFunction::CreateContractHostFn(_)
            | SorobanAuthorizedFunction::CreateContractV2HostFn(_) => (
                AuthContractId("HOST_CREATE_CONTRACT".to_string()),
                "create_contract".to_string(),
                vec![],
            ),
        };

        let sub_invocations = inv
            .sub_invocations
            .iter()
            .map(Self::invocation_to_node)
            .collect();

        InvocationNode {
            function: InvocationFunction {
                contract: contract_id,
                function_name,
                args,
            },
            sub_invocations,
            is_authorized: true,
            invoker: None,
        }
    }

    fn scval_to_authval(v: &ScVal) -> AuthVal {
        match v {
            ScVal::Symbol(s) => AuthVal::Symbol(s.0.to_utf8_string_lossy()),
            ScVal::I128(parts) => {
                let val = ((parts.hi as i128) << 64) | (parts.lo as i128);
                AuthVal::I128(val)
            }
            ScVal::U32(n) => AuthVal::U128(*n as u128),
            ScVal::String(s) => AuthVal::Symbol(s.0.to_utf8_string_lossy()),
            other => AuthVal::Symbol(format!("{other:?}")),
        }
    }
}
