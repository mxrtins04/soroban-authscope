use soroban_authscope::{AuthScope, XdrAuthDecoder};
use stellar_xdr::{
    ContractId, Hash, InvokeContractArgs, ScAddress, ScSymbol, ScVal,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, StringM, VecM,
};

fn build_sample_nested_auth_entry() -> SorobanAuthorizationEntry {
    let token_inv = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([2u8; 32]))),
            function_name: ScSymbol(StringM::try_from("transfer").unwrap()),
            args: VecM::try_from(vec![ScVal::U32(500)]).unwrap(),
        }),
        sub_invocations: VecM::default(),
    };

    let router_inv = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([1u8; 32]))),
            function_name: ScSymbol(StringM::try_from("swap").unwrap()),
            args: VecM::try_from(vec![ScVal::Symbol(ScSymbol(
                StringM::try_from("USDC").unwrap(),
            ))])
            .unwrap(),
        }),
        sub_invocations: VecM::try_from(vec![token_inv]).unwrap(),
    };

    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::SourceAccount,
        root_invocation: router_inv,
    }
}

#[test]
fn test_real_xdr_authorization_entry_decodes_nested_tree_and_enforces_depth_policy() {
    let entry = build_sample_nested_auth_entry();
    let b64 = XdrAuthDecoder::encode_entry_base64(&entry).unwrap();

    let decoded = XdrAuthDecoder::decode_entry_base64(&b64).unwrap();
    assert_eq!(decoded.function.function_name, "swap");
    assert_eq!(decoded.sub_invocations.len(), 1);
    assert_eq!(decoded.sub_invocations[0].function.function_name, "transfer");

    // Depth limit 2 allows router -> token
    let ok_scope = AuthScope::strict().with_max_depth(2);
    assert!(ok_scope.analyze(&decoded).is_ok());

    // Depth limit 0 flags nested sub-invocation on real decoded XDR
    let tight_scope = AuthScope::strict().with_max_depth(0);
    assert!(tight_scope.analyze(&decoded).is_err());
}
