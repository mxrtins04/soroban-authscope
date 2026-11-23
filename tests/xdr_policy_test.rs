use soroban_authscope::{AuthScope, XdrAuthDecoder};
use stellar_xdr::{
    ContractId, Hash, InvokeContractArgs, ScAddress, ScSymbol, ScVal,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, StringM, VecM,
};

#[test]
fn test_real_xdr_decoder_rejects_corrupted_base64_and_handles_deep_nesting() {
    assert!(XdrAuthDecoder::decode_entry_base64("!!!not-valid-xdr!!!").is_err());

    let leaf = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([3u8; 32]))),
            function_name: ScSymbol(StringM::try_from("mint").unwrap()),
            args: VecM::try_from(vec![ScVal::U32(1)]).unwrap(),
        }),
        sub_invocations: VecM::default(),
    };
    let mid = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([2u8; 32]))),
            function_name: ScSymbol(StringM::try_from("deposit").unwrap()),
            args: VecM::default(),
        }),
        sub_invocations: VecM::try_from(vec![leaf]).unwrap(),
    };
    let root = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([1u8; 32]))),
            function_name: ScSymbol(StringM::try_from("zap").unwrap()),
            args: VecM::default(),
        }),
        sub_invocations: VecM::try_from(vec![mid]).unwrap(),
    };

    let entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::SourceAccount,
        root_invocation: root,
    };
    let b64 = XdrAuthDecoder::encode_entry_base64(&entry).unwrap();
    let decoded = XdrAuthDecoder::decode_entry_base64(&b64).unwrap();

    // Depth 2 tree passes max_depth=2, fails max_depth=1
    assert!(AuthScope::strict().with_max_depth(2).analyze(&decoded).is_ok());
    assert!(AuthScope::strict().with_max_depth(1).analyze(&decoded).is_err());
}
