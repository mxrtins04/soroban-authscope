use soroban_authscope::{AuthScope, InvocationNode, TraceParser};

#[test]
fn test_parser_rejection_of_unsupported_version() {
    let bad_json = r#"{
        "schema_version": "99.0",
        "root": {
            "function": {
                "contract": "CA_POOL",
                "function_name": "deposit",
                "args": []
            },
            "is_authorized": true,
            "sub_invocations": []
        }
    }"#;

    let res = TraceParser::parse_json(bad_json);
    assert!(res.is_err());
    let err_str = res.unwrap_err().to_string();
    assert!(err_str.contains("Unsupported schema"));
}

#[test]
fn test_end_to_end_multicall_verification() {
    let tree = InvocationNode::new("CA_CONTRACT", "call1", vec![])
        .set_authorized(true)
        .with_sub_invocation(InvocationNode::new("CB_CONTRACT", "call2", vec![]).set_authorized(true));

    let serialized = serde_json::to_string(&tree).unwrap();
    let parsed = TraceParser::parse_json(&serialized).unwrap();
    let scope = AuthScope::strict();
    let report = scope.analyze(&parsed).unwrap();
    assert!(report.is_clean());
    assert_eq!(report.total_nodes_scanned, 2);
}

#[test]
fn test_cli_markdown_output_format() {
    use soroban_authscope::MarkdownReporter;
    let tree = InvocationNode::new("CA_CONTRACT", "call1", vec![]).set_authorized(false);
    let scope = AuthScope::strict();
    let report = scope.analyze(&tree).unwrap_err();
    let md = MarkdownReporter::format(&report);
    assert!(md.contains("AUTHORIZATION MISMATCH DETECTED"));
    assert!(md.contains("Missing Authorization"));
}
