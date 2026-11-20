use soroban_authscope::{
    AuthScope, AuthVal, InvocationNode, TreeVisualizer,
};

#[test]
fn test_compliant_atomic_swap_authorization() {
    let swap_root = InvocationNode::new(
        "CA_SWAP_ESCROW",
        "execute_swap",
        vec![
            AuthVal::Address("G_ALICE".into()),
            AuthVal::Address("G_BOB".into()),
            AuthVal::U128(100_000_000),
        ],
    )
    .set_authorized(true)
    .with_sub_invocation(
        InvocationNode::new(
            "CD_TOKEN_A",
            "transfer",
            vec![
                AuthVal::Address("G_ALICE".into()),
                AuthVal::Address("G_BOB".into()),
                AuthVal::U128(50_000_000),
            ],
        )
        .set_authorized(true),
    )
    .with_sub_invocation(
        InvocationNode::new(
            "CD_TOKEN_B",
            "transfer",
            vec![
                AuthVal::Address("G_BOB".into()),
                AuthVal::Address("G_ALICE".into()),
                AuthVal::U128(100_000_000),
            ],
        )
        .set_authorized(true),
    );

    let scope = AuthScope::strict();
    let report = scope.analyze(&swap_root).expect("Compliant swap should pass strict verification");

    assert_eq!(report.total_nodes_scanned, 3);
    assert_eq!(report.authorized_nodes, 3);
    assert_eq!(report.missing_auth_nodes, 0);
    assert!(report.violations.is_empty());
}

#[test]
fn test_missing_sub_contract_authorization() {
    // Deliberate defect: Token B sub-invocation lacks authorization
    let flawed_swap = InvocationNode::new(
        "CA_SWAP_ESCROW",
        "execute_swap",
        vec![
            AuthVal::Address("G_ALICE".into()),
            AuthVal::Address("G_BOB".into()),
        ],
    )
    .set_authorized(true)
    .with_sub_invocation(
        InvocationNode::new(
            "CD_TOKEN_A",
            "transfer",
            vec![AuthVal::Address("G_ALICE".into()), AuthVal::U128(50_000_000)],
        )
        .set_authorized(true),
    )
    .with_sub_invocation(
        InvocationNode::new(
            "CD_TOKEN_B",
            "transfer",
            vec![AuthVal::Address("G_BOB".into()), AuthVal::U128(100_000_000)],
        )
        .set_authorized(false), // MISSING AUTH!
    );

    let scope = AuthScope::strict();
    let err_report = scope
        .analyze(&flawed_swap)
        .expect_err("Unauthenticated sub-invocation must fail strict verification");

    assert_eq!(err_report.missing_auth_nodes, 1);
    assert_eq!(err_report.violations.len(), 1);

    let err_msg = err_report.violations[0].to_string();
    assert!(err_msg.contains("CD_TOKEN_B"));
    assert!(err_msg.contains("transfer"));
}

#[test]
fn test_wildcard_permission_rejection() {
    let wildcard_call = InvocationNode::new(
        "CA_VAULT",
        "admin_execute",
        vec![AuthVal::Address("G_ADMIN".into()), AuthVal::Wildcard],
    )
    .set_authorized(true);

    let scope = AuthScope::strict_non_wildcard();
    let err_report = scope
        .analyze(&wildcard_call)
        .expect_err("Wildcard arguments must be rejected under StrictNonWildcard policy");

    assert!(err_report.violations.iter().any(|v| v.to_string().to_lowercase().contains("wildcard")));
}

#[test]
fn test_ascii_dag_tree_formatting() {
    let tree = InvocationNode::new("CA_CONTRACT", "call", vec![AuthVal::U128(42)])
        .set_authorized(true)
        .with_sub_invocation(
            InvocationNode::new("CB_SUB", "nested", vec![]).set_authorized(false),
        );

    let ascii = TreeVisualizer::format_ascii(&tree);
    assert!(ascii.contains("┌─ AuthorizedInvocation DAG"));
    assert!(ascii.contains("[AUTH: ✓] CA_CONTRACT::call"));
    assert!(ascii.contains("[AUTH: ✗ MISSING] CB_SUB::nested"));
}

#[test]
fn test_json_trace_export() {
    let tree = InvocationNode::new("CA_CONTRACT", "ping", vec![]).set_authorized(true);
    let json = TreeVisualizer::to_json_trace(&tree).expect("JSON serialization must succeed");
    assert!(json.contains("\"function_name\": \"ping\""));
    assert!(json.contains("\"is_authorized\": true"));
}

#[test]
fn test_circular_invocation_detection() {
    use soroban_authscope::AuthMismatch;

    // Node A calls Node B calls Node A (Loop!)
    let loop_tree = InvocationNode::new("CONTRACT_A", "callback_entry", vec![])
        .set_authorized(true)
        .with_sub_invocation(
            InvocationNode::new("CONTRACT_B", "invoke_external", vec![])
                .set_authorized(true)
                .with_sub_invocation(
                    InvocationNode::new("CONTRACT_A", "callback_entry", vec![])
                        .set_authorized(true),
                ),
        );

    let scope = AuthScope::strict();
    let err = scope.analyze(&loop_tree).expect_err("Circular invocation must be flagged");
    assert!(err.violations.iter().any(|v| matches!(v, AuthMismatch::CircularInvocation { .. })));
}

#[test]
fn test_trace_parser_and_markdown_reporter() {
    use soroban_authscope::{MarkdownReporter, TraceParser};

    let json_trace = r#"{
        "schema_version": "2.0",
        "network_passphrase": "Test SDF Network ; September 2015",
        "root": {
            "function": {
                "contract": "CA_POOL",
                "function_name": "deposit",
                "args": [{"Address": "G_USER"}]
            },
            "is_authorized": true,
            "sub_invocations": []
        }
    }"#;

    let root = TraceParser::parse_json(json_trace).expect("Parser should parse valid envelope");
    assert_eq!(root.function.function_name, "deposit");

    let scope = AuthScope::strict();
    let report = scope.analyze(&root).unwrap();
    let md = MarkdownReporter::format(&report);
    assert!(md.contains("VERIFIED SECURE"));
}

#[test]
fn test_max_call_depth_threshold_exceeded() {
    use soroban_authscope::{StrictVerifier, VerificationPolicy, AuthMismatch};

    let leaf = InvocationNode::new("C_LEAF", "action", vec![]).set_authorized(true);
    let child = InvocationNode::new("C_MID", "proxy", vec![])
        .set_authorized(true)
        .with_sub_invocation(leaf);
    let root = InvocationNode::new("C_ROOT", "entry", vec![])
        .set_authorized(true)
        .with_sub_invocation(child);

    // root is depth 0, child is depth 1, leaf is depth 2.
    let verifier = StrictVerifier::new(VerificationPolicy::StrictAll).with_max_depth(1);
    let err = verifier.verify(&root).expect_err("Call exceeding max depth 1 must fail");
    assert!(err.violations.iter().any(|v| matches!(v, AuthMismatch::MaxDepthExceeded { depth: 2, max_depth: 1, .. })));
}

#[test]
fn test_invocation_filter_matching() {
    use soroban_authscope::InvocationFilter;

    let leaf = InvocationNode::new("C_LEAF", "transfer", vec![]).set_authorized(true);
    let sibling = InvocationNode::new("C_OTHER", "approve", vec![]).set_authorized(true);
    let root = InvocationNode::new("C_ROOT", "execute", vec![])
        .set_authorized(true)
        .with_sub_invocation(leaf)
        .with_sub_invocation(sibling);

    let filter_contract = InvocationFilter::new().with_contract("C_LEAF");
    let matches = filter_contract.find_matches(&root);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].function.contract.0, "C_LEAF");

    let filter_fn = InvocationFilter::new().with_function("approve");
    let matches_fn = filter_fn.find_matches(&root);
    assert_eq!(matches_fn.len(), 1);
    assert_eq!(matches_fn[0].function.function_name, "approve");

    let filter_miss = InvocationFilter::new().with_contract("NONEXISTENT");
    assert_eq!(filter_miss.find_matches(&root).len(), 0);
}

#[test]
fn test_invalid_function_identifier_rejection() {
    use soroban_authscope::AuthMismatch;

    let invalid_call = InvocationNode::new("C_CONTRACT", "deposit$bad!name", vec![])
        .set_authorized(true);

    let scope = AuthScope::strict();
    let err = scope.analyze(&invalid_call).expect_err("Invalid function name must be rejected");
    assert!(err.violations.iter().any(|v| matches!(v, AuthMismatch::InvalidFunctionIdentifier { .. })));

    let too_long = InvocationNode::new("C_CONTRACT", "a".repeat(33), vec![])
        .set_authorized(true);
    let err_long = scope.analyze(&too_long).expect_err("Overlong function name must be rejected");
    assert!(err_long.violations.iter().any(|v| matches!(v, AuthMismatch::InvalidFunctionIdentifier { .. })));
}

#[test]
fn test_json_summary_reporter_output() {
    use soroban_authscope::JsonSummaryReporter;

    let valid_node = InvocationNode::new("C_OK", "action", vec![]).set_authorized(true);
    let scope = AuthScope::strict();
    let report = scope.analyze(&valid_node).unwrap();

    let summary = JsonSummaryReporter::summarize(&report);
    assert_eq!(summary.status, "PASS");
    assert_eq!(summary.total_nodes, 1);
    assert_eq!(summary.authorized_nodes, 1);
    assert_eq!(summary.violation_count, 0);

    let json_str = JsonSummaryReporter::to_json_string(&report).unwrap();
    assert!(json_str.contains(r#""status": "PASS""#));
}
