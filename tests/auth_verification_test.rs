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
