use soroban_authscope::{
    AuthScope, AuthVal, InvocationNode,
};

#[test]
fn test_target1_compliant_multi_hop_vault() {
    let vault_root = InvocationNode::new("CA_VAULT", "deposit", vec![AuthVal::U128(500)])
        .with_invoker("G_USER")
        .set_authorized(true)
        .with_sub_invocation(
            InvocationNode::new("CB_TOKEN", "transfer", vec![AuthVal::U128(500)])
                .with_invoker("CA_VAULT")
                .set_authorized(true),
        );

    assert_eq!(vault_root.max_depth(), 2);
    let scope = AuthScope::strict_non_wildcard();
    let res = scope.analyze(&vault_root);
    assert!(res.is_ok(), "Compliant multi-hop vault must pass verification");
}

#[test]
fn test_target2_defective_vault_missing_child_auth() {
    let defective_vault = InvocationNode::new("CA_VAULT", "deposit", vec![AuthVal::U128(500)])
        .with_invoker("G_USER")
        .set_authorized(true)
        .with_sub_invocation(
            InvocationNode::new("CB_TOKEN", "transfer", vec![AuthVal::U128(500)])
                .with_invoker("CA_VAULT")
                .set_authorized(false), // DELIBERATE DEFECT: missing sub-auth
        );

    let scope = AuthScope::strict();
    let err = scope.analyze(&defective_vault).expect_err("Missing child auth must fail");
    assert_eq!(err.missing_auth_nodes, 1);
    let msg = err.violations[0].to_string();
    assert!(msg.contains("CB_TOKEN"));
    assert!(msg.contains("transfer"));
}

#[test]
fn test_target3_over_privileged_wildcard_scope() {
    let over_privileged = InvocationNode::new(
        "CA_VAULT",
        "withdraw",
        vec![AuthVal::Address("G_RECEIVER".into()), AuthVal::Wildcard], // DELIBERATE DEFECT: wildcard amount
    )
    .set_authorized(true);

    let scope = AuthScope::strict_non_wildcard();
    let err = scope.analyze(&over_privileged).expect_err("Wildcard scope must fail");
    assert!(!err.violations.is_empty());
    let msg = err.violations[0].to_string();
    assert!(msg.contains("parameter 1 uses unbounded wildcard"));
}
