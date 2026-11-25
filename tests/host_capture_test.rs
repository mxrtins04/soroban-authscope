use soroban_authscope::{AuthScope, HostAuthCapture};

#[test]
fn test_real_soroban_host_multi_contract_auth_capture_and_depth_policy() {
    let trees = HostAuthCapture::capture_router_vault_auth_tree();
    assert_eq!(trees.len(), 1);

    let root = &trees[0];
    assert_eq!(root.sub_invocations.len(), 1);

    // Depth limit 2 allows router -> inner vault
    assert!(AuthScope::strict().with_max_depth(2).analyze(root).is_ok());

    // Depth limit 0 flags the real nested sub-invocation
    assert!(AuthScope::strict().with_max_depth(0).analyze(root).is_err());

    // Direct verify_live_router_capture helper matches
    assert!(HostAuthCapture::verify_live_router_capture(2).is_ok());
    assert!(HostAuthCapture::verify_live_router_capture(0).is_err());
}
