use crate::types::{AuthContractId, InvocationFunction, InvocationNode};
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation},
    Address, Env,
};

#[contract]
pub struct DemoInnerVault;

#[contractimpl]
impl DemoInnerVault {
    pub fn deposit(_env: Env, user: Address, amount: i128) -> i128 {
        user.require_auth();
        amount
    }
}

#[contract]
pub struct DemoRouter;

#[contractimpl]
impl DemoRouter {
    pub fn route_deposit(env: Env, vault_id: Address, user: Address, amount: i128) -> i128 {
        user.require_auth();
        let vault = DemoInnerVaultClient::new(&env, &vault_id);
        vault.deposit(&user, &amount)
    }
}

/// Captures live `soroban_sdk::Env::auths()` trees from real multi-contract Soroban host
/// invocations and converts them into `AuthScope` `InvocationNode` trees.
pub struct HostAuthCapture;

impl HostAuthCapture {
    pub fn convert_authorized_invocation(inv: &AuthorizedInvocation) -> InvocationNode {
        let (contract, function_name) = match &inv.function {
            AuthorizedFunction::Contract((addr, sym, _args)) => {
                let raw = format!("{sym:?}");
                let clean_fn = raw
                    .strip_prefix("Symbol(")
                    .and_then(|s| s.strip_suffix(')'))
                    .unwrap_or(&raw)
                    .to_string();
                (AuthContractId(format!("{addr:?}")), clean_fn)
            }
            AuthorizedFunction::CreateContractHostFn(_)
            | AuthorizedFunction::CreateContractV2HostFn(_) => (
                AuthContractId("HOST_CREATE_CONTRACT".to_string()),
                "create_contract".to_string(),
            ),
        };

        let sub_invocations = inv
            .sub_invocations
            .iter()
            .map(Self::convert_authorized_invocation)
            .collect();

        InvocationNode {
            function: InvocationFunction {
                contract,
                function_name,
                args: vec![],
            },
            sub_invocations,
            is_authorized: true,
            invoker: None,
        }
    }

    /// Execute a real multi-contract `DemoRouter -> DemoInnerVault` call in `soroban_sdk::Env`
    /// and return the captured `InvocationNode` authorization tree.
    pub fn capture_router_vault_auth_tree() -> Vec<InvocationNode> {
        let env = Env::default();
        env.mock_all_auths();

        let vault_id = env.register(DemoInnerVault, ());
        let router_id = env.register(DemoRouter, ());
        let router = DemoRouterClient::new(&env, &router_id);
        let user = Address::generate(&env);

        router.route_deposit(&vault_id, &user, &1000);

        env.auths()
            .iter()
            .map(|(_addr, inv)| Self::convert_authorized_invocation(inv))
            .collect()
    }
}
