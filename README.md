# soroban-authscope

Hierarchical authorization tree analyzer and diagnostic engine for Soroban smart contracts.

## Overview

When developing multi-contract Soroban protocols—such as atomic swaps, cross-contract vaults, and delegated DeFi flows—managing contract authorization hierarchies (`AuthorizedInvocation`) can be complex. Many test suites default to `mock_all_auths()`, which can mask missing sub-contract authorization checks, signature scoping vulnerabilities, and over-privileged wildcard signatures.

`soroban-authscope` provides deterministic authorization inspection and visualization for Soroban contract tests:
- **Invocation Tracing**: Reconstructs the complete hierarchical invocation DAG executed during contract calls.
- **Strict Authorization Verification**: Verifies that every intermediate contract and sub-invocation is explicitly and correctly authorized without blanket mocking.
- **Diagnostic Inspection**: Detects over-privileged signatures, unbounded argument permissions, and missing sub-auth nodes with precise root-cause diagnostics.
- **ASCII & JSON Output**: Visualizes invocation trees directly in test runner stdout and emits structured JSON traces for CI inspection.

## Architecture

```
┌──────────────────────────────────────────────────┐
│              Soroban Host Environment             │
└─────────────────────────┬────────────────────────┘
                          │ Invocation Traversal
                          ▼
┌──────────────────────────────────────────────────┐
│              soroban-authscope Engine             │
│  - Invocation Tree Interceptor                   │
│  - Policy & Signature Verifier                    │
│  - Mismatch & Wildcard Diagnostic Analyzer       │
└─────────────────────────┬────────────────────────┘
                          │ Output Formatting
         ┌────────────────┴────────────────┐
         ▼                                 ▼
   ASCII Tree View                   JSON Trace Event
```

## Getting Started

### Prerequisites

- Rust 1.79+
- Soroban SDK / Stellar CLI

### Installation

Add `soroban-authscope` to your `Cargo.toml`:

```toml
[dev-dependencies]
soroban-authscope = { git = "https://github.com/mxrtins04/soroban-authscope" }
```

### Usage Example

```rust
use soroban_authscope::AuthScope;
use soroban_sdk::{Env, Address};

#[test]
fn test_vault_deposit_authorization() {
    let env = Env::default();
    let authscope = AuthScope::new(&env);
    
    // Execute contract call under inspection
    // ...
    
    // Print formatted authorization tree to test output
    authscope.print_tree();
    
    // Assert complete invocation tree compliance
    authscope.assert_exact_auth();
}
```

## Roadmap

- [ ] Core AST & invocation tree capture from Soroban host events
- [ ] Strict invocation validation replacing `mock_all_auths()`
- [ ] Over-privileged signature & wildcard permission detector
- [ ] Multi-contract integration scenarios (Atomic Swaps, Liquidity Vaults)
- [ ] CLI export tools and CI test reporters

## License

Apache-2.0 or MIT
