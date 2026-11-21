# Soroban AuthScope CLI & Integration Guide

`soroban-authscope` provides offline static and dynamic invocation tree analysis for Soroban smart contracts. It audits contract call trees, authorization scopes, parameter constraints, and cross-contract call hierarchies to detect missing or over-scoped authorization boundaries.

---

## 1. Quick Installation

```bash
cargo install --path .
```

Or run directly from source:
```bash
cargo run --bin authscope -- <COMMAND> [OPTIONS]
```

---

## 2. Basic Command-Line Usage

### Audit an Invocation Trace

```bash
authscope analyze examples/fixtures/token_transfer_trace.json
```

### Formats & Reporters

* **ASCII Tree (Default):**
  ```bash
  authscope analyze trace.json --format ascii
  ```
* **Markdown Audit Scorecard:**
  ```bash
  authscope analyze trace.json --format markdown > AUDIT_REPORT.md
  ```
* **Machine-Readable JSON Summary:**
  ```bash
  authscope analyze trace.json --format json
  ```
* **SARIF v2.1.0 for CI Code Scanning:**
  ```bash
  authscope analyze trace.json --format sarif > results.sarif
  ```

---

## 3. Policy Enforcement Rules

| Rule ID | Name | Description |
|---|---|---|
| `AUTH001` | `StrictAll` | Every node in the invocation DAG must have explicit authorization recorded. |
| `AUTH002` | `DisallowWildcards` | Flags any unbounded wildcard authorization scopes. |
| `AUTH003` | `MaxDepthExceeded` | Traversal terminates and flags recursion if depth exceeds threshold. |
| `AUTH004` | `MissingCallerAuth` | Ensures root entrypoints verify invoker address explicitly. |
