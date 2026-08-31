# NanVix `blockedHosts` Default-Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent a NanVix `blockedHosts` list from widening a `defaultPolicy=block` request into allow-by-default networking.

**Architecture:** Keep enforcement inside the NanVix runner. Validation rejects the incompatible policy, while `host_networking_enabled` independently excludes `blockedHosts` as an opt-in signal so the boundary remains fail-safe if validation is bypassed.

**Tech Stack:** Rust 2021, MXC `wxc_common` policy model, Rust unit tests, Markdown documentation

---

## File Structure

- Modify `src/backends/nanvix/runner/src/lib.rs`: define the diagnostic, enforce the policy invariant, make network enablement fail-safe, and update unit tests.
- Modify `docs/nanvix-microvm/nanvix.md`: document the valid default-policy and host-list combinations.

### Task 1: Enforce the NanVix Blocklist Contract

**Files:**
- Modify: `src/backends/nanvix/runner/src/lib.rs:36-42`
- Modify: `src/backends/nanvix/runner/src/lib.rs:102-118`
- Modify: `src/backends/nanvix/runner/src/lib.rs:522-533`
- Modify: `src/backends/nanvix/runner/src/lib.rs:638-657`
- Test: `src/backends/nanvix/runner/src/lib.rs:1123-1178`

- [ ] **Step 1: Replace the permissive blocklist test with failing contract tests**

Replace `policy_accepts_blocklist_only` with tests equivalent to:

```rust
#[test]
fn policy_rejects_blocklist_with_block_default() {
    let request = ExecutionRequest {
        policy: ContainerPolicy {
            blocked_hosts: vec!["93.184.216.34".to_string()],
            ..Default::default()
        },
        ..Default::default()
    };

    let err = NanVixScriptRunner::validate_policies(&request).unwrap_err();
    assert!(
        err.to_string().contains(ERR_BLOCKED_HOSTS_REQUIRE_ALLOW),
        "blocklist with block default should be rejected, got: {}",
        err
    );
    assert!(!NanVixScriptRunner::host_networking_enabled(&request));
}

#[test]
fn policy_accepts_blocklist_with_allow_default() {
    let request = ExecutionRequest {
        policy: ContainerPolicy {
            default_network_policy: NetworkPolicy::Allow,
            blocked_hosts: vec!["93.184.216.34".to_string()],
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(NanVixScriptRunner::validate_policies(&request).is_ok());
    assert!(NanVixScriptRunner::host_networking_enabled(&request));
}
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```powershell
Set-Location src
cargo test -p nanvix_runner policy_rejects_blocklist_with_block_default
cargo test -p nanvix_runner policy_accepts_blocklist_with_allow_default
```

Expected: the first test fails because `ERR_BLOCKED_HOSTS_REQUIRE_ALLOW` and the rejection do not exist; the second preserves the supported allow-default behavior.

- [ ] **Step 3: Add the validation diagnostic and fail-safe helper**

Add:

```rust
const ERR_BLOCKED_HOSTS_REQUIRE_ALLOW: &str = concat!(
    "blockedHosts requires network.defaultPolicy = \"allow\" for the NanVix backend -- ",
    "a blocklist is allow-by-default and cannot be combined with a block default",
);
```

Change the helper to:

```rust
fn host_networking_enabled(request: &ExecutionRequest) -> bool {
    request.policy.default_network_policy == NetworkPolicy::Allow
        || !request.policy.allowed_hosts.is_empty()
}
```

After the existing both-lists check in `validate_policies`, add:

```rust
if !request.policy.blocked_hosts.is_empty()
    && request.policy.default_network_policy != NetworkPolicy::Allow
{
    return Err(NanVixError::Preflight(
        ERR_BLOCKED_HOSTS_REQUIRE_ALLOW.to_string(),
    ));
}
```

Update the module and helper comments to state that `allowedHosts` enables
filtered networking under a block default, while `blockedHosts` requires an
allow default.

- [ ] **Step 4: Run all NanVix runner unit tests**

Run:

```powershell
Set-Location src
cargo test -p nanvix_runner
```

Expected: all `nanvix_runner` tests pass.

- [ ] **Step 5: Commit the behavior change**

```powershell
git add src/backends/nanvix/runner/src/lib.rs
git commit -m "fix: preserve NanVix block-default networking"
```

### Task 2: Document the Supported Policy Matrix

**Files:**
- Modify: `docs/nanvix-microvm/nanvix.md`

- [ ] **Step 1: Update the per-host filtering contract**

Replace the statement that either list overrides `defaultPolicy` with:

```markdown
`allowedHosts` is an allowlist and is valid with the default `"block"` posture.
`blockedHosts` is a blocklist over allow-by-default networking and therefore
requires `defaultPolicy: "allow"`. A blocklist with a block default is rejected
at preflight rather than widening the requested network boundary.
```

Expand the policy table to include `defaultPolicy`:

```markdown
| `defaultPolicy` | `allowedHosts` | `blockedHosts` | Effect |
| --------------- | -------------- | -------------- | ------ |
| `block`         | _(empty)_      | _(empty)_      | no egress |
| `allow`         | _(empty)_      | _(empty)_      | unrestricted egress |
| `block`         | `[A, ...]`     | _(empty)_      | allowlist — only listed destinations are reachable |
| `allow`         | _(empty)_      | `[B, ...]`     | blocklist — every unlisted destination is reachable |
| `block`         | _(empty)_      | `[B, ...]`     | rejected at preflight |
| _either_        | `[A, ...]`     | `[B, ...]`     | rejected at preflight |
```

Add the rejected block-default/blocklist combination to the “Not Supported”
table.

- [ ] **Step 2: Check the documentation diff**

Run:

```powershell
git diff --check
git diff -- docs/nanvix-microvm/nanvix.md
```

Expected: no whitespace errors; the documentation consistently describes the new contract.

- [ ] **Step 3: Commit the documentation**

```powershell
git add docs/nanvix-microvm/nanvix.md
git commit -m "docs: clarify NanVix blocklist policy"
```

### Task 3: Validate and Review the Complete Fix

**Files:**
- Verify: `src/backends/nanvix/runner/src/lib.rs`
- Verify: `docs/nanvix-microvm/nanvix.md`

- [ ] **Step 1: Run Rust formatting**

Run:

```powershell
Set-Location src
cargo fmt --all -- --check
```

Expected: exit code 0.

- [ ] **Step 2: Run targeted Clippy**

Run:

```powershell
Set-Location src
cargo clippy -p nanvix_runner --all-targets -- -D warnings
```

Expected: exit code 0 with no warnings.

- [ ] **Step 3: Re-run the complete targeted test suite**

Run:

```powershell
Set-Location src
cargo test -p nanvix_runner
```

Expected: all `nanvix_runner` tests pass.

- [ ] **Step 4: Verify the final diff**

Run:

```powershell
git diff main...HEAD --check
git status --short
```

Expected: no whitespace errors and no uncommitted implementation changes.

- [ ] **Step 5: Run the requested review skills**

Invoke `/rust-review`, address any confirmed findings, re-run affected checks,
then invoke `/rubber-duck-quick` and address any confirmed findings.
