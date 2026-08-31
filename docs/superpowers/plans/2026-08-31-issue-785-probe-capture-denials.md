# Issue 785 Probe Capture-Denials Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `wxc-exec --probe` use the current runtime's request-aware ProcessContainer tier selection and report native capture availability without rejecting guarded-WPR fallback.

**Architecture:** Pass the complete `ExecutionRequest` from the CLI probe path into `appcontainer_common::probe`. Gather the same request-specific BaseContainer inputs used by the dispatcher, route them through a small pure helper around `detect_with_base_container_capabilities`, and expose native PSEC plus Learning Mode usability as an always-present probe fact.

**Tech Stack:** Rust 1.93, serde/serde_json, MXC `appcontainer_common`, Cargo test/clippy/rustfmt

---

## File map

- Modify `src/backends/appcontainer/common/src/probe.rs`: accept the full request, add the native-capture fact, add a deterministic decision helper, and extend unit coverage.
- Modify `src/core/wxc/src/main.rs`: retain and pass the loaded `ExecutionRequest` through the `--probe` fast path.

### Task 1: Add failing request-aware probe tests

**Files:**
- Modify: `src/backends/appcontainer/common/src/probe.rs:183-346`

- [ ] **Step 1: Add a test request helper and the native-capture serialization assertion**

Add this helper at the start of `mod tests`:

```rust
fn request_with_policy(policy: ContainerPolicy) -> ExecutionRequest {
    ExecutionRequest {
        policy,
        ..Default::default()
    }
}
```

Add `native_capture_available` to both existing `ProbeFacts` test fixtures:

```rust
native_capture_available: true,
```

and

```rust
native_capture_available: false,
```

Then assert the camel-case JSON field in `probe_output_serializes`:

```rust
assert_eq!(v["probes"]["nativeCaptureAvailable"], true);
```

- [ ] **Step 2: Add tests for capability-driven tier selection and guarded-WPR fallback**

Add tests against the planned internal helper:

```rust
#[test]
fn request_capabilities_control_base_container_selection() {
    let request = ExecutionRequest::default();
    let probes = test_probe_facts(false);

    let selected = run_probe_with_capabilities(&request, probes, true, true);
    assert_eq!(selected.tier, Some("base-container"));
    assert!(selected.error.is_none());
}

#[test]
fn capture_denials_remains_launchable_on_appcontainer_fallback() {
    let _guard = ForceTierGuard::set_tier(IsolationTier::AppContainerDacl);
    let mut policy = ContainerPolicy::default();
    policy.capture_denials = Some(Default::default());
    let request = request_with_policy(policy);

    let output = run_probe_with_capabilities(
        &request,
        test_probe_facts(false),
        false,
        false,
    );

    assert_eq!(output.tier, Some("appcontainer-dacl"));
    assert_eq!(output.probes.native_capture_available, false);
    assert!(output.error.is_none());
}
```

Factor the repeated fixture into:

```rust
fn test_probe_facts(native_capture_available: bool) -> ProbeFacts {
    ProbeFacts {
        base_container_api_present: true,
        native_capture_available,
        bfscfg_present: false,
        bfs_compiled_in: false,
        base_container_supports_deny_paths: false,
        isolation_session_available: false,
        hyperlight_available: false,
        ui_capabilities: all_ui_capabilities(),
    }
}
```

Update existing `run_probe` test calls to pass `&ExecutionRequest` by using
`request_with_policy`.

- [ ] **Step 3: Run the focused tests and confirm they fail for the missing API**

Run from `src\`:

```powershell
cargo test -p appcontainer_common probe::tests -- --nocapture
```

Expected: compilation fails because `ProbeFacts::native_capture_available` and
`run_probe_with_capabilities` do not exist and `run_probe` still accepts
`&ContainerPolicy`.

### Task 2: Implement request-aware probe selection

**Files:**
- Modify: `src/backends/appcontainer/common/src/probe.rs:14-180`
- Modify: `src/core/wxc/src/main.rs:757-774`

- [ ] **Step 1: Change the probe API and add the native capability fact**

In `probe.rs`, import `ExecutionRequest`:

```rust
use wxc_common::models::ExecutionRequest;
```

Add this field immediately after `base_container_api_present`:

```rust
/// Whether the preferred native PSEC plus Learning Mode capture path is usable.
///
/// A false value does not mean `captureDenials` is unsupported: the executor
/// can use guarded WPR on a compatible fallback tier.
pub native_capture_available: bool,
```

Change the public signature and gather the request-aware inputs before building
the output:

```rust
pub fn run_probe(request: &ExecutionRequest) -> ProbeOutput {
    use crate::base_container_runner::BaseContainerRunner;

    let prefer_base_container = BaseContainerRunner::is_usable_for_request(request);
    let supports_deny_paths = BaseContainerRunner::supports_deny_paths_for_request(request);
    let probes = ProbeFacts {
        base_container_api_present: BaseContainerRunner::is_base_container_api_present().is_ok(),
        native_capture_available: BaseContainerRunner::is_native_capture_available(),
        bfscfg_present: fallback_detector::find_bfscfg_exe()
            .ok()
            .flatten()
            .is_some(),
        bfs_compiled_in: cfg!(feature = "tier2_bfs"),
        base_container_supports_deny_paths: supports_deny_paths,
        isolation_session_available: false,
        hyperlight_available: false,
        ui_capabilities: crate::job_object::supported_ui_restrictions().into(),
    };

    run_probe_with_capabilities(
        request,
        probes,
        prefer_base_container,
        supports_deny_paths,
    )
}
```

- [ ] **Step 2: Implement the pure detector adapter**

Move the existing `match` that builds `ProbeOutput` into:

```rust
fn run_probe_with_capabilities(
    request: &ExecutionRequest,
    probes: ProbeFacts,
    prefer_base_container: bool,
    supports_deny_paths: bool,
) -> ProbeOutput {
    match fallback_detector::detect_with_base_container_capabilities(
        &request.policy,
        prefer_base_container,
        prefer_base_container,
        supports_deny_paths,
    ) {
        Ok(decision) => ProbeOutput {
            tier: Some(decision.tier.as_str()),
            needs_dacl_augmentation: Some(decision.needs_dacl_augmentation),
            warnings: decision.warnings,
            probes,
            error: None,
        },
        Err(error) => ProbeOutput {
            tier: None,
            needs_dacl_augmentation: None,
            warnings: vec![],
            probes,
            error: Some(format_fallback_error(&error)),
        },
    }
}
```

Do not add a `captureDenials` rejection. The current `wxc-exec` runtime always
supplies `factory_for_request(request)`, so native-capture unavailability routes
to guarded WPR rather than making tier selection fail.

- [ ] **Step 3: Preserve the complete request in the CLI probe path**

Replace the policy-only local in `src/core/wxc/src/main.rs`:

```rust
let request = if let Some((data, is_b64)) = config_input(&cli) {
    let mut probe_logger = Logger::new(Mode::Buffer);
    match load_request(&data, &mut probe_logger, is_b64) {
        Ok(request) => request,
        Err(_) => {
            eprintln!("Error: failed to load probe config");
            eprint!("{}", probe_logger.get_buffer());
            process::exit(1);
        }
    }
} else {
    wxc_common::models::ExecutionRequest::default()
};
let output = appcontainer_common::probe::run_probe(&request);
```

Keep the existing IsolationSession and Hyperlight fact overrides unchanged.

- [ ] **Step 4: Run the focused tests and confirm they pass**

Run from `src\`:

```powershell
cargo test -p appcontainer_common probe::tests -- --nocapture
```

Expected: all `probe::tests` pass.

- [ ] **Step 5: Commit the implementation**

```powershell
git add -- src/backends/appcontainer/common/src/probe.rs src/core/wxc/src/main.rs
git commit -m "fix: align capture-denials probe with runtime" -m "Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>"
```

### Task 3: Validate the Rust change

**Files:**
- Verify: `src/backends/appcontainer/common/src/probe.rs`
- Verify: `src/core/wxc/src/main.rs`

- [ ] **Step 1: Check formatting**

Run from `src\`:

```powershell
cargo fmt --all -- --check
```

Expected: exit code 0 with no formatting differences.

- [ ] **Step 2: Run all appcontainer unit tests**

Run from `src\`:

```powershell
cargo test -p appcontainer_common
```

Expected: all tests pass.

- [ ] **Step 3: Run targeted lint checks**

Run from `src\`:

```powershell
cargo clippy -p appcontainer_common -p wxc --all-targets -- -D warnings
```

Expected: exit code 0 with no warnings.

- [ ] **Step 4: Inspect the final diff**

Run:

```powershell
git diff main...HEAD --check
git status --short
```

Expected: no whitespace errors; only the committed design, plan, and
implementation files are present.

### Task 4: Run requested independent reviews

**Files:**
- Review: `src/backends/appcontainer/common/src/probe.rs`
- Review: `src/core/wxc/src/main.rs`

- [ ] **Step 1: Run the Rust review skill**

Invoke `/rust-review` against the implementation diff. Address every confirmed
correctness, safety, API, testing, or maintainability finding, then rerun the
smallest affected test and formatting check.

- [ ] **Step 2: Run the adversarial rubber-duck review**

Invoke `/rubber-duck-quick` against the final diff and the Issue #785 contract.
Address confirmed findings and rerun the smallest affected validation.

- [ ] **Step 3: Confirm the working tree state**

Run:

```powershell
git status --short
git log -3 --oneline
```

Expected: the implementation and any review fixes are committed, with no
unexpected working-tree changes.
