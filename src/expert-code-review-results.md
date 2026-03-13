# Expert Code Review — `src/` (wxc workspace)

**Review Date**: 2026-03-13
**Methodology**: expert-code-reviewer v2.1 — classify → route → expert analysis → signal-to-noise gate → synthesize
**Scope**: All Rust source files under `src/` (wxc, wxc_common, wxc_test_driver)

---

## Stage 1: Classification

| Attribute | Value |
|-----------|-------|
| **Language** | Rust |
| **Domains** | memory-safety, concurrency, security, error-handling, api-design, ffi-abi (Win32 FFI consumer) |
| **Change Type** | new-feature (full codebase review) |
| **Risk Score** | **0.73** |
| **Codebase** | ~1,500 lines across 14 source files in 3 crates |

### Risk Score Breakdown

```
Domain scores (estimated):
  memory-safety:  0.60 × weight 0.90 = 0.54   (unsafe code present, RAII guards well-structured)
  concurrency:    0.40 × weight 0.85 = 0.34   (thread::spawn with straightforward patterns)
  security:       0.60 × weight 0.95 = 0.57   (AppContainer + firewall; DNS TOCTOU gap)
  error-handling: 0.50 × weight 0.50 = 0.25   (validation gaps, silent failures)
  api-design:     0.40 × weight 0.60 = 0.24   (reasonable trait design, minor gaps)
  ffi-abi:        0.50 × weight 0.90 = 0.45   (#[repr(C)] structs, extensive Win32 API usage)

base_risk = 2.39 / 4.70 = 0.508
change_type_multiplier = 1.0 (new-feature)
size_factor = 1.2 (200–500 lines in core modules)
cross_file_factor = 1.2 (5–10 files with cross-module dependencies)

risk_score = 0.508 × 1.0 × 1.2 × 1.2 = 0.73
```

---

## Stage 2: Routing

| Attribute | Value |
|-----------|-------|
| **Path** | **Deep Path** (risk ≥ 0.70) |
| **Skills Applied** | rust-unsafe-safety, rust-async-concurrency, rust-error-handling, rust-api-design, rust-ffi-abi |
| **Expert Patterns Consulted** | Daniel Prilik (unsafe-safety, api-design), Jason Rahman (error-handling, concurrency), Kevin Bocksrocker (concurrency), Chris Oo (unsafe-safety), Sander Saares (unsafe-safety, error-handling) |

### Risk Triggers Activated

| Trigger | Signal | Files |
|---------|--------|-------|
| `t_unsafe_change` | `unsafe` blocks with raw pointer manipulation, `FreeSid`, `LocalFree`, `CreateProcessW` | appcontainer.rs, process_util.rs, string_util.rs, network_firewall.rs |
| `t_send_sync` | `unsafe impl Send for SendOwnedHandle` | process_util.rs:29 |
| `t_ffi_boundary` | `#[repr(C)]` structs passed to Win32 APIs, `PSID` manipulation | appcontainer.rs:45–82 |

---

## Findings

### F1 — Invalid stdin handle passed to child process

| Attribute | Value |
|-----------|-------|
| **Severity** | **High** |
| **Confidence** | 0.88 |
| **Domain** | error-handling |
| **Skill** | rust-error-handling (Jason Rahman pattern) |
| **File** | `wxc_common/src/process_util.rs` |
| **Lines** | 251–264 |

**Summary**: `run_process_with_captured_output` creates stdin pipes but never connects them to the child process.

**Detail**: The function calls `create_std_pipes(false)` to create a stdin pipe pair (line 251), but the `STARTUPINFOW` struct never sets `hStdInput` (lines 258–264). Since `STARTF_USESTDHANDLES` is set, Windows will use the default-initialized `hStdInput` field (null handle). The child process will have an invalid stdin handle, which will cause any stdin read to fail immediately. The pipe handles are created and destroyed pointlessly.

**Fix**: Either set `si.hStdInput = stdin_read.get()` in the `STARTUPINFOW` initialization, or remove the unused stdin pipe creation entirely if child stdin is not needed.

```rust
// Option A: Connect the pipe
let mut si = STARTUPINFOW {
    cb: std::mem::size_of::<STARTUPINFOW>() as u32,
    dwFlags: STARTF_USESTDHANDLES,
    hStdInput: stdin_read.get(),    // <-- missing
    hStdOutput: stdout_write.get(),
    hStdError: stderr_write.get(),
    ..Default::default()
};

// Option B: Remove unused pipe
// Delete lines 251-252 entirely if stdin is not needed
```

---

### F2 — DNS-to-IP resolution is TOCTOU-vulnerable for firewall rules

| Attribute | Value |
|-----------|-------|
| **Severity** | **High** |
| **Confidence** | 0.85 |
| **Domain** | security |
| **Skill** | rust-unsafe-safety + rust-ffi-abi (Sander Saares security pattern) |
| **File** | `wxc_common/src/network_firewall.rs` |
| **Lines** | 146–158 |

**Summary**: Hostname-to-IP resolution happens at rule creation time, but DNS may return different IPs later.

**Detail**: `process_host_list` resolves hostnames to IPs via `resolve_hostname` and creates firewall rules targeting those IPs. This has two security implications:

1. **DNS rebinding**: An attacker controlling a hostname in `allowed_hosts` could initially resolve to a benign IP (passing validation) and later change DNS to a malicious IP. The firewall rule targets the original IP, so this isn't directly exploitable in the _allow_ direction — but in the _block_ direction, a blocked host could change IPs to evade the block rule.

2. **Multi-IP hosts**: `resolve_hostname` takes only the first IP from `to_socket_addrs()`. Hosts behind load balancers or CDNs may have multiple IPs; the firewall rule covers only one, leaving traffic to other IPs unrestricted.

**Fix**: Consider resolving periodically, or document this limitation. For block rules, consider using Windows Firewall's native hostname-based blocking if available, or resolving all returned IPs.

---

### F3 — `catch_unwind(AssertUnwindSafe(...))` may run cleanup on corrupted state

| Attribute | Value |
|-----------|-------|
| **Severity** | **Medium** |
| **Confidence** | 0.82 |
| **Domain** | error-handling |
| **Skill** | rust-error-handling (Adam Prout shutdown-ordering pattern) |
| **File** | `wxc_common/src/script_runner.rs` |
| **Lines** | 51–56 |

**Summary**: Panic recovery wraps `run_internal` with `AssertUnwindSafe`, then proceeds to run firewall and BFS cleanup on potentially inconsistent state.

**Detail**: If `run_internal` panics (e.g., inside `AppContainerScriptRunner::run_internal_impl`), the `catch_unwind` catches it and the template method proceeds to run cleanup code (firewall rule removal on line 58–60, BFS policy removal on line 61–63). Since `AssertUnwindSafe` suppresses unwind safety checks, `self`, `fw_manager`, and `bfs_manager` may be in an inconsistent state after the panic. Firewall rule removal calls COM methods; BFS removal spawns external processes. Running these on corrupted state could leave orphaned firewall rules or fail silently.

**Fix**: Consider whether cleanup should be attempted at all after a panic. If cleanup is important, isolate it behind its own error boundary:
```rust
Err(_) => {
    // Best-effort cleanup — each step independently guarded
    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if fw_manager.rules_applied() && request.policy.remove_firewall_rules_on_exit {
            let _ = fw_manager.remove_firewall_rules(logger);
        }
    }));
    ScriptResponse::error("Unknown error during script execution.")
}
```

---

### F4 — Capability SID failures silently degrade container security posture

| Attribute | Value |
|-----------|-------|
| **Severity** | **Medium** |
| **Confidence** | 0.80 |
| **Domain** | security |
| **Skill** | rust-unsafe-safety (Daniel Prilik pattern) |
| **File** | `wxc_common/src/appcontainer.rs` |
| **Lines** | 180–196 |

**Summary**: When `get_capability_sid_from_name` fails for a capability, the error is logged as a warning and the capability is silently skipped.

**Detail**: The loop iterates over `capabilities_to_add` and calls `get_capability_sid_from_name` for each. On failure, it logs a warning and continues (lines 189–195). This means the AppContainer process may launch with fewer capabilities than the caller requested. In particular, if the `AgenticAppContainer` capability (always added on line 162) fails, the container runs without its primary capability — silently degrading the security model. The caller (`ScriptRunner::run`) has no way to detect that the process launched with a reduced capability set.

**Fix**: Consider distinguishing between optional and required capabilities. At minimum, fail if the mandatory `AgenticAppContainer` capability cannot be resolved. Optionally, return a list of successfully applied capabilities so the caller can make an informed decision.

---

### F5 — `test_for_root_path` only recognizes `C:\` as a root path

| Attribute | Value |
|-----------|-------|
| **Severity** | **Medium** |
| **Confidence** | 0.85 |
| **Domain** | api-design |
| **Skill** | rust-api-design (Rob Day naming/semantics pattern) |
| **File** | `wxc_common/src/filesystem_bfs.rs` |
| **Lines** | 171–173 |

**Summary**: The function name implies generic root-path detection, but it only checks for the literal string `"C:\\"`.

**Detail**: `test_for_root_path` returns `false` (no inheritance) only for `"C:\\"`. Paths like `"D:\\"`, `"E:\\"`, or UNC roots (`"\\\\server\\share"`) will return `true`, receiving the `--containerinherit` flag. This means BFS policies on non-C: drive roots will apply inheritance, which may be overly permissive. On multi-drive systems, this could grant broader filesystem access than intended.

**Fix**: Generalize the root-path check:
```rust
fn test_for_root_path(path: &str) -> bool {
    // Drive root: single letter + ":\\"
    if path.len() == 3
        && path.as_bytes()[0].is_ascii_alphabetic()
        && &path[1..] == ":\\"
    {
        return false;
    }
    true
}
```

---

### F6 — `validate_request` performs minimal validation

| Attribute | Value |
|-----------|-------|
| **Severity** | **Medium** |
| **Confidence** | 0.78 |
| **Domain** | error-handling |
| **Skill** | rust-error-handling (Sander Saares holistic design pattern) |
| **File** | `wxc_common/src/validator.rs` |
| **Lines** | 4–11 |

**Summary**: Request validation only checks that `script_code` is non-empty, missing several security-relevant checks.

**Detail**: The validator does not check:
- **`working_directory`**: If non-empty, it should exist and be accessible. Passing a non-existent directory to `CreateProcessW` will cause a runtime failure rather than a clean validation error.
- **`app_container_name`**: No length or character validation. Windows `CreateAppContainerProfile` has constraints on valid names.
- **`script_timeout`**: No upper bound. Very large values (close to `u32::MAX`) could effectively disable timeouts (the `get_timeout_milliseconds` function maps `0 → u32::MAX`, but a user could pass `u32::MAX - 1` directly).
- **Filesystem paths**: No check for path traversal patterns (e.g., `..\\..\\`) that could escape intended boundaries.

**Fix**: Add validation for security-sensitive fields. At minimum, validate `app_container_name` length/characters and ensure `working_directory` (if provided) is an absolute path.

---

### F7 — `unsafe impl Send for SendOwnedHandle` lacks structured SAFETY comment

| Attribute | Value |
|-----------|-------|
| **Severity** | **Low** |
| **Confidence** | 0.80 |
| **Domain** | memory-safety |
| **Skill** | rust-unsafe-safety (Chris Oo SAFETY comment template pattern) |
| **File** | `wxc_common/src/process_util.rs` |
| **Lines** | 28–29 |

**Summary**: The `unsafe impl Send` has a doc comment explaining the rationale, but does not follow the standard `// SAFETY:` comment convention.

**Detail**: The comment on line 28 ("SAFETY: Windows HANDLEs are process-wide and safe to use from any thread.") is in a doc comment (`///`) rather than the conventional `// SAFETY:` format placed directly above the `unsafe` keyword. The rationale is correct — Windows HANDLEs are indeed process-wide kernel objects and are safe to send across threads. This is a documentation convention issue, not a correctness bug.

**Fix**: Use the standard format:
```rust
// SAFETY: Windows HANDLEs are process-wide kernel objects identified by
// pointer-sized values. They can safely be used from any thread in the process.
unsafe impl Send for SendOwnedHandle {}
```

---

### F8 — `suppress_python_location_error` only removes first occurrence

| Attribute | Value |
|-----------|-------|
| **Severity** | **Low** |
| **Confidence** | 0.75 |
| **Domain** | error-handling |
| **Skill** | rust-error-handling |
| **File** | `wxc_common/src/process_util.rs` |
| **Lines** | 177–186 |

**Summary**: The function removes only the first occurrence of the Python location error, but the error could appear multiple times in stderr.

**Detail**: `suppress_python_location_error` uses `find()` to locate the first instance of `"Failed to find real location of "` and removes that single line. If the Python process emits this error multiple times (e.g., for multiple modules), subsequent occurrences remain in the output. This is a minor robustness issue — the function's intent is to clean up noisy Python stderr, but it only partially achieves this.

**Fix**: Use a loop or `retain`-style approach to remove all occurrences.

---

## Risk Assessment

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| **Code Safety** | 0.55 | Extensive `unsafe` code, but well-structured with RAII guards (`OwnedHandle`, `CapabilitySidGuard`, `AttrListGuard`). Raw pointer usage is contained within clear boundaries. |
| **Concurrency** | 0.35 | Thread spawning with `join` coordination. `SendOwnedHandle` correctly transfers handle ownership. No complex async patterns or lock ordering concerns. |
| **API Surface** | 0.40 | Public API is reasonable. `ScriptRunner` trait provides clean template method. Minor gaps in validation and naming. |
| **Security Boundary** | 0.65 | AppContainer sandboxing is the core purpose. DNS TOCTOU gap in firewall rules. Silent degradation of capability set. Minimal input validation at trust boundary. |

| Attribute | Value |
|-----------|-------|
| **Overall Risk** | **Medium-High** |
| **Risk Score** | **0.73** |
| **Human Review Recommended** | **Yes** |
| **Confidence** | 0.80 |

### HITL Rationale

Human review is recommended because:
1. Risk score is 0.70–0.85 AND change involves memory safety and security boundaries
2. The code manages Windows security primitives (AppContainers, firewall rules, SIDs) where correctness is critical
3. Two high-severity findings (F1, F2) affect correctness and security respectively
4. `unsafe` code is present across multiple files — even though it's well-structured, the RAII patterns and Win32 FFI interactions warrant expert verification

---

## Summary

**8 findings total**: 2 High, 4 Medium, 2 Low.

The codebase demonstrates good Rust practices overall — RAII wrappers for Windows HANDLEs and SIDs, clear separation of concerns via the `ScriptRunner` trait, proper `#[repr(C)]` for Win32 FFI structs, and defense-in-depth security controls (AppContainer + filesystem BFS + network firewall).

**Key issues requiring attention:**
1. **F1 (High)**: `run_process_with_captured_output` creates stdin pipes but never connects them to the child process, resulting in an invalid stdin handle.
2. **F2 (High)**: DNS resolution for firewall rules is subject to TOCTOU — blocked hosts can evade rules by changing IPs; multi-IP hosts are only partially covered.
3. **F4 (Medium)**: Capability SID resolution failures are silently ignored, which could result in the AppContainer running with a weaker-than-expected security posture.
4. **F5 (Medium)**: Root path detection is hardcoded to `C:\`, causing incorrect BFS inheritance on other drive letters.

### Tool Escalation

| Check | Tier | Rationale |
|-------|------|-----------|
| `cargo clippy -- -D warnings` | Baseline | Standard lint pass for all Rust code |
| `cargo test` | Baseline | Existing test suite covers config parsing, validation, string utils, network validation |
| Miri (targeted) | Recommended | Run on `process_util` and `string_util` unsafe code to verify no UB |
| Manual security review | Recommended | AppContainer + firewall rule creation involves security-critical Win32 API sequences |

---

*Generated by expert-code-reviewer v2.1 — Deep Path review with 5 expert skill patterns applied.*
