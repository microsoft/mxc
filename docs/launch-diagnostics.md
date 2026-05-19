# Launch Diagnostics: Surfacing Errors to Callers (#348)

## Problem

Two known errors are silently swallowed today:

1. **Packaged pwsh.exe** -- AppContainer/BaseContainer cannot launch packaged (MSIX) apps; the process just fails with a generic error.
2. **pwsh < 7.7-preview1 needs r/o access to `C:\`** -- unless the sandbox policy grants it, pwsh crashes on startup.

Neither is detected or reported as an actionable message to the user (copilot.exe).

## Design Goals

- Surface errors as **structured, actionable messages** with remediation guidance.
- Work for **both** one-shot (`spawnSandbox`) and state-aware flows.
- Allow the SDK caller (copilot.exe) to programmatically distinguish these errors from generic failures.
- **Zero overhead on the happy path** -- diagnostics run only after a launch failure.

---

## Implementation

### Phase 1: Rust -- Post-failure diagnostics (shared module)

**New file:** `src/wxc_common/src/launch_diagnostics.rs`

A shared diagnostics module that both runners call **after** a process-creation failure to enrich the error with actionable guidance:

```rust
pub struct LaunchDiagnostic {
    pub kind: &'static str,       // e.g. "packaged_app", "missing_filesystem_access"
    pub message: String,          // human-readable explanation
    pub remediation: String,      // actionable fix for the user
}

/// Attempts to diagnose *why* a process launch failed.
/// Returns `None` if no known condition is detected (the original error passes through unchanged).
pub fn diagnose_launch_failure(
    exe_path: &Path,
    readonly_paths: &[String],
    exit_code: Option<u32>,
) -> Option<LaunchDiagnostic> { ... }
```

**Checks (in order):**

1. **`packaged_app`** -- If the resolved exe path is under `C:\Program Files\WindowsApps\` (MSIX install location), return:
   - message: "The target executable is a packaged (MSIX) app which cannot run inside a sandboxed container."
   - remediation: "Uninstall the packaged version and install via `winget install Microsoft.PowerShell`."

2. **`missing_filesystem_access`** -- If the exe is `pwsh.exe` (not `powershell.exe`) and the policy does NOT grant `readonlyPaths` including the drive root (`C:\`), return:
   - message: "pwsh.exe versions before 7.7 require read-only access to the root drive to start."
   - remediation: "Add `C:\\` to `readonlyPaths` in your sandbox policy, or upgrade to pwsh 7.7+."

**Callers:**

- `appcontainer_runner.rs` -- after `CreateProcessW` fails or child exits non-zero.
- `base_container_runner.rs` -- after `Experimental_CreateProcessInSandbox` returns failure or child exits non-zero.

Both runners already return `ScriptResponse::error(...)` for failures, so this enriches existing error paths without changing control flow.

### Phase 2: Rust -- Structured error envelope for one-shot flows

**File:** `src/wxc/src/main.rs`

When a `ScriptResponse` contains a diagnostic, emit a JSON error envelope on **stderr**:

```json
{"error": {"code": "backend_error", "message": "...", "details": {"kind": "packaged_app", "remediation": "..."}}}
```

This reuses `MxcErrorCode::BackendError` with a `details.kind` discriminator. The existing human-readable stderr text continues to be emitted for direct CLI users.

### Phase 3: SDK -- Parse structured errors from one-shot flows

**File:** `sdk/src/sandbox.ts`

- Non-PTY path: after child exits non-zero, scan stderr for a JSON `{"error": {...}}` line. If found, throw `MxcError`.
- PTY path (merged stdout/stderr): scan combined output for the error envelope. If found, throw `MxcError`.
- Fallback: existing behavior (return exit code + raw output).

### Phase 4: Tests and documentation

1. Unit tests in `src/wxc_common/` for the detection heuristics.
2. Test config under `test_configs/` that triggers the packaged-app detection (manual validation).
3. This document serves as the feature's design reference.

---

## Detection Heuristics

### Packaged app detection

```rust
fn is_packaged_app(exe_path: &Path) -> bool {
    let normalized = exe_path.to_string_lossy().to_lowercase();
    normalized.contains("\\windowsapps\\")
}
```

### Missing filesystem access (pwsh root drive)

```rust
fn missing_root_readonly(exe_path: &Path, readonly_paths: &[String]) -> bool {
    let filename = exe_path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
    if filename != "pwsh.exe" { return false; }
    let root = format!("{}\\", &exe_path.to_string_lossy()[..2]);
    !readonly_paths.iter().any(|p| p.eq_ignore_ascii_case(&root) || p == "\\")
}
```

Version detection is deferred -- the simpler heuristic is path + filename based. Note from @asklar: this does not apply to `powershell.exe` (inbox Windows PowerShell 5.x), only to `pwsh.exe` < 7.7.

---

## Open Questions

1. **New error code vs `backend_error` + details?** Adding a first-class code (e.g. `launch_diagnostic`) requires both Rust and SDK changes to the closed union. Using `backend_error` + `details.kind` is additive-only.
2. **PTY path reliability** -- In PTY mode stdout/stderr are merged. Should the envelope use a unique prefix (e.g., `MXC_ERROR:`) for reliable parsing?
3. **pwsh version detection** -- Is it worth spawning `pwsh --version` post-failure, or is path-based detection sufficient?
