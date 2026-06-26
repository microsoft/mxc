# Bubblewrap (bwrap) Backend for MXC — Feasibility Evaluation

## What is Bubblewrap?

[Bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) is a lightweight, unprivileged
sandboxing tool for Linux. It uses Linux kernel namespaces (user, mount, PID, network, IPC, UTS)
to create sandboxed environments *without* requiring root privileges or a container runtime like
LXC. It's the same technology backing Flatpak sandboxing.

Key advantages over LXC for MXC:
- **No root required** — runs as unprivileged user (uses user namespaces)
- **No daemon or rootfs** — no `lxc-create`, no distribution download, instant startup
- **Single-binary dependency** — just `bwrap` on PATH
- **Fine-grained mount control** — `--ro-bind`, `--bind`, `--tmpfs`, `--dev`, etc.
- **Network namespace isolation** — `--unshare-net` blocks all networking trivially
- **Simpler lifecycle** — no container create/start/stop/destroy; it's just a process

## Architecture Assessment

### How it fits the MXC model

MXC's `ScriptRunner` trait requires only:
```rust
fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse;
```
Plus optional `validate_runner()`. This is a perfect fit for bwrap, which is fundamentally
"run a command in a namespace sandbox" — a single `std::process::Command` invocation.

### Comparison with existing Linux backend (LXC)

| Aspect | LXC | Bubblewrap |
|--------|-----|------------|
| Privileges | Root required | Unprivileged (user namespaces) |
| Rootfs | Downloads distro rootfs | Bind-mounts host filesystem |
| Startup | Create → Start → Attach | Single `bwrap` exec |
| Network isolation | iptables + veth | `--unshare-net` (no network stack) |
| Network filtering | Per-host allow/block via iptables | `--unshare-net` for full block; iptables (reuses `NetworkIptablesManager`) for per-host filtering |
| Filesystem policy | LXC mount entries | `--ro-bind`, `--bind`, `--tmpfs` |
| Signal cleanup | Kill container on SIGTERM | Process dies with parent |
| Dependencies | `lxc-*` tools, rootfs templates | Single `bwrap` binary |

## Implementation Plan

### 1. Schema Changes

**File:** `schemas/dev/mxc-config.schema.0.6.0-dev.json`

Add `"bubblewrap"` to the `containment` enum:
```json
"containment": {
  "enum": ["process", "processcontainer", "windows_sandbox", "lxc", "microvm",
           "wslc", "seatbelt", "isolation_session", "bubblewrap"]
}
```

No backend-specific config block for now. Bubblewrap will use only the shared
cross-backend fields (`filesystem`, `network`, `process`, `lifecycle`, `ui`).
Adding backend-specific knobs later would mean introducing a dedicated section
plus updating the parser's single-backend-section enforcement so it's allowed.

### 2. Rust Model Changes

**File:** `src/core/wxc_common/src/models.rs`

```rust
// Add to ContainmentBackend enum:
/// Bubblewrap — unprivileged Linux sandboxing via user namespaces.
/// Experimental — requires --experimental flag.
Bubblewrap,
```

No `BubblewrapConfig` struct needed for now — the runner uses only the shared
`ContainerPolicy` fields on `ExecutionRequest` (filesystem paths, network policy, env, etc.).
A backend-specific config can be added later under `ExperimentalConfig` if needed.

### 3. Config Parser Changes

**File:** `src/core/wxc_common/src/wire.rs` and `config_parser.rs`

- Add a `Bubblewrap` variant to the wire `Containment` enum (or rely on the
  abstract `process` intent resolving to `Bubblewrap` on Linux)
- Add any backend-specific fields to the wire model (under `experimental` while
  experimental), then regenerate the schema with `mxc_schema_gen`
- Map the new `containment` value in `map_wire_containment`
- Optionally: make `"process"` resolve to `Bubblewrap` on Linux when LXC is unavailable
  (or add a `"process"` → bwrap fallback chain)

### 4. New Crate: `bwrap_common`

**Pattern follows:** `backends/lxc/common/` and `backends/seatbelt/common/`

```
src/backends/bubblewrap/common/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── bwrap_runner.rs        # BubblewrapScriptRunner
│   ├── bwrap_command.rs       # Command builder for bwrap CLI
│   └── filesystem_policy.rs   # Maps ContainerPolicy → bwrap mount args
```

**Cargo.toml:**
```toml
[package]
name = "bwrap_common"
version = "0.1.0"
edition = "2021"

[dependencies]
wxc_common = { workspace = true }
lxc_common = { workspace = true }
nix = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
```

Add `bwrap_common` to workspace `members` in `src/Cargo.toml`.

### 5. BubblewrapScriptRunner Implementation

Core design — translate `ExecutionRequest` into a `bwrap` command line:

```rust
pub struct BubblewrapScriptRunner;

impl ScriptRunner for BubblewrapScriptRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        // Check bwrap is on PATH
        // Check user namespaces are enabled (cat /proc/sys/kernel/unprivileged_userns_clone)
        // Validate filesystem paths exist
        // Reject allowedHosts/blockedHosts (not supported by bwrap)
    }

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        let mut cmd = std::process::Command::new("bwrap");

        // Namespace isolation (all unshared by default)
        cmd.arg("--unshare-user");
        cmd.arg("--unshare-pid");
        cmd.arg("--unshare-ipc");
        cmd.arg("--unshare-uts");

        // Network: use --unshare-net only when full block with no host lists
        let has_host_rules = !request.policy.allowed_hosts.is_empty()
            || !request.policy.blocked_hosts.is_empty();
        let use_unshare_net = request.policy.default_network_policy == NetworkPolicy::Block
            && !has_host_rules;
        if use_unshare_net {
            cmd.arg("--unshare-net");
        }

        // Base filesystem: bind-mount host root read-only
        cmd.args(["--ro-bind", "/", "/"]);

        // Apply filesystem policy from request.policy
        for path in &request.policy.readwrite_paths {
            cmd.args(["--bind", path, path]);
        }
        for path in &request.policy.readonly_paths {
            cmd.args(["--ro-bind", path, path]);
        }
        for path in &request.policy.denied_paths {
            cmd.args(["--tmpfs", path]);  // Mask with empty tmpfs
        }

        // /dev, /proc, /tmp
        cmd.args(["--dev", "/dev"]);
        cmd.args(["--proc", "/proc"]);
        cmd.args(["--tmpfs", "/tmp"]);

        // Working directory
        cmd.args(["--chdir", &request.working_directory]);

        // Environment
        cmd.arg("--clearenv");
        for env_str in &request.env {
            if let Some((k, v)) = env_str.split_once('=') {
                cmd.args(["--setenv", k, v]);
            }
        }

        // The command to run
        cmd.args(["--", "sh", "-c", &request.script_code]);

        // Execute with timeout
        let output = cmd.output();
        // ... map to ScriptResponse
    }
}
```

**Policy mapping details:**

| MXC Policy | bwrap Flag | Notes |
|------------|-----------|-------|
| `readwritePaths` | `--bind <src> <dest>` | RW bind mount |
| `readonlyPaths` | `--ro-bind <src> <dest>` | RO bind mount |
| `deniedPaths` | `--tmpfs <path>` | Mask with empty tmpfs |
| `network: block` | `--unshare-net` | No network at all |
| `network: allow` | (omit `--unshare-net`) | Full host network |
| `allowedHosts/blockedHosts` | iptables via `NetworkIptablesManager` | Reuses LXC approach; requires root |
| `ui.disable: true` | N/A | No X11/Wayland socket bind |

### 6. Binary Integration (add to `lxc-exec`)

The `lxc-exec` binary already dispatches by `ContainmentBackend` and falls back to LXC.
Adding a `ContainmentBackend::Bubblewrap` arm keeps the SDK binary-resolution unchanged
(Linux → `lxc-exec`) and avoids new `findBwrapExecutable()` / `platform.ts` plumbing.

```rust
// In lxc/src/main.rs, match request.containment:
ContainmentBackend::Bubblewrap => {
    if !request.experimental_enabled {
        eprintln!("Error: Bubblewrap is experimental. Use --experimental.");
        process::exit(1);
    }
    Box::new(BubblewrapScriptRunner)
}
```

Add `bwrap_common` dependency to `lxc/Cargo.toml`.

### 7. SDK / TypeScript Changes

**`sdk/src/types.ts`:**
```typescript
export type ContainmentBackend =
  | 'processcontainer' | 'windows_sandbox' | 'wslc'
  | 'lxc' | 'microvm' | 'seatbelt' | 'isolation_session'
  | 'bubblewrap';  // ← add

export const ExperimentalBackends = ['microvm', 'wslc', 'seatbelt', 'bubblewrap'];
```

**`sdk/src/platform.ts`:**
```typescript
// In getPlatformSupport() Linux block:
if (platform === 'linux') {
    const methods: string[] = [];
    if (isLxcAvailable()) methods.push('lxc');
    if (isBubblewrapAvailable()) methods.push('bubblewrap');
    if (methods.length > 0) {
        support.isSupported = true;
        support.availableMethods = methods;
    } else {
        support.reason = 'Neither LXC nor Bubblewrap is available';
    }
}

function isBubblewrapAvailable(): boolean {
    try {
        execSync('bwrap --version', { encoding: 'utf-8', stdio: 'pipe' });
        return true;
    } catch { return false; }
}
```

**`sdk/src/sandbox.ts`:**
Add a `buildBubblewrapConfig()` builder function (similar to `buildLinuxProcessConfig()`).

**`sdk/src/helper.ts`:**
No changes needed — `lxc-exec` handles both LXC and Bubblewrap backends, so the existing
Linux binary resolution path works as-is.

### 8. Network Policy — iptables (consistent with LXC)

Bubblewrap provides all-or-nothing network isolation via `--unshare-net`. For per-host
allow/block filtering, the runner reuses `NetworkIptablesManager` from `lxc_common` — the
same iptables-based approach used by the LXC backend.

**How it works:**

1. When `network.defaultPolicy` is `"block"` **and** no `allowedHosts`/`blockedHosts` are
   specified, use `--unshare-net` for zero-overhead full isolation (no iptables needed).

2. When `allowedHosts` or `blockedHosts` are specified, **do not** use `--unshare-net`
   (the sandbox shares the host network namespace). Instead:
   - Discover the bwrap child PID
   - Create a per-sandbox iptables chain via `NetworkIptablesManager`
   - Apply allow/block rules scoped to the sandbox process using `--pid-owner` match
     or cgroup-based scoping
   - Clean up rules after execution

3. When `network.defaultPolicy` is `"allow"` with no host lists, omit `--unshare-net`
   (full host network access, no iptables needed).

**Note:** iptables requires root, which partially reduces the "unprivileged" advantage of
bwrap for configs that use host-level network filtering. This is an acceptable trade-off
for consistency with the LXC backend. Configs that only need all-or-nothing network policy
still run fully unprivileged.

**Implementation:** The `BubblewrapScriptRunner` imports `NetworkIptablesManager` from
`lxc_common` (add `lxc_common` as a dependency of `bwrap_common`). The lifecycle mirrors
the LXC runner: apply rules before execution, remove rules after.

### 9. Test Additions

- Unit tests in `bwrap_common/src/bwrap_runner.rs` (command-line generation, policy mapping)
- Test config files in `tests/configs/` (e.g., `bubblewrap_basic.json`)
- E2E test in `wxc_e2e_tests` if applicable
- Script in `tests/scripts/run_bwrap_tests.sh`

### 10. Documentation

- `docs/bwrap-support/bubblewrap-backend.md` — user guide
- Update `docs/schema.md` — new containment value and config block
- Update `.github/copilot-instructions.md` — add to backend table
- Update `docs/authoring-a-new-feature.md` if the experimental feature checklist changes

## Effort Estimate (Complexity)

| Component | Complexity | Notes |
|-----------|-----------|-------|
| Schema + models | Low | Add enum value, config struct, wire through parser |
| BubblewrapScriptRunner | Medium | Core logic is straightforward (build bwrap CLI), but need PTY handling, timeout, signal forwarding |
| Filesystem policy mapping | Low | Direct 1:1 mapping to bwrap flags |
| Network policy | Low | Reuse `NetworkIptablesManager` from `lxc_common`; `--unshare-net` for full block |
| SDK TypeScript | Low | Add type, platform detection, builder function |
| Binary integration | Low | Add dispatch arm to lxc-exec |
| Tests | Medium | Need Linux environment with bwrap + user namespaces |
| Documentation | Low | Follow existing patterns |

**Overall: Medium complexity.** The core runner is simpler than LXC (no container lifecycle),
but PTY integration, timeout handling, and proper signal forwarding need care. The network
policy gap is a design decision, not an implementation challenge.

## Files to Touch (Summary)

### Rust (new)
- `src/backends/bubblewrap/common/Cargo.toml`
- `src/backends/bubblewrap/common/src/lib.rs`
- `src/backends/bubblewrap/common/src/bwrap_runner.rs`
- `src/backends/bubblewrap/common/src/bwrap_command.rs`
- `src/backends/bubblewrap/common/src/filesystem_policy.rs`

### Rust (modify)
- `src/Cargo.toml` — add `bwrap_common` to workspace members + dependencies
- `src/core/lxc/Cargo.toml` — add `bwrap_common` dependency
- `src/core/lxc/src/main.rs` — add dispatch arm for `ContainmentBackend::Bubblewrap`
- `src/core/wxc_common/src/models.rs` — add `Bubblewrap` variant, `BubblewrapConfig` struct, wire into `ExperimentalConfig` and `ExecutionRequest`
- `src/core/wxc_common/src/wire.rs` — add the `Bubblewrap` containment variant (and any backend fields), then regenerate the schema
- `src/core/wxc_common/src/config_parser.rs` — map the new containment value in `map_wire_containment`

### Schema (modify)
- `schemas/dev/mxc-config.schema.0.6.0-dev.json` — add `"bubblewrap"` to enum, add config block

### TypeScript (modify)
- `sdk/src/types.ts` — add `'bubblewrap'` to `ContainmentBackend`, `ExperimentalBackends`
- `sdk/src/platform.ts` — add `isBubblewrapAvailable()`, update Linux detection
- `sdk/src/sandbox.ts` — add `buildBubblewrapConfig()` builder
- `sdk/src/helper.ts` — no changes needed (lxc-exec handles both backends)

### Documentation (new/modify)
- `docs/bwrap-support/bubblewrap-backend.md` (new)
- `docs/schema.md` (modify)
- `.github/copilot-instructions.md` (modify — add to backend table)

### Tests (new)
- `tests/configs/bubblewrap_basic.json`
- `tests/scripts/run_bwrap_tests.sh`
