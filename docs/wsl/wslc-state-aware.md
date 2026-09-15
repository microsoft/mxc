# WSLc State-Aware Lifecycle

This document describes the **state-aware lifecycle** for the WSL Container (WSLc) backend:
the multi-invocation `provision → start → exec → stop → deprovision` surface that keeps a
container **warm** across separate `wxc-exec` phase processes, amortizing WSLc's high cold-start
cost.

It complements:

- [`wsl-container-support-plan.md`](wsl-container-support-plan.md) — the original one-shot backend design.
- [`../state-aware-lifecycle/mxc-state-aware-sandbox-api.md`](../state-aware-lifecycle/mxc-state-aware-sandbox-api.md) — the cross-backend state-aware wire format, the Rust `StatefulSandboxBackend` trait, and the dispatcher contract.

The WSLc state-aware surface is **experimental** — it requires `--experimental` and a build with
the `wslc` feature (`build.bat --with-wslc`).

## Why a daemon

The WSLc SDK (`wslcsdk.dll`, 2.9.9) has **no cross-process session re-attach**: every operation
(`WslcCreateContainer`, `WslcStartContainer`, `WslcCreateContainerProcess`, image pull, stop /
delete) requires a live in-process `WslcSession` / `WslcContainer` handle, and there is no
`WslcOpenSession`. State-aware runs each phase as a **separate**
`wxc-exec` invocation, so handles minted during `provision` cannot be reused by a later `exec`
or `deprovision` in a different process.

> SDK 2.9.9 added `WslcOpenContainer` (open an existing container by name, full ID, or unique ID
> prefix). That is a *container*-level primitive and still requires a live session handle in the
> calling process, so it does not by itself remove the need for the daemon. Whether a fresh
> per-phase session plus `WslcOpenContainer` could replace the warm-handle model has not been
> evaluated; the daemon remains the supported design.

To keep the session (VM) and container **warm** across phases, WSLc uses a **persistent per-user
daemon** (`wxc-wslc-daemon.exe`, crate `wxc_wslc_daemon` at `src/backends/wslc/daemon/`) that owns
the live SDK handles. Each phase process is a thin client that contacts the daemon over a named
pipe; the daemon performs the actual SDK calls and streams stdio back. This mirrors the Windows
Sandbox daemon pattern.

The daemon runs all SDK calls on a **single apartment-affine worker thread** (the WSLc SDK handles
are not thread-agnostic). Today `exec` blocks that worker for the duration of the run, so commands
against different sandboxes are serialized — correct, just not concurrent. See
[Known limitations](#known-limitations).

## Components

| Component | Location | Role |
|-----------|----------|------|
| State-aware backend | `src/backends/wslc/common/src/state_aware.rs` (`WslcStateAwareRunner`) | Translates runtime `WslcProvisionConfig` and cross-cutting policy into daemon protocol frames; implements `StatefulSandboxBackend` (`ID_PREFIX`/`BACKEND_KEY` = `wslc`). |
| Policy honor matrix | `src/backends/wslc/common/src/policy.rs` | Per-phase validation of which policy fields are honored vs rejected. |
| Daemon client | `src/backends/wslc/common/src/daemon_client.rs` | Discovers / spawns the daemon, connects the control pipe, sends `DaemonRequest` frames, reads responses; typed `DaemonError`. |
| Daemon | `src/backends/wslc/daemon/` (`wxc-wslc-daemon.exe`) | Long-lived host process holding `WslcSession` / `WslcContainer`; worker thread drives the SDK; idle-timeout watchdog tears the session down when unused. |
| Engine arm | `src/core/mxc_engine/src/state_aware.rs` | Dispatches the WSLc state-aware backend (Windows + `wslc` feature). |
| Prefix registration | `src/core/wxc_common/src/state_aware_dispatch.rs` (`backend_from_prefix`) | Maps the `wslc:` id prefix back to the WSLc backend for post-provision phases. |

Exact adapters construct `wxc_common::models::WslcProvisionConfig` directly from
`experimental.wslc.provision`. Engine-side checked binding preserves an absent
config, a present empty config, and supplied `image`/`imageTarPath` values
without reparsing JSON. An omitted image remains `None` until the backend
chooses its default. The separate rolling `wire::WslcProvisionPhase` survives
only as schema/type-oracle input and test characterization, not the backend's
provision associated type.

## Sandbox IDs

`provision` mints an id of the form `wslc:<32 lowercase hex>` (`wslc:` + a UUID simple form). All
post-provision phases (`start` / `exec` / `stop` / `deprovision`) carry this id in `sandboxId`; the
dispatcher derives the backend from the `wslc:` prefix (they do **not** repeat `containment`).

## Phase → WSLc SDK mapping

| Phase | Daemon action (WSLc SDK) |
|-------|--------------------------|
| provision | Load SDK, `WslcCreateSession`, resolve/import image, `WslcCreateContainer` with a keepalive init process (so the container survives across separate `exec` phases). The container is created **not started** (`started: false`). |
| start | `WslcStartContainer` — starts the container minted at provision-time (the keepalive init keeps it warm across later `exec` phases); marks it `started`. |
| exec | `WslcCreateContainerProcess` in the warm container; stream stdout/stderr, forward stdin, return the process exit code. A timeout SIGKILLs the **process**, not the container. |
| stop | `WslcStopContainer`. |
| deprovision | `WslcDeleteContainer`; release the session + SDK when the last container is gone (daemon may then exit / idle-time out). |

### exec output semantics

`provision` / `start` / `stop` / `deprovision` return a JSON `{result | error}` envelope on stdout.
A **successful** `exec` streams the script's raw stdout (relayed from the daemon-captured buffers)
and exits with the script's own exit code — it does **not** wrap the result in an envelope. Callers
discriminate via the exit code + whether stdout parses as an envelope.

## Policy honor matrix

WSLc networking is **all-or-nothing** (`WslcContainerNetworkingMode` `None` vs
`Bridged`); there is no per-host filtering or independent ingress/host-loopback
restriction primitive. Proxy configuration supplies environment variables, not
a firewall. Exact v0.9 supports two coherent postures:

| Posture | `egress.default` | `ingress.default` | `ingress.hostLoopback` |
| --- | --- | --- | --- |
| Isolated | `deny` | `deny` | `deny` |
| Bridged, unrestricted | `allow` | `allow` | `allow` |

Omitted directional values default to deny, so an egress-only allow request is
rejected rather than claiming its implicit ingress/loopback denies are enforced.
Mixed postures and per-host rules are rejected. Allowing ingress/host-loopback
does not create host port forwarding or promise reachability across NAT; it
acknowledges that WSLC cannot independently restrict those directions.

| Field | provision | start / stop / deprovision | exec |
|-------|-----------|----------------------------|------|
| `readwritePaths` / `readonlyPaths` | honored → container volumes | rejected | rejected |
| `deniedPaths` | rejected if overlapping/nested under a mount (a standalone denied path is accepted); no Deny primitive | rejected | rejected |
| Directional `network` posture | deny/deny/deny → isolated; allow/allow/allow → bridged | rejected | rejected; inherit provision posture |
| `network.egress.allow` / `deny` rules | rejected | rejected | rejected |
| Legacy `network` fields | structurally rejected in v0.9 | structurally rejected | structurally rejected |
| `runtimeConfig.networkProxy` | structurally rejected | structurally rejected | honored as a routable URL, injected as `HTTP_PROXY` / `HTTPS_PROXY` env vars |
| `ui` | rejected | rejected | rejected |
| `process.timeout` | n/a | n/a | honored → `ExecConfig.timeout_ms` |
| `lifecycle` | rejected (whole section, at parse) | rejected | rejected |

The exact `0.9.0-alpha` request root is selected before backend dispatch.
Fields absent from that phase's closed root fail structurally with
`malformed_request`: provision excludes `ui`, start / stop / deprovision admit
no filesystem, network, UI, or process policy, and exec excludes filesystem and
UI. These failures do not reach WSLc's presence checks.

Fields the exact root does admit still receive backend semantic validation.
Every resulting `policy_validation` above aborts the phase before anything is
created: the dispatcher runs each `validate_*` hook ahead of the phase body,
and `connect_daemon()` lives inside `provision()`, so a refused provision never
spawns the daemon, VM, or container.

Filesystem policy is fixed at `provision` and immutable afterwards.

The directional network posture is fixed at `provision`. Post-provision
phases reject supplied posture by presence, even when values equal defaults.
Only exec can supply a cooperative proxy through top-level `runtimeConfig`;
its request omits `network` so proxy-only execution inherits the existing
posture. Proxy URLs must address a listener reachable from the guest; a host
loopback listener is not made guest-reachable by spelling its host address
`localhost`.

The legacy `defaultPolicy`/`network.proxy` vocabulary documented in older
published contracts is not a v0.9 compatibility fallback. The new v0.9
directional requirements do not change those published contracts.

## Error mapping

Exact-contract `malformed_request` failures occur before daemon connection and
are not part of daemon error mapping. Once dispatch reaches the backend,
`state_aware.rs::map_daemon_error` maps daemon errors to the cross-backend wire error codes:

| Source | Wire error code |
|--------|-----------------|
| daemon `ErrKind::NotProvisioned` (incl. stale / deprovisioned id) | `not_provisioned` |
| daemon `ErrKind::NotStarted` | `not_started` |
| daemon `ErrKind::Busy` / `NotReady` / `Protocol` / `Backend`, or `DaemonError::Transport` | `backend_error` |
| `DaemonClient::connect` failure (no reachable daemon) | `backend_unavailable` |
| WSLc feature absent / host cannot run WSLc | `backend_unavailable` |

## Daemon idle-timeout env overrides

The daemon tears its session down after an idle period (default **300s**, polled every **15s**). Both
are overridable via environment (positive integer seconds; unset / empty / non-numeric / zero fall
back to the default). The daemon inherits the environment of the phase process that spawns it, so a
caller sets these before the first `provision`:

| Variable | Default | Meaning |
|----------|---------|---------|
| `MXC_WSLC_DAEMON_IDLE_TIMEOUT_SECS` | `300` | Idle duration after which the daemon tears down the session. |
| `MXC_WSLC_DAEMON_IDLE_POLL_SECS` | `15` | How often the idle watchdog checks for inactivity. |

The state-aware E2E harness (`tests/scripts/run_wslc_state_aware_tests.ps1`) uses short overrides so
it can observe idle-teardown within seconds.

## Testing

`tests/scripts/run_wslc_state_aware_tests.ps1` is the multi-invocation E2E harness (requires a WSL2
host with the image pre-pulled and `wxc-wslc-daemon.exe` staged next to `wxc-exec.exe`). It exercises
core lifecycle, warm-reuse (a marker written by one `exec` is read back by a separate `exec`
process — only possible if the container stayed warm), filesystem volumes, bridged networking +
proxy, validation rejections, and idle teardown. Fixtures live in
`tests/configs/wslc_state_aware_*.json`.

### Running the fixtures (ordering + id substitution)

The `wslc_state_aware_*.json` fixtures are **stateful** — unlike the one-shot configs, they cannot be
run individually or in an arbitrary order:

- **Order is mandatory.** A sandbox must go through `provision → start → exec… → stop → deprovision`.
  `provision` is what boots the session and mints the id; every other phase fails without it
  (`start`/`exec` before provision → `not_provisioned` / `not_started`, and any phase after
  `deprovision` → `not_provisioned`).
- **The id must be threaded through.** `provision` returns the real `wslc:<32-hex>` id on stdout
  (`result.sandboxId`). The post-provision fixtures (`_start`, `_stop`, `_deprovision`, and every
  `_exec_*`) ship with a literal **`{{SANDBOX_ID}}` placeholder** that must be replaced with that
  minted id before the config is passed to `wxc-exec`. Running a post-provision fixture as-is sends
  the literal placeholder and fails validation.

`run_wslc_state_aware_tests.ps1` handles both concerns automatically (it drives the phases in order
and does the `{{SANDBOX_ID}}` substitution from each provision's output), which is why the fixtures
should be exercised **through the harness**, not by pointing `wxc-exec --config` at them directly.

## Known limitations

- **Serialized exec (deferred).** Because the daemon's single worker thread blocks on
  `WaitForSingleObject` for the whole `exec`, no other sandbox can provision or exec while one
  command runs, and a per-container single-flight `Busy` guard is not yet meaningful. The intended
  fix splits `exec` into an on-worker `ExecStart` (extract the thread-agnostic Win32 exit-event
  handle) + an off-thread wait + an on-worker `ExecReap`, with a per-container `in_flight` slot. This
  is tracked as follow-up work.
