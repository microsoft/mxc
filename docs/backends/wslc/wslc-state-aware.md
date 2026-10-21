# WSLc Container Lifecycle Operations

> **Audience:** MXC consumers and developers

This document describes **container lifecycle operations** for the WSL Container (WSLc) backend:
`provision → start → exec → stop → deprovision` calls that keep a
container running across separate `wxc-exec` phase processes, avoiding repeated
WSLc startup costs. See the [consumer glossary](../../glossary.md) for terminology.

It complements:

- [WSLC SDK bindings runbook](../../development/build-and-test/wslc-sdk-bindings.md) — regenerating the SDK bindings.
- [Container lifecycle architecture](../../development/architecture/container-lifecycle.md) — the shared lifecycle JSON format, the Rust `StatefulSandboxBackend` trait, and backend routing.

WSLc lifecycle ["MXC request JSON"](../../schema.md#mxc-request-json) is supported by published contracts
beginning with `0.9.0-alpha`. The Rust, .NET, and Node high-level v1 lifecycle
APIs use stable contract `1.0.0`; callers do not
supply a schema version. Neither path requires a runtime experimental opt-in.
Native builds still require the `wslc` feature (`build.bat --with-wslc`).

## Why a daemon

The WSLc SDK (`wslcsdk.dll`, 3.0.3) has **no cross-process session re-attach**: every operation
(`WslcCreateContainer`, `WslcStartContainer`, `WslcCreateContainerProcess`, image pull, stop /
delete) requires a live in-process `WslcSession` / `WslcContainer` handle, and there is no
`WslcOpenSession`. Each lifecycle phase runs as a **separate**
`wxc-exec` invocation, so handles minted during `provision` cannot be reused by a later `exec`
or `deprovision` in a different process.

> SDK 2.9.9 added `WslcOpenContainer` (open an existing container by name, full ID, or unique ID
> prefix). That is a *container*-level primitive and still requires a live session handle in the
> calling process, so it does not by itself remove the need for the daemon. Whether a fresh
> per-phase session plus `WslcOpenContainer` could replace the warm-handle model has not been
> evaluated; the daemon remains the supported design.

To keep the session (VM) and container **warm** across phases, WSLc uses a **persistent per-user
daemon** (`wxc-wslc-daemon.exe`, an `mxc-sdk` binary target at
`src/mxc-sdk/src/bin/wslc_daemon/`) that owns
the live SDK handles. Each phase process is a thin client that contacts the daemon over a named
pipe; the daemon performs the actual SDK calls and streams stdio back. This mirrors the Windows
Sandbox daemon pattern.

The daemon owns the live SDK handles on a **single apartment-affine worker thread**, which services
every lifecycle command. Any thread that has joined the MTA may use those handles, so an image
pull and an `exec` each run on an MTA thread of their own and post their outcome back to the
worker, leaving it free to serve other sandboxes for the duration of a run. A second `exec` on a
container with a run in flight is refused as `busy`; a lifecycle command naming that container
waits for the run, because deleting the container would free a handle the run is using. See
[Known limitations](#known-limitations).

One daemon holds several sessions — several utility VMs — and places sandboxes
in them, so one caller's VM is not another caller's. See [Sessions](#sessions).

## Components

| Component | Location | Role |
|-----------|----------|------|
| Lifecycle backend | `src/mxc-sdk/src/backends/wslc/common/state_aware.rs` (`WslcStateAwareRunner`) | Translates runtime `WslcProvisionConfig` and shared policy fields into daemon protocol frames; implements `StatefulSandboxBackend` (`ID_PREFIX`/`BACKEND_KEY` = `wslc`). |
| Policy support checks | `src/mxc-sdk/src/backends/wslc/common/policy.rs` | Per-phase validation of which policy fields are enforced or rejected. |
| Daemon client | `src/mxc-sdk/src/backends/wslc/common/daemon_client.rs` | Discovers / spawns the daemon, connects the control pipe, sends `DaemonRequest` frames, reads responses; typed `DaemonError`. |
| Store slot pool | `src/mxc-sdk/src/backends/wslc/common/store_slots.rs` | Owns the daemon's image stores: slot paths and leasing. See [Image store](#image-store). |
| Daemon | `src/mxc-sdk/src/bin/wslc_daemon/` (`wxc-wslc-daemon.exe`) | Long-lived host process holding every live `WslcSession` / `WslcContainer`; worker thread drives the SDK; idle-timeout watchdog releases a session nothing is using and tears the daemon down when it is wholly unused. |
| Engine routing | `src/mxc-sdk/src/core/mxc_engine/state_aware.rs` | Selects the WSLc lifecycle backend (Windows + `wslc` feature). |
| Prefix registration | `src/mxc-sdk/src/tools/mxc_common/state_aware_dispatch.rs` (`backend_from_prefix`) | Maps the `wslc:` id prefix back to the WSLc backend for post-provision phases. |

Version-specific adapters construct `mxc_common::models::WslcProvisionConfig` directly from
`wslc.provision`. Conversion to the backend's typed configuration preserves an absent
config, a present empty config, and supplied
`image`/`imageTarPath`/`portMappings` values without reparsing JSON. An omitted
image remains `None` until the backend chooses its default. Each version's JSON
request type is converted once by its adapter; the backend uses the runtime
`WslcProvisionConfig` model rather than deserializing JSON again.

### Port mappings

`wslc.provision.portMappings` forwards host ports into the sandbox's container,
using the same entry shape as the create-and-run `wslc.portMappings` list:

```json
{
    "version": "1.1.0-alpha",
    "phase": "provision",
    "containment": "wslc",
    "network": {
        "egress": { "default": "allow" },
        "ingress": { "default": "allow", "hostLoopback": "allow" }
    },
    "wslc": {
        "provision": {
            "portMappings": [
                { "windowsPort": 8080, "containerPort": 80 }
            ]
        }
    }
}
```

Port mappings require bridged networking. A request that leaves `network` out,
or sets it to the all-`deny` isolated posture, is rejected at provision: the
container has no networking for a forward to reach.

The field requires development contract `1.1.0-alpha`. Requests declaring
`0.9.0-alpha` cannot include it and must select `1.1.0-alpha` explicitly.
The daemon creates a separate container for each provision, so a mapping
applies only to the container that declared it. `cpuCount`, `memoryMb`, and
`gpu` instead size the session's VM and are set by `provision-session`
(see [Sessions](#sessions)). `storagePath` remains create-and-run-only:
the daemon leases its store from the slot pool rather than taking a caller-named
path (see [Image store](#image-store)).

The create-and-run `wslc.portMappings` list and `wslc.provision.portMappings` share
one duplicate check, so two entries claiming the same `windowsPort` are
rejected identically. Zero ports and non-TCP protocols are rejected when the
version-specific JSON request is deserialized.

The forward listens on `127.0.0.1` only, so a mapped port reaches the container
from the host itself and not from other machines. WSLC installs it when the
container starts rather than at provision, so a `windowsPort` that another
process already holds on loopback fails the `start` phase, not `provision`.

## Sessions

A WSLc session is one WSL2 utility VM. A daemon holds as many of them as it is
asked for, each with its own leased image store, and places sandboxes in them.

A caller addresses a session through two lifecycle phases of its own:

| Phase | Carries | Returns |
|-------|---------|---------|
| `provision-session` | `wslc.provisionSession.cpuCount`, `memoryMb`, `gpu` | `result.sessionId` |
| `deprovision-session` | `sessionId` | an empty result |

A sandbox joins one by naming it on `wslc.provision.sessionId`. Sizing belongs
to the session, so `cpuCount: 4` means the VM has four virtual CPUs shared by
every sandbox in it, not a four-CPU quota per sandbox — which is why a
`provision` declares no sizing of its own.

Both session phases declare `containment: "wslc"` and are routed by it, since a
session ID carries no backend prefix to route by. WSLc is the only backend that
owns a session, so a session phase naming any other containment is refused with
`unsupported_containment`.

Both phases require contract `1.1.0-alpha`. No v1 SDK can reach them: the Rust,
Node, and .NET v1 surfaces all emit published contract `1.0.0`, which declares
no session fields. Use MXC request JSON through
`mxc_sdk::__ffi::run_lifecycle_json`, the FFI, or `wxc-exec` until a new
stable contract publishes.

A `provision` that names no session joins the daemon's **implicit** session,
which is booted on first use and shared by every request that names none. That
is what every provision did before sessions became addressable, so an existing
caller is unaffected.

Session ids take the form `wslcsess:<32 lowercase hex>`. The implicit session
gets a random id like any other and it is never handed back, so one caller
cannot name the session everyone else is sharing and release it from under them.
Releasing the implicit session by id is refused for the same reason; it goes
when nothing is using it, or when the daemon does.

Malformed IDs return `malformed_id` for both session placement and release.

> **A session ID is a bearer capability.** The daemon's pipe is owner-only, so
> any same-user process holding one can place sandboxes in that session and
> release it. Nothing well-known is ever minted — not `wslcsess:default`, not
> anything derivable — and `wxc-exec` refuses an ID that is not
> `wslcsess:` plus 32 lowercase hex before the daemon is contacted. Treat the
> ID as opaque and keep it out of logs, as mxc does.

The SDK is given one name per session, derived from its id
(`mxc-wslc-daemon-<32 hex>`). Two live sessions under one name is an untested
SDK failure mode, which is why the name is not fixed.

### A sandbox's policy identity does not cover its session's sizing

When telemetry or diagnostic logging is active, `wxc-exec` computes
`MXC.PolicyHash` from the request **before** dispatch. In-process lifecycle
entry points do not emit this record. A `provision-session` hashes the sizing
it declares. A sandbox joining an existing session declares none, so two otherwise identical
`provision` requests hash identically whether they land in a two-CPU VM or an
eight-CPU VM with GPU passthrough — and `gpu` is a capability grant.

The gap is accepted rather than papered over:

- **Restating sizing on the provision request** would make the hash an
  unverified caller claim. The request is hashed before the daemon resolves the
  session, so a request could declare no GPU and still land in a session that
  has one. A false attestation is worse than a known omission.
- **Hashing the `sessionId`** would give two identically sized sessions
  unrelated identities, and would put a bearer capability in a log.

What the hash does record is the one related fact the request carries:
`joinsNamedSession: true` when `wslc.provision.sessionId` is present, meaning
this sandbox's VM was sized by another request rather than by the host defaults
the implicit session uses. It does not identify which session, or what sizing.
A request that names no session hashes exactly as it did before the session
surface existed.

Closing the gap properly means establishing identity after the backend resolves
the session, which changes when identity is computed for every backend. That is
tracked separately.

### How many sessions

Nothing in mxc bounds the number of concurrent sessions. Neither the store pool,
which mints a slot per session on demand, nor the daemon.

That is deliberate rather than an omission. A count cannot express the thing a
limit would protect: a session carries its own CPU and memory, so the same
number of sessions is a trivial load on one host and more than another has. A
fixed cap is wrong in both directions at once — it permits four VMs sized past
the host's memory, and refuses ten small ones that would have been fine.

The host is therefore the only limit. What that means in practice was measured
rather than assumed, and it is worse than "the create fails":

| Asked for | 64 TB of memory on a host with 27 GB free |
|---|---|
| `WslcCreateSession` | **Succeeded, in 0.9s.** Nothing about the request is checked against what the host can supply. |
| First use (the store probe) | Failed after **1106 seconds** with `HRESULT 0x800705AA` (`ERROR_NO_SYSTEM_RESOURCES`). |
| The 180s boot timeout | Bounded the create, which took under a second. Nothing bounds first use. |

So an impossible session is accepted cheaply and the whole cost lands on the
first call that needs the VM to actually work. This is the same shape as the
store-sharing violation: `WslcCreateSession` validates nothing that requires the
VM to function, so the store probe run straight after create is what catches
both — and is therefore also where the time goes.

That is why a session boots on **a thread of its own** rather than on the
daemon's worker thread. On the worker, one such request would stall every other
sandbox on the daemon for a quarter of an hour — including the watchdog poll
that drives the empty-session reaper, so the mechanism that reclaims abandoned
sessions would be starved exactly when something is going wrong. A session count
cap would not have helped: one request is enough.

While a session is booting, the slot it will use is already leased and its id
already reserved, so nothing else can take either. A `provision` that names a
booting session — or names none while the implicit session is still coming up —
**parks** behind it and is replayed when the VM is ready. That parking is what
stops two implicit sessions being booted side by side when two provisions
arrive together. A boot that fails answers everything parked behind it, returns
its slot, and retires its id, so the next request starts cleanly rather than
queueing behind a session that will never exist.

What remains: a caller in a runaway loop still consumes the host, it just no
longer takes the daemon down with it. Callers that provision sessions on behalf
of untrusted input should bound their own concurrency and validate requested
sizes against the host. Bounding aggregate memory inside the daemon is a
separate problem and is not solved here — and would be unreliable anyway, since
`memoryMb` is optional and an absent one resolves to a host default the SDK does
not report.

### Sizing

A session carries `cpuCount`, `memoryMb` and `gpu`. The two numeric ones behave
oppositely, measured on a 64 GB host with 16 logical processors:

| Request | Outcome |
|---|---|
| `memoryMb` = 128 GB (2× installed) | Boots. The guest reports 128718 MB; the host pays 3.2 GB. |
| `memoryMb` = 64 GB (1× installed) | Boots. Guest reports 64258 MB; host pays 1.9 GB. |
| `cpuCount` = 32 (2× logical) | **Refused**, in 242 ms. |
| `cpuCount` = 16 (1× logical) | Boots. Guest reports 16. |

**`memoryMb` is a ceiling, not a reservation.** The host backs only what the VM
touches, plus roughly 1.5 GB of bookkeeping per 64 GB of ceiling. Asking for
more memory than the host has installed is legitimate and works — which is why
mxc does not reject it. (It is also why an absurd ceiling eventually fails: at
64 TB the bookkeeping alone exceeds the host, which is the `ERROR_NO_SYSTEM_RESOURCES`
case above.)

**`cpuCount` admits no oversubscription.** More processors than the host has is
refused outright. mxc checks this before calling the SDK — not to change the
outcome, which would be a refusal either way, but to change the diagnosis. The
SDK's own failure surfaces from the store probe as `WslcListSessionImages
failed ... (0x80004005)`, blaming the image store for a processor problem.
Checking up front returns `policy_validation` naming the processor count and
the host's.

`memoryMb` must fit in the SDK's unsigned 32-bit megabyte field
(`0` through `4294967295`). Session validation rejects a larger value before
contacting the daemon, including during a dry run.

`0` means "use the default" for both (2 processors, 2000 MB) and is passed
through rather than measured. `gpu` is a feature flag, not a quantity; whether
passthrough is available is answered by the runtime component check. The
session's VHD size is not exposed — every session takes the SDK default.

Both surfaces apply this: container lifecycle operations and create-and-run
execution.

### Session lifetime

A session is released when nothing is using it any more. "Using it" means any
sandbox placed in it — including one that is quarantined, and one that has been
retired because its provision reply never reached a client, both of which still
own live SDK handles — plus any provision still waiting on an image pull, any
exec in flight, and any pull still running.

A session observed holding nothing is released after the **empty-session
grace**, which defaults to the daemon's own idle window.

| Variable | Default | Meaning |
|----------|---------|---------|
| `MXC_WSLC_DAEMON_SESSION_IDLE_SECS` | `MXC_WSLC_DAEMON_IDLE_TIMEOUT_SECS`, else `300` | How long a session holding nothing is kept. |
| `MXC_WSLC_DAEMON_SESSION_BOOT_SECS` | `600` | How long a boot is given before the clients waiting on it are let go. |

Defaulting to the daemon's idle window is deliberate. That window is already the
longest a caller can leave anything here untouched and expect to find it, since
an idling daemon releases every session it holds; a session cannot promise to
outlive the daemon it lives in. Shortening the daemon's idle window shortens the
grace with it, so a test that drives teardown sets one knob rather than two.

An empty session does **not** hold the daemon open. If it did, the implicit
session would keep the daemon alive for the grace and only then let the idle
streak start, roughly doubling teardown — while buying nothing, because both
clocks start at the same moment and run to the same default.

The consequence to know about: a caller that boots a session and does not place
a container in it within the grace finds it gone, and gets `not_provisioned`
naming the session. Creating another is the recovery. The alternative — keeping
an unused session until someone explicitly released it — makes an abandoned
session pin a utility VM, a store slot, *and* the daemon, with nothing able to
reclaim any of them short of ending the process by hand.

A `deprovision-session` naming a session that still holds something is
**refused**, not cascaded. The sandboxes in a session are addressed
individually and their owners still hold those ids, so deleting sandboxes the
caller never named would be worse than an error. Deprovision them first, then
release the session.

## Sandbox and session IDs

`provision` mints an id of the form `wslc:<32 lowercase hex>` (`wslc:` + a UUID simple form), and
`provision-session` mints `wslcsess:<32 lowercase hex>` the same way.
"MXC request JSON" carries the sandbox id in `sandboxId` for every post-provision phase
(`start` / `exec` / `stop` / `deprovision`), and the session id in `sessionId` for
`deprovision-session`. Direct `wxc-exec` calls omit the id from JSON and pass it
as `--container-id` or `--session-id` respectively; the two flags are mutually exclusive, and a
phase supplied the wrong one is told which it wanted. The dispatcher derives the backend from the
`wslc:` prefix for sandbox-addressed phases (later operations do **not** repeat `containment`), and
from the declared `containment` for the session phases.

The session a sandbox joins is not a routing value, so it stays in the request body at
`wslc.provision.sessionId` rather than moving to a flag.

## Phase → WSLc SDK mapping

| Phase | Daemon action (WSLc SDK) |
|-------|--------------------------|
| provision-session | Load SDK, lease a store slot, `WslcCreateSession` with the requested sizing on a thread of its own, then validate the session with a store probe. Returns the minted `sessionId`. |
| provision | Load SDK, ensure the session (`WslcCreateSession` on first use when none was named), resolve/import image, `WslcCreateContainer` with a keepalive init process (so the container survives across separate `exec` phases). The container is created **not started** (`started: false`). |
| start | `WslcStartContainer` — starts the container minted at provision-time (the keepalive init keeps it warm across later `exec` phases); marks it `started`. |
| exec | `WslcCreateContainerProcess` in the warm container; stream stdout/stderr and return the process exit code. Stdin is not forwarded to the process. A timeout or caller cancellation SIGKILLs the **process**, not the container. |
| stop | `WslcStopContainer`. |
| deprovision | `WslcDeleteContainer`. The session stays warm for the next provision and is released once nothing is using it (see [Session lifetime](#session-lifetime)). |
| deprovision-session | Refuse while anything is still in the session, else terminate the VM and return its store slot. |

A dry run of either session phase validates the request and stops there: no ID
is minted, no VM is booted, no store slot is leased, and the daemon is never
contacted.

A session is created with the CPU count, memory, and GPU flag it was asked for,
and always with a **boot timeout** (180s, the same budget create-and-run
execution uses), so a utility VM that never comes up fails the request instead
of wedging the worker that asked for it.

## Image store

A WSLc store is a host directory handed to `WslcCreateSession`; the SDK creates
`storage.vhdx` inside it and mounts that VHDX into the session's WSL2 utility
VM, where it holds the session's pulled images. A warmed store runs to a couple
of GiB.

The daemon leases its store from a pool rather than taking a caller-named path:

```text
%LOCALAPPDATA%\mxc\wslc-store-slots\slot-0, slot-1, …
```

`%TEMP%\mxc\wslc-store-slots` is used instead when `%LOCALAPPDATA%` is
unresolvable. A session leases the lowest free slot when it boots and returns it
when it is released, so a daemon holding one session runs on `slot-0`, a second
concurrent session takes `slot-1`, and so on. The pool grows to meet demand and
bounds nothing; how many sessions may run at once is not bounded by mxc at all
(see [How many sessions](#how-many-sessions)). Create-and-run execution keeps its own default of
`%TEMP%\mxc-wslc-sessions` and never touches the pool.

Both the daemon and the command that warms the pool resolve these variables from
their own environment, so warm the pool as the user the daemon runs as. A
refusal names the directory it needs filled, so a warm that reports success
against a different directory has filled the wrong store.

Separating the two is what lets both surfaces run at once. A store's VHDX admits
one live session, so while the daemon held `%TEMP%\mxc-wslc-sessions` every
create-and-run WSLc execution on the same host failed with
`WslcListSessionImages failed: HRESULT 0x80070020` until the daemon idled out.

The pool does not cap how many sessions a host may run, and a slot count would
be the wrong control for that: a session carries its own cpu and memory, so the
same count can mean very different host load. Admission belongs with the work
that lets a caller request a second session.

### Slot contents and disk

A returned slot keeps its images — that is the point of leasing rather than
minting. A slot that has never been leased holds nothing at all, and an uncached
image under the isolated posture is refused before a container is created.
The error names the selected store's slot and path, the uncached image, and
the command to warm it. MXC does not relocate the session to another store or
pull outside the declared network policy. The SDK session may already be
running when its image cache is inspected. Warm the pool with either:

```powershell
.\scripts\setup-wslc.ps1 -Image alpine:latest -DaemonSlots 1
wxc-exec.exe --setup-wslc --image alpine:latest --wslc-daemon-slots 1
```

Both default to 0 and warm slots from 0 up, so `1` is what a daemon holding one
session needs. Each store is opened once and filled with every image given, so
pass them all to one invocation. See
[the getting-started guide](wsl-container-getting-started.md#how-warming-works)
for how warming works, and
[Step 3](wsl-container-getting-started.md#step-3--container-images-optional-pre-pull)
for the create-and-run store, which these do not replace.

A slot directory is created when it is first leased, so an index no session has
reached costs nothing, and the pool grows only to the number of sessions the host
has actually run at once. Warming is the exception: `-DaemonSlots N` creates and
populates all `N` stores up front whether or not a daemon ever leases them, so a
large `N` costs a multi-GiB store per slot immediately. Reclaim the disk by
deleting the pool directory while no daemon is running.

### Store exclusivity

The SDK does not report a store conflict at create time: `WslcCreateSession`
against a store another live session holds returns a healthy-looking handle, and
the violation appears only on first use. The daemon therefore probes the store
itself immediately after create (`WslcListSessionImages`) and treats a failure
as a *create* failure, so a conflict can never mint a sandbox id that dies at an
arbitrary later phase.

Lease tracking covers one process, so two sessions inside one daemon can never
be handed the same slot. A holder outside that bookkeeping — typically a daemon
from a previous build still inside its idle window — fails the provision with an
error naming the slot, rather than relocating the session onto a cold slot and
reporting a missing image instead.

A session whose VM teardown could not stop keeps its slot leased rather than
returning it, because that VM may still have the store's VHDX mounted and
reissuing the slot would hand out a store nothing can open. Three cases reach
that state: a pull still running when the drain budget expired, a terminate that
reported a failure (including one stopping a VM whose store probe failed), and a
terminate still running when teardown's release budget expired.

Teardown spends its budget twice over: once waiting for in-flight work across
every session, and again waiting for the VMs that drained to stop. Sharing one
budget would let a single stuck pull leave the remaining sessions no time to
release, and a leaked slot costs capacity permanently where a slow terminate does
not.

A session whose boot lands after teardown has begun is released before the SDK
unloads rather than left for the command channel to drop.

Stopping a VM runs on a thread of its own, as booting one does, so neither the
empty-session reaper nor a `deprovision-session` holds up the sandboxes in every
other session. Shutdown uses the same threads: it starts every release at once
and waits for them only until its budget runs out. A VM still stopping then is
left running with its slot held, and the SDK stays loaded under it, rather than
holding up the daemon's exit. A client asking to release a session is answered
when its VM has actually stopped, not when the request was accepted.

A session booted while another is being released waits for that release to
return its store slot rather than taking a cold one, since the next free slot
lacks the images the released session had pulled. Each finished release lets one
waiting boot go. A release normally finishes in under a second; one still running
after 60 seconds is treated as stuck, and the boots waiting on it take the next
free slot instead.

The boot timeout above bounds `WslcCreateSession` only — the store probe that
follows it has no deadline of its own and has been measured taking minutes. A
boot still running after `MXC_WSLC_DAEMON_SESSION_BOOT_SECS` therefore has its
waiting clients answered and its id retired, so a later request boots a fresh
session rather than parking behind one that may never arrive. Its store slot
stays held, because that boot thread may still open the store; if it does
eventually produce a VM, that VM is released rather than installed. A boot still
waiting for a releasing slot at that point has no thread and no slot, so it is
dropped. The deadline runs from when the session was asked for, including any
wait for a releasing slot.

### exec output semantics

`provision` / `start` / `stop` / `deprovision` return a JSON object containing `result` or `error` on stdout.
For `wxc-exec` CLI execution, a **successful** `exec` relays the script's raw stdout/stderr live
from daemon frames and exits with the script's own exit code — it does **not** wrap the result in
a JSON result object. A CLI dispatch **failure** writes its `{error}` JSON object to stderr, because the
script's output may already own stdout by the time the failure is known. In-process SDK execution
uses the supported streaming APIs, which return separate stdout/stderr pipes; no stdin pipe is
returned. Rust and .NET SDKs do not expose attached exec as a public operation. A timeout on the
CLI attached relay surfaces as a backend error because that path cannot return a typed timeout;
the streaming path reports it through its wait result.

### exec admission, cancellation, and failure containment

The daemon admits up to eight exec streams at once, one per container. A second
exec naming a container that already has one in flight is refused with `busy`
before any admission reaches the client; the outward SDK error is
`backend_error`. The bound of eight comes from memory: a streaming exec's output
lives only in its bounded live-output queue, so the persistent per-user daemon
stays near 128 MB of live output even against clients that never drain. An
exec's slot is held until the run has reported back and its client has been
written to, so a client that disconnects mid-run keeps counting against that
bound while its process is still going, and one that drains slowly keeps
counting while its output is still queued. A run whose termination could not be
confirmed leaves its sandbox quarantined and keeps the slot until that sandbox
is deprovisioned, because the process may still be alive.

Three conditions surface as `busy`, and all reach an SDK caller as
`backend_error`:

| Condition | Message | Retry |
| --- | --- | --- |
| The daemon's eight exec slots are all occupied | `WSLc daemon exec capacity is exhausted` | Succeeds once any exec finishes |
| The named container already has an exec in flight | `sandbox <id> already has an exec in flight` | Succeeds once that container's run finishes |
| Every client slot is occupied and the request is not a cancellation | `WSLc daemon client capacity is exhausted` | Succeeds once any client disconnects |

Up to eight additional control connections can be serviced while every exec slot
is occupied. Beyond that, a connection is admitted only to cancel: cancellation
is the one request that never waits on the worker, and the only way to end a run
with no timeout, so it keeps capacity of its own that lifecycle work cannot
consume. A connection on that lane must send its request within two seconds and
in under 1 KB, so one that connects and stalls cannot hold a cancellation slot
for the general deadline.

`start` / `stop` / `deprovision` naming a container with an exec in flight
**wait** for that run, because deleting the container would free a handle the
run is still using.

Each exec carries an internal ID and per-run token. A duplicate live ID is
rejected, and cancellation must match both values so a delayed cancellation
cannot terminate a later run that reused the same ID. Cancellation observed
before the worker starts a queued command returns a typed cancelled result
without creating the process.

Live output uses bounded queues in both the daemon and the in-process native
pipe bridge. If a caller does not drain stdout/stderr quickly enough, excess
output is dropped and the run is reported as truncated; incomplete output is
never reported as successful. A run that would otherwise have exited cleanly
becomes an explicit backend error carrying the process's exit code in
`details.exitCode`. A run that timed out or was cancelled keeps that outcome —
truncation is reported alongside it rather than replacing it. For an in-process
piped caller that pairing is only available on a clean exit: `ExecOutcome` has no
field for a modifier, so a piped run that both timed out and truncated reports
only the timeout.

If process termination cannot be positively confirmed after creation, the
container is quarantined and cannot be started or used for another exec. The
daemon attempts immediate deletion. If deletion fails, the quarantined entry is
retained so `deprovision` can retry cleanup; it is not removed from tracking
while a potentially running workload remains.

## Supported and rejected policy fields

WSLc networking is **all-or-nothing** (`WslcContainerNetworkingMode` `None` vs
`Bridged`); there is no per-host filtering or independent ingress/host-loopback
restriction primitive. Proxy configuration supplies environment variables, not
a firewall. Schema `0.9.0-alpha` supports two combinations:

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
| `process.env` / `process.inheritDefaultEnv` | n/a | n/a | honored → see [Environment](wsl-container-getting-started.md#environment) |
| `process.timeout` | n/a | n/a | honored → `ExecConfig.timeout_ms` |
| `lifecycle` | rejected (whole section, at parse) | rejected | rejected |

For "MXC request JSON" declaring `0.9.0-alpha`, that version's request type is selected before
backend execution. High-level v1 SDK calls select contract `1.0.0` internally.
Fields not declared for that phase are rejected during parsing with
`malformed_request`: provision excludes `ui`, start / stop / deprovision admit
no filesystem, network, UI, or process policy, and exec excludes filesystem and
UI. These failures do not reach WSLc's presence checks.

Fields allowed by that phase's JSON request type still receive backend validation.
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

JSON parsing failures reported as `malformed_request` occur before daemon connection and
are not part of daemon error mapping. Once dispatch reaches the backend,
`state_aware.rs::map_daemon_error` maps daemon errors to the shared SDK error codes:

| Source | SDK error code |
|--------|-----------------|
| daemon `ErrKind::NotProvisioned` (incl. stale / deprovisioned id) | `not_provisioned` |
| daemon `ErrKind::NotStarted` | `not_started` |
| daemon `ErrKind::Unavailable` (host cannot run WSLc) | `backend_unavailable` |
| daemon `ErrKind::Rejected` (request the backend refuses as written) | `policy_validation` |
| daemon `ErrKind::Busy` / `NotReady` / `Protocol` / `Backend` / `Unknown`, or `DaemonError::Transport` | `backend_error` |
| `DaemonClient::connect` failure (no reachable daemon) | `backend_unavailable` |
| WSLc feature absent / host cannot run WSLc | `backend_unavailable` |

The daemon classifies each failure from the `failure_phase` its step helper
reported, so a phase failure reaches the SDK with the same code that
create-and-run execution returns for the same host condition. A caller branches on the code
without matching the message.

`ErrKind` is additive: a kind a client does not recognize decodes to
`ErrKind::Unknown` and maps to `backend_error`, so a daemon from a newer
install degrades to the previous behavior instead of failing the decode. Adding
a kind therefore needs no `PROTOCOL_VERSION` bump.

## Upgrading across a protocol version

The control protocol carries a `PROTOCOL_VERSION`, published in the daemon's
discovery record and compared for **exact equality** with no negotiation. A
client refuses a daemon whose version differs, in either direction.

That makes a version change a cutover. The SDK has no way to re-attach to a
live session from another process, so a daemon still holding sandboxes when the
version changes strands them: nothing but that process can reach those
containers, and the replacement daemon cannot adopt them. Letting the old daemon
idle out, or ending it, is the only way through, and it destroys whatever it was
holding.

Staying compatible instead is not the safer trade. The config frames admit
unknown fields, so a daemon predating a field silently drops it and reports
success for a request it only partly honoured — a sandbox that is quietly not
what was asked for. A refusal the caller can see is better.

Upgrading an install that may have a live daemon therefore means stopping the
old one first. `PROTOCOL_VERSION` is **8** as of the addition of session frames
(`provision_session` / `deprovision_session`, and the optional `session_id` on
`provision`).

## Daemon idle-timeout env overrides

The daemon tears everything down after an idle period (default **300s**, polled every **15s**). Both
are overridable via environment (positive integer seconds; unset / empty / non-numeric / zero fall
back to the default). The daemon inherits the environment of the phase process that spawns it, so a
caller sets these before the first `provision`:

| Variable | Default | Meaning |
|----------|---------|---------|
| `MXC_WSLC_DAEMON_IDLE_TIMEOUT_SECS` | `300` | Idle duration after which the daemon tears down every session it holds and exits. |
| `MXC_WSLC_DAEMON_IDLE_POLL_SECS` | `15` | How often the idle watchdog checks for inactivity. |

A session that holds nothing is released on its own clock, which defaults to
whatever the first of these resolves to — see
[Session lifetime](#session-lifetime). That reaping rides on the same watchdog
poll, and never waits for anything: a session still in use is simply left for
the next poll, so one busy session cannot stall the others' requests.

Teardown waits at most **60s** for off-worker execs and every session's
outstanding pulls, then at most another **60s** for the VMs it is stopping. The
first budget is shared across every session rather than spent once per session,
so a daemon holding four sessions does not take four times as long to exit as a
daemon holding one. Whatever is still running when a budget expires is abandoned
rather than released, since freeing memory the SDK is still using is the worse
failure: an abandoned session keeps its store slot leased, because its store's
VHDX may still be mounted, and the SDK stays loaded under a VM still stopping.

The lifecycle end-to-end test script (`tests/scripts/run_wslc_state_aware_tests.ps1`) uses short overrides so
it can observe idle-teardown within seconds.

## Testing

`tests/scripts/run_wslc_state_aware_tests.ps1` is the multi-invocation E2E harness (requires a WSL2
host that can reach a registry or already has the images cached in daemon store slots 0–2, and `wxc-wslc-daemon.exe` staged next to `wxc-exec.exe`). It exercises
core lifecycle, warm-reuse (a marker written by one `exec` is read back by a separate `exec`
process — only possible if the container stayed warm), filesystem volumes, bridged networking +
proxy, validation rejections, exec concurrency, and idle teardown. Fixtures live in
`tests/configs/wslc_state_aware_*.json`.

The session tests place two sandboxes in one session and compare their VM
boot IDs. They also keep two identically sized sessions alive together and
check that releasing one leaves the other's sandbox usable. The setup
preflight warms three stores for the implicit session and the two explicit
sessions, because isolated provisions cannot pull into a cold store.

The cold-store regression uses a private pool and daemon discovery root,
warms only slot 0 with `-DaemonSlots 1`, and holds that slot with a sandbox.
An isolated provision on slot 1 must name the cold store in its refusal,
leave no container behind, and leave the original warm sandbox usable.
This case needs registry access even with `-SkipSetup`; it does not reuse or
modify the normal image cache.

The concurrency section launches a phase without waiting for it (`Start-StateAware` /
`Wait-StateAware`), which is what lets it observe two sandboxes running at once, a refused
same-container second exec, and a lifecycle command issued while a run is in flight. Every other
section drives one phase process at a time.

### Running the fixtures (ordering + id substitution)

The `wslc_state_aware_*.json` test inputs describe **container lifecycle operations**: unlike create-and-run configs, they cannot be
run individually or in an arbitrary order:

- **Order is mandatory.** A sandbox must go through `provision → start → exec… → stop → deprovision`.
  `provision` is what boots the session and mints the id; every other phase fails without it
  (`start`/`exec` before provision → `not_provisioned` / `not_started`, and any phase after
  `deprovision` → `not_provisioned`). An explicit session widens that to
  `provision-session → provision → start → exec… → stop → deprovision → deprovision-session`:
  a `provision` cannot name a session that does not exist yet, and a
  `deprovision-session` is refused while a sandbox is still in it.
- **The id must be threaded through.** `provision` returns the real `wslc:<32-hex>` id on stdout
  (`result.sandboxId`), and `provision-session` returns `wslcsess:<32-hex>` in `result.sessionId`.
  The post-provision fixtures (`_start`, `_stop`, `_deprovision`, and every
  `_exec_*`) ship with a literal **`{{SANDBOX_ID}}` placeholder**; the session fixtures
  (`_provision_in_session`, `_deprovision_session`) ship with **`{{SESSION_ID}}`**. These test
  inputs use "MXC request JSON"; the harness replaces the placeholders before converting the
  request to direct executor CLI form.

`run_wslc_state_aware_tests.ps1` handles both concerns automatically (it drives the phases in order
and does the `{{SANDBOX_ID}}` / `{{SESSION_ID}}` substitution from each provision's output). It then
removes `phase` and the phase's routing id from the JSON and passes them as `--operation` and
`--container-id` or `--session-id`. The session a `provision` joins stays in the body, since it is
configuration rather than routing. Exercise these fixtures **through the harness**, not by pointing
`wxc-exec --config` at them directly.

## Known limitations

- **Ordering is per-container, not global.** A lifecycle command naming a container with a run in
  flight waits for that run; commands for other sandboxes proceed independently. A caller cannot
  infer that work on one sandbox completed because work on another did.

- **`busy` collapses to `backend_error` (deferred).** A refused exec reaches an SDK caller as a
  generic `backend_error` with no indication that retrying would succeed. A retryable error code
  needs a new `MxcErrorCode` variant, whose predefined values match the SDK `ErrorCode` union
  one-for-one, so it spans Rust, Node, .NET, the versioned references, and schema regeneration.
  This is tracked as follow-up work.

- **No typed SDK can set port mappings or sessions yet.** The Rust, Node, and
  .NET v1 SDKs all use published stable contract `1.0.0`, which declares
  neither `wslc.provision.portMappings` nor any session field, and released
  schemas are immutable. "MXC request JSON" using contract `1.1.0-alpha` through the
  raw Rust entry point `mxc_sdk::__ffi::run_lifecycle_json`, FFI, or `wxc-exec`
  reaches them today. Promoting `1.1.0-alpha` to a stable release is what lets
  the three typed SDKs expose them together.

- **A sandbox's policy identity does not cover its session's sizing.** See
  [the section above](#a-sandboxs-policy-identity-does-not-cover-its-sessions-sizing).
