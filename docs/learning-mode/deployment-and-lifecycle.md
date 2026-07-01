# Learning-mode capture: deployment & lifecycle design

Status: **Draft for review.** Owner: learning-mode capture feature.
Reviewers: Tessera crew (`@microsoft/tessera-code-reviewers`).
Related: [`architecture.md`](./architecture.md) (box layout + runtime data flow),
[`consumer-guide.md`](./consumer-guide.md) (application integration contract and gotchas),
[`../host-prep.md`](../host-prep.md) (broker install/uninstall command reference).

This document exists because the captureDenials work (PR #558 and the stacked PRs
behind it) introduced a **privileged Windows service** — the
`MxcLearningModeBroker` — and reviewers asked the natural follow-on questions that
the code alone does not answer:

1. **Developer workflow** — end to end, what does a consumer do to *use*
   `captureDenials`? Who installs the broker, when, and with what privileges?
2. **Cleanup logic** — if applications cause the service to be created, what
   removes it? What about the `SeSystemProfilePrivilege` grant that uninstall
   deliberately leaves behind?
3. **Per-app vs shared** — is there one service per application, or one shared
   machine-wide service for all consumers? Is that the right model?
4. **Packaging fit** — MXC ships an npm package (`@microsoft/mxc-sdk`) today and
   a Rust crate tomorrow. Neither packaging model can register an elevated,
   machine-wide OS service at install time. How does broker provisioning fit?

Per CONTRIBUTING.md §"To spec or not to spec", this is the short written design
we agree on **before** building any of the workflow/lifecycle automation the
questions imply.

**Scope:** Windows only. The broker is a Windows construct; the Linux/macOS
learning-mode adapters are stubs today (`Err(NotSupported)`) and their
deployment model is explicitly out of scope and called out as future work in the
last section.

---

## TL;DR of the recommendation

- **Keep one shared, machine-wide service.** Do not move to per-app services.
  Cross-tenant isolation is already enforced *per call* by the broker's
  impersonate-then-`OpenProcess` check, not by service instancing.
- **Provisioning is an explicit, elevated, out-of-band step — never an app/runtime
  side effect, never an npm/cargo install hook.** The SDK and `wxc-exec` stay
  unprivileged and only *consume* a broker that an administrator/provisioning
  system installed.
- **The SDK gains an unprivileged preflight** (a read-only SCM status probe — see
  Q1) so a consumer gets one clear, actionable error ("broker not installed — run
  `wxc-host-prep install-learning-mode-broker` as admin") *before* a wasted run,
  instead of silently seeing zero denials.
- **Cleanup stays explicit and idempotent** (`uninstall-learning-mode-broker`).
  We do **not** add app-driven ref-counting. We *do* make the privilege grant
  self-describing — enumerate before granting, record whether *we* added
  `SeSystemProfilePrivilege`, and revoke on uninstall only when we did — so an
  uninstall is a safe-by-default revert instead of leaving a permanent residual
  grant.
- **Packaging:** binaries (`mxc-learning-mode-broker.exe`, `wxc-host-prep.exe`)
  ship inside the npm package payload (and, later, are produced by the crate's
  build), but **activation is a documented, separate admin/MDM/CI step**, not an
  install hook.

The rest of this doc justifies each of those choices against the alternatives.

---

## Developer workflow in Windows (high level)

We introduce a new **shared, machine-wide service** whose role is to let
*unprivileged* callers read the ETW traces written when the learning-mode
capability is injected into a process and an access check is **denied**.

The service is managed by **`wxc-host-prep.exe`** — it can be
installed/uninstalled/inspected through it. An application that uses MXC sandbox
capabilities and also wants the **Learning Mode retry** capability runs
`wxc-host-prep.exe` to install the service. If the service already exists the
install is a **no-op**. The service does **not** auto-start at login (it is
Manual/Demand-start; the SCM idle-stops it and the next inbound request restarts
it).

`wxc-host-prep.exe` exists so we can keep **`wxc-exec.exe` unprivileged**: all
elevated machine-state changes live in host-prep. Installation also grants
`SeSystemProfilePrivilege` to `LocalService`. The application is responsible for
running the host-prep **uninstall** as part of its own uninstall flow.

**Distribution.** The npm package payload carries the native binaries
`mxc-learning-mode-broker.exe` and `wxc-host-prep.exe`. (No install hooks — see Q4.)

**Provisioning.** Once per machine, by running `wxc-host-prep
install-learning-mode-broker`. It installs the service and grants the privilege.

**Use.** If the service is missing, an unprivileged SDK preflight **fails fast**
with a message telling the user how to remedy it (run the host-prep install).
Otherwise, when `captureDenials` is `true`, the shared service brokers a scoped,
per-PID ETW session for the workload and denials are collected.

**Uninstall.** Driven by `wxc-host-prep uninstall-learning-mode-broker`. Revokes
`SeSystemProfilePrivilege` only if our install marker recorded that *we* granted
it (track-and-revoke; see Q2).

---

## Application integration: surfacing denials & the approval hook

Provisioning gets the *capability* onto the box; this section is what the
*application* codes against once the broker is installed. It is OS-independent —
the wire shape is identical on every platform the feature lands on — and is the
answer to "how does my app learn a path was denied, and how do I ask the user to
allow it?"

> **The SDK no longer drives this loop.** The native `wxc-exec` binary streams
> denials and the **consumer owns** parsing, consent, and the re-spawn loop.
> The SDK keeps only the generic `createConfigFromPolicy` / `spawnSandboxFromConfig`
> surface plus the `captureDenials` field. A reference implementation of the
> parser, the anonymous-pipe `--denials-fd` transport, the default filters, and policy expansion
> lives in the native E2E harness
> (`src/testing/wxc_e2e_tests/src/denial_consumer.rs`); the descriptions below are
> the contract that harness (and any consumer) implements.

### The denial record

Every denied access surfaces as a typed `DeniedResource` on the wire:

```ts
{
  type: 'denial',
  path: string,                                   // e.g. C:\Users\me\secret.txt
  resourceType: 'file' | 'network' | 'ui' | 'other',
  accessType: 'read' | 'write' | 'execute' | 'unknown',
  pid: number,
  filetime: bigint,
}
```

Records are deduped by `(path, accessType)` upstream, and the consumer's default
filters strip the OS "background hum" (loader DLL probes, etc.) so the
application only sees actionable denials.

### Two delivery modes

- **Real-time, per denial** — each denial is emitted the instant it occurs as its
  own `0x1E`-framed NDJSON `denial` record. The consumer reads these live (off
  `wxc-exec`'s **stderr** in pipe mode, or the anonymous pipe read end paired
  with **`--denials-fd <handle>`** in PTY mode) and can prompt or log per denial mid-run.
- **Consolidated, per run** — the summary terminator line carries the deduped
  `deniedResources` array, giving the consumer a race-free single read after exit.
  This is the batch that powers the approve-and-retry UX below.

### The approval hook

The hook an application uses to ask the user "allow this?" is **consumer-owned** —
it is no longer an SDK callback. The consumer collects the run's denials (live
and/or from the summary), drives whatever approval UX it wants (dialog, CLI
prompt, policy file, …), and decides which paths to grant.

### What the consumer does with the decision

1. If the user **approved** at least one denial, the consumer expands its base
   config — adding exactly those approved paths to
   `filesystem.readonlyPaths` / `readwritePaths` — refusing OS-security-critical
   paths even if approved.
2. It **re-spawns the workload once** with the expanded config (enforcement is
   non-blocking, so a grant only takes effect on the next run — it cannot
   un-fail the already-denied operation).
3. Any paths still denied (or newly hit) surface on the next run, so the
   application can prompt again or surface the final state.

```
spawn (captureDenials: true)
        │
        ▼
denials stream ──► consumer collects + prompts user ◄── returns approved paths
        │
        ▼
consumer expands config with approved paths
        │
        ▼
re-spawn with expanded config ──► still-denied? ──► prompt again (next round)
```

### Guardrails

- **The consumer owns the cadence.** A typical loop caps at one prompt-and-retry
  round; multi-round approval is the consumer's choice. MXC does a single run per
  invocation and never loops on its own.
- **Refuse system-critical paths.** Even if the user approves them, the consumer's
  policy-expansion must skip OS-security-critical paths (SYSTEM hives,
  `kernel32.dll`, …). The reference `expand_readonly_paths` in `denial_consumer.rs`
  does this.
- **PTY mode uses an anonymous inherited-handle transport** (`--denials-fd`) instead of stderr,
  because the workload owns the terminal. The `DeniedResource` shape and the
  approval logic are identical; only the transport differs.

### Complete, copy-paste samples

The end-to-end reference — denial parser (0x1E NDJSON framing), default noise
filters, the `--denials-fd` anonymous-pipe side channel, and additive policy
expansion — lives in **`src/testing/wxc_e2e_tests/src/denial_consumer.rs`**, and
`src/testing/wxc_e2e_tests/tests/e2e_windows_capture_denials.rs` exercises the full
pipe-mode (live stderr), side-channel (anonymous pipe), and multi-round
approve-and-respawn flow against the native `wxc-exec` binary. Consumers
reimplement the same contract in their own language; the TypeScript sketch below
shows the shape for a Node consumer.

Prerequisites:

- Node.js 18+.
- The broker installed once on the machine (the provisioning step):
  `wxc-host-prep install-learning-mode-broker` from an elevated prompt.
- The SDK added as a dependency (for the generic spawn surface only):

  ```bash
  npm install @microsoft/mxc-sdk
  ```

The sketch below shows the consumer-owned loop: build a default-deny config with
`captureDenials: true`, spawn `wxc-exec` via the generic SDK surface, read denials
off stderr (pipe mode), prompt the user, expand the config with approved paths,
and re-spawn.

```ts
import {
  createConfigFromPolicy,
  spawnSandboxFromConfig,
  getPlatformSupport,
  type SandboxPolicy,
} from '@microsoft/mxc-sdk';
// Consumer-owned helpers — you implement these (reference port in Rust:
// src/testing/wxc_e2e_tests/src/denial_consumer.rs):
//   parseDenialStream     — split the 0x1E-framed NDJSON, apply default filters
//   defaultDenialFilters  — drop the OS loader / registry background hum
//   expandPolicyFromDenials — additively grant approved paths, refuse critical ones
import {
  parseDenialStream,
  defaultDenialFilters,
  expandPolicyFromDenials,
} from './your-denial-helpers.js';

async function runRound(policy: SandboxPolicy, script: string) {
  const config = createConfigFromPolicy(policy, 'process');
  config.captureDenials = true;
  config.process!.commandLine = script;

  // usePty:false keeps stdout/stderr separate so the NDJSON denial protocol
  // (which rides stderr) can be demultiplexed from the workload's own writes.
  const child = spawnSandboxFromConfig(config, { usePty: false });
  return parseDenialStream(child.stderr!, {
    filters: defaultDenialFilters,
    onDenial: (r) => console.log(`denied: ${r.accessType} ${r.path}`),
  });
}

async function main(): Promise<void> {
  const support = getPlatformSupport();
  if (!support.isSupported) {
    console.error(`Sandbox not supported here: ${support.reason ?? 'unknown'}`);
    process.exit(1);
  }

  let policy: SandboxPolicy = {
    version: '0.6.0-alpha',
    filesystem: { readwritePaths: [], readonlyPaths: [] },
  };
  const script = 'cmd /c type "C:\\Users\\Alice\\Documents\\report.txt"';

  const result = await runRound(policy, script);

  // captureDenialsActive === false ⇒ the broker wasn't installed/reachable.
  if (result.summary?.captureDenialsActive === false) {
    console.error(
      'Denial capture is not active — install the broker (as admin):\n' +
        '  wxc-host-prep install-learning-mode-broker',
    );
    process.exit(2);
  }

  if (result.denials.length > 0) {
    const approved = await askUserWhichToAllow(result.denials); // consumer UX
    policy = expandPolicyFromDenials(policy, approved);
    await runRound(policy, script); // re-spawn once with the expanded policy
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```

---

## Current behavior (as-is)

This is what exists today, verified against `docs/host-prep.md` and the
`wxc_host_prep` broker install/uninstall implementation.

### The components

| Component | Privilege | Role |
|---|---|---|
| `mxc-learning-mode-broker.exe` (service `MxcLearningModeBroker`) | `NT AUTHORITY\LocalService` + `SeSystemProfilePrivilege` | Loans a scoped, per-PID ETW trace handle to unprivileged callers. **One per machine.** |
| `wxc-host-prep.exe` | Requires elevation (`requireAdministrator` in its manifest) | Installs/uninstalls/inspects the service. |
| `wxc-exec.exe` | Unprivileged | The sandbox launcher. Connects to the broker's named pipe, drives `OpenTrace`/`ProcessTrace`, streams denials. |
| `@microsoft/mxc-sdk` | Unprivileged | Spawns `wxc-exec`, parses the denial stream. |

### Service shape

- **One shared, machine-wide service.** Name `MxcLearningModeBroker`, pipe
  `\\.\pipe\mxc-learning-mode-broker`. It is **not** per-app and **not**
  per-session.
- **Account:** `LocalService` (least-privilege built-in). `LocalService` does
  not carry `SeSystemProfilePrivilege` by default, so install grants it via the
  LSA `LsaAddAccountRights` API. The grant is **persistent** (survives reboots)
  and **idempotent**.
- **Start type:** `Demand`/Manual. SCM idle-shutdown stops the process after a
  period of inactivity; the next inbound pipe request restarts it. So "installed"
  and "running" are different states — a consumer can rely on the service being
  *installed* without it being *running*.

### Lifecycle commands (all elevated)

- `install-learning-mode-broker [--broker-path <source>]` — **copy** the broker binary
  into the protected install location (`%ProgramFiles%\Mxc`), register the service
  to point there, and grant the privilege. `--broker-path` is the **source** to copy
  from (defaults to the binary next to `wxc-host-prep`). Idempotent: re-running with
  the same source refreshes the installed copy; registering a service already
  pointing elsewhere is an explicit conflict (uninstall first).
- `uninstall-learning-mode-broker` — stop + `DeleteService`, and best-effort delete
  the copied binary + its (now empty) install directory. Idempotent.
  **Does not revoke** `SeSystemProfilePrivilege` (another tool on the box may
  rely on it; clobbering an LSA right is destructive).
- `dump-learning-mode-broker [--json]` — report installed/state/binary path. Exit 0
  installed, 1 not.

### Who installs it today?

**Nobody automatically.** Install is a manual, elevated, out-of-band step. The
SDK and `wxc-exec` never install, never elevate, never clean up. When the broker
is absent or unreachable, capture degrades gracefully: the summary line reports
`captureDenialsActive: false` and zero denials stream. The SDK surfaces this flag
specifically so a consumer does not misread "0 denials" as "the workload tripped
no denials" when the truth is "the feature was never active."

### What's missing (the gap the reviewers found)

- No defined **developer workflow** tying "I want captureDenials" to "the broker is
  installed."
- No defined **cleanup ownership** — installs accrete and are never removed; the
  privilege grant never goes away.
- No story for how an **npm/crate** consumer gets the service onto a box.

---

## Q1 — Developer workflow

**Question:** What does a consumer actually do, end to end, to use
`captureDenials`?

### Options

**A. Status quo — purely manual.** The consumer reads the docs, runs
`wxc-host-prep install-learning-mode-broker` from an elevated prompt once, then uses
the SDK. If they forget, they silently get `captureDenialsActive: false`.

- 👍 Zero new code. Clean privilege separation.
- 👎 Poor ergonomics; the failure mode is silent and easy to misdiagnose.

**B. Provisioning-system step.** Same install command, but positioned as a
machine-provisioning action: MDM policy, an image build step, a CI runner setup
script, or a one-time elevated setup wrapper that ships with the consuming app.

- 👍 Matches how privileged machine state is *supposed* to be established
  (once, by something that legitimately holds admin). Auditable.
- 👎 Requires the consumer to own a provisioning channel; nothing the SDK can do
  for an ad-hoc developer on their own box.

**C. SDK preflight + actionable error.** Keep install out-of-band (A/B), but add
an **unprivileged** SDK preflight that checks whether the service is installed
*before* spawning the workload and, when it's missing, throws/returns a typed,
actionable error with the exact remedy command — instead of letting the run
proceed to a silent post-run `captureDenialsActive: false`.

The mechanism must stay unprivileged, so it **cannot** shell out to
`dump-learning-mode-broker`: although that command's underlying SCM query is
read-only, `wxc-host-prep.exe` is `requireAdministrator` and aborts (exit 65) /
prompts UAC when launched unelevated. Instead the preflight queries the SCM
directly read-only — `OpenSCManager(SC_MANAGER_CONNECT)` +
`OpenService(SERVICE_QUERY_STATUS)` — via either a `wxc-exec` probe (extending
the existing read-only `wxc-exec --probe` that `getPlatformSupport()` already
uses) or a direct `sc query MxcLearningModeBroker`. `installed: true` is treated as
OK regardless of run state, since the Manual/Demand service restarts on the next
pipe request. `dump-learning-mode-broker` remains the **elevated operator**
diagnostic.

- 👍 Small, unprivileged, turns a silent post-run failure into a fail-fast with a
  one-line fix. Composable with A or B.
- 👎 Still doesn't *install* anything (by design).

**D. Auto-install from the runtime.** The SDK/`wxc-exec` self-installs the
service on first use.

- 👎 **Rejected.** Requires the runtime to elevate — exactly the design `wxc-exec`
  deliberately abandoned (host-prep owns elevation; `wxc-exec` never
  self-elevates). It would also make every consuming app a machine-state mutator,
  which is a security and supportability regression.

### Recommendation

**B + C.** Position install as an explicit, elevated provisioning step (B), and
add the SDK preflight (C) so the missing-broker case is a clear, actionable error
rather than a silent zero. Keep D off the table.

Concretely, the documented developer workflow becomes:

1. **Provision (once per machine, elevated):**
   `wxc-host-prep install-learning-mode-broker`
   — run by an admin, MDM, image build, or CI setup step.
2. **Develop (unprivileged):** use the SDK / `wxc-exec` normally with
   `captureDenials: true`. The SDK preflight verifies the broker is installed and,
   if not, fails fast with the remedy command.
3. **Run:** denials stream over stderr (or the `--denials-fd` anonymous-pipe side channel in PTY
   mode); the summary reports `captureDenialsActive: true`.

---

## Q2 — Cleanup logic

**Question:** If apps cause the service to be created, what removes it? And what
about the privilege grant uninstall leaves behind?

### The two things to clean up

1. **The service** (`MxcLearningModeBroker`).
2. **The persistent `SeSystemProfilePrivilege` grant** on `LocalService`.

### Options for the service

**A. Leave installed (status quo).** The service is installed once and left;
`uninstall-learning-mode-broker` exists for operators who want it gone. Because the
service is Manual-start with SCM idle-shutdown, an idle installed-but-unused broker
costs essentially nothing at rest.

- 👍 Matches the "provision once" model. No teardown coordination problem.
- 👎 The service lingers after the last consumer is uninstalled; nothing prompts
  its removal.

**B. App-driven ref-counting.** Each consuming app registers/deregisters on
install/uninstall; the last one out removes the service.

- 👎 **Rejected.** Requires a shared, privileged, concurrency-safe ref-count store
  and makes every app a privileged machine-state mutator. High complexity, brittle
  failure modes (crashed app never decrements), and it re-introduces the
  elevation-from-app problem from Q1/D.

**C. Explicit uninstall, owned by whoever provisioned (recommended).** The same
actor that ran install (admin/MDM/image/CI) owns uninstall. Idempotent, safe to
run in teardown scripts.

- 👍 Symmetric with the provisioning model; no runtime coupling.
- 👎 Requires the provisioner to remember teardown (acceptable — it's the same
  actor that did setup).

### Options for the privilege grant

The current uninstall **does not** revoke `SeSystemProfilePrivilege` because
another tool might rely on it and blind revocation is destructive. That is the
safe default, but it means an "uninstall" doesn't fully revert machine state — a
legitimate concern for hardened/clean-revert environments.

- **G1. Never revoke (status quo).** Safe but leaves a residual right.
- **G2. Always revoke on uninstall.** Clean revert, but can break a co-installed
  tool that shares the account/right.
- **G3. Opt-in revoke.** Add `uninstall-learning-mode-broker --revoke-privilege`
  that performs the LSA `LsaRemoveAccountRights` revocation, documented as "only
  safe when no other tool on the box depends on `LocalService` holding
  `SeSystemProfilePrivilege`." Default stays non-revoking. Better than G1/G2 but
  still puts the "is it safe to revoke?" judgement on the operator.
- **G4. Track-and-revoke (recommended).** Make the grant self-describing so revoke
  is safe *by default*:
  1. **At install**, before granting, call `LsaEnumerateAccountRights` on the
     `LocalService` SID and scan for `SeSystemProfilePrivilege`. If it's already
     present, the grant is a no-op and we record **`we_granted = false`**; if not,
     we `LsaAddAccountRights` and record **`we_granted = true`**.
  2. **Persist the marker** across the install→uninstall process boundary — e.g. a
     small state file under `%ProgramData%\mxc\` (host-prep already writes logs
     there for the null-device op) or a registry value.
  3. **At uninstall**, revoke **only when `we_granted == true`**. This reverts to
     the exact pre-install state and never clobbers a grant we did not create.

  The grant code already anticipates this path: `privilege.rs` keeps a
  free-helper around commented "for a future audit/revoke path (e.g. via
  `LsaEnumerateAccountRights`)."

  **Caveats to document:**
  - LSA account rights are a **set, not reference-counted**. If a *different* tool
    independently grants the same privilege *after* us, our marker still reads
    "we added it" and our revoke removes it out from under them. Enumerate-before-
    grant narrows but cannot fully close this cross-tool race — an OS limitation,
    not something we can solve. Within our own ecosystem (one broker, one host-prep)
    it is airtight.
  - The buffer returned by `LsaEnumerateAccountRights` must be freed with
    **`LsaFreeMemory`**, not `LocalFree`.

### Recommendation

**Service: C (explicit, provisioner-owned uninstall).** Do not build
ref-counting. **Privilege: G4 (track-and-revoke).** Enumerate before granting,
persist whether we added the right, and revoke on uninstall only when we did —
giving a safe-by-default revert instead of today's permanent residual grant.
Optionally still expose `--revoke-privilege` / `--keep-privilege` flags for
operators who want to override the tracked decision. Document the cross-tool LSA
caveat in `host-prep.md`.

---

## Q3 — Per-app vs shared service

**Question:** One service per app, or one shared service for all? Is the current
shared model right?

### Options

**A. One shared machine-wide service (status quo).** All consumers talk to the
same `MxcLearningModeBroker` over one well-known pipe.

**B. One service per app / per tenant.** Each consumer gets its own service
instance (distinct name + pipe).

**C. Per-session / per-launch service.** A fresh broker spun up for each sandbox
launch.

### Why isolation does **not** require per-app instances

The instinct behind per-app services is isolation: "app X must not see app Y's
denials, and must not be able to attach to app Y's processes." But that boundary
is **already enforced per call**, not per service instance. From the broker
security model (see `architecture.md`):

- On every `OpenDenialSession(pid)` the broker does
  `ImpersonateNamedPipeClient` then `OpenProcess(pid,
  PROCESS_QUERY_LIMITED_INFORMATION)` **under the caller's token**. If the caller
  cannot open the target via Windows ACLs, the request is rejected
  (`unauthorized`). A caller can therefore only start sessions for processes it
  could already inspect.
- `ExtendDenialSession` requires the caller SID to match the recorded
  session-owner SID, and re-validates every PID through the same impersonation
  check.

So Windows itself — which already models sandbox tokens, RDP sessions, and
multi-user boxes — is the isolation boundary. Splitting into per-app services
would duplicate that boundary at the service layer while adding real cost:

- **Naming/discovery:** every consumer needs a unique service+pipe name and a way
  to discover its own — a coordination problem the single well-known pipe avoids.
- **Privilege multiplication:** N services means N `LocalService` privilege
  grants and N installs/uninstalls to track.
- **ETW ceiling pressure:** Windows enforces a system-wide user-mode ETW session
  ceiling (~64). The broker is a *broker* of sessions, not a session itself, so one
  broker serving many callers is strictly better for that budget than many
  brokers.

Per-session (C) is even worse: it pays the install/elevation cost on the hot
path, which is precisely what the broker model exists to avoid.

### Recommendation

**A — keep one shared machine-wide service.** Isolation is a per-call property
enforced by impersonation, not a property of service instancing. Per-app/per-session
instances add naming, privilege, and ETW-budget cost for no security gain. The
existing "not in scope" hardening follow-up (restricting the pipe ACL to a
process-trust SID via code signing) remains the right lever if we ever need to
narrow *who* may connect — that is orthogonal to instance count.

---

## Q4 — Packaging fit (npm today, Rust crate tomorrow)

**Question:** MXC ships an npm package today and a Rust crate tomorrow. Neither
can register an elevated machine-wide service at install time. How does broker
provisioning fit?

### The core constraint

A package install (`npm install`, `cargo add`/`cargo build`) runs with the
**developer's/CI's normal privileges**, in an arbitrary location, possibly many
times across many projects on one machine. Registering a machine-wide OS service
is an **elevated, machine-singleton, root-owned** action. These two are
fundamentally mismatched. The packaging model can *deliver the binaries*; it must
not *activate* them.

### Options

**A. npm `postinstall` hook installs the service.**

- 👎 **Rejected.** `postinstall` isn't elevated (fails on a standard dev box),
  runs on every `npm install` in every project (machine-singleton violated), is
  widely disabled in CI (`--ignore-scripts`), and turns a library install into a
  privileged machine mutation — a supply-chain red flag. Same reasoning rules out
  a `build.rs`-driven install for the crate.

**B. Ship the binaries in the package; activate separately (recommended).** The
npm package payload already carries the native binaries it spawns; include
`mxc-learning-mode-broker.exe` and `wxc-host-prep.exe` in that payload (and, for the
crate, have the build emit them to a known target dir). Activation is the
documented elevated step from Q1:
`wxc-host-prep install-learning-mode-broker --broker-path <resolved path>`.

- 👍 No elevation in the install path; binaries are present and discoverable;
  activation is explicit and auditable. The `--broker-path` flag points install at
  the packaged broker binary as the **source** to copy into the protected install
  location (`%ProgramFiles%\Mxc`), wherever the package placed it.
- 👎 Consumer must run the separate step (mitigated by Q1's preflight error +
  docs, and by helper scripts below).

**C. Provisioning helpers for the common channels.** On top of B, ship thin,
documented helpers for the realistic activation channels:

- **Dev box:** a one-line elevated command (or a `setup-learning-mode.ps1` helper
  mirroring the existing `scripts/setup-wslc.ps1` pattern) that resolves the
  packaged broker path and runs the install.
- **CI:** a documented runner setup step (the runner already has admin).
- **Fleet/MDM:** the install command as an MDM-pushed configuration action.

### Discoverability detail

The SDK already auto-discovers the native binaries it spawns (npm-packaged
`bin/<triple>/` and local-dev `target/<triple>/{release,debug}/`). The same
resolution should expose the broker/host-prep paths so the helper script and the
preflight error can name the exact `--broker-path` to use, regardless of how the
package was installed.

### Recommendation

**B + C.** Bundle the binaries in the package payload; keep activation as an
explicit elevated step; ship per-channel helpers (dev/CI/MDM) and reuse the
binary-discovery logic so the right `--broker-path` is always available. **No
install hooks** in npm or cargo.

---

## Recommended end-to-end design (stitched)

Putting Q1–Q4 together:

1. **Distribution:** `mxc-learning-mode-broker.exe` + `wxc-host-prep.exe` ship in the
   npm package payload (and are produced by the crate build into the known target
   dir). Install hooks are explicitly *not* used.
2. **Provisioning (once per machine, elevated, out-of-band):**
   `wxc-host-prep install-learning-mode-broker [--broker-path <packaged path>]`,
   run by admin / MDM / image build / CI setup, optionally via a shipped helper
   script. Installs the single shared `MxcLearningModeBroker` service and grants
   the privilege.
3. **Use (unprivileged):** the SDK preflight checks the broker's install state via a
   read-only SCM query (a `wxc-exec` probe or `sc query`, *not* the elevated
   `dump-learning-mode-broker`); if absent, it fails fast with the exact remedy
   command. Otherwise the consumer uses `captureDenials: true` normally; one
   shared service brokers scoped ETW sessions, isolation enforced per call by
   impersonation.
4. **Teardown (elevated, provisioner-owned):**
   `wxc-host-prep uninstall-learning-mode-broker` (idempotent), which by default
   revokes `SeSystemProfilePrivilege` **only if our install marker recorded that
   we granted it** (track-and-revoke). No app-driven ref-counting.

This keeps the runtime unprivileged, the privileged surface tiny and explicit,
the service a single shared broker, and packaging free of elevation.

---

## Open questions for the Tessera review

1. **Helper-script surface:** do we want a first-party `setup-learning-mode.ps1`
   (mirroring `setup-wslc.ps1`) in-repo, or only documented one-liners?
2. **SDK preflight shape:** since the check must be unprivileged (host-prep is
   `requireAdministrator`), confirm the probe mechanism — a `wxc-exec --probe`
   extension vs. a direct `sc query` from the SDK — and whether it returns a typed
   error/exception vs. a capability object (`{ installed, state, remedy }`). And
   should it run automatically when `captureDenials: true`, or be opt-in?
3. **Privilege-grant override:** is track-and-revoke (G4) enough on its own, or do
   we still want explicit `--revoke-privilege` / `--keep-privilege` flags to
   override the tracked decision? And where should the "we_granted" marker live —
   `%ProgramData%\mxc\` state file vs. registry?
4. **CI provisioning ownership:** is broker install part of the MXC test-runner
   image, or a per-pipeline step? (Affects where the e2e tests can run.)
5. **Crate activation parity:** for the future Rust-crate consumer, do we expose a
   small `mxc` provisioning subcommand, or rely solely on `wxc-host-prep`?
6. **Pipe-ACL hardening interaction:** if we later restrict the pipe ACL to a
   process-trust SID (code-signed `wxc-exec`), does that change any of the
   per-app-vs-shared reasoning? (Believed orthogonal; confirm.)

---

## Decision log

To be filled during/after the Tessera review.

| # | Decision | Outcome | Owner | Date |
|---|----------|---------|-------|------|
| Q1 | Developer workflow (B+C: provision step + SDK preflight) | _pending_ | | |
| Q2 | Cleanup (explicit uninstall; track-and-revoke privilege grant) | _pending_ | | |
| Q3 | One shared machine-wide service | _pending_ | | |
| Q4 | Bundle binaries, activate separately, no install hooks | _pending_ | | |

---

## Future work (out of scope)

- **Linux/macOS deployment.** The Linux (`fanotify`+audit) and macOS
  (EndpointSecurity) adapters are stubs today. Their privilege-brokering and
  provisioning stories differ from Windows services and will be designed when
  those adapters are implemented. The cross-platform pieces above the adapter
  (denial channel wire format, SDK preflight concept, "provision out-of-band"
  principle) are intended to carry over.
- **Pipe-ACL narrowing** to a code-signed process-trust SID — tracked as a
  hardening follow-up in `architecture.md`.
