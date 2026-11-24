# Productizing Windows Sandbox workload privilege separation

> **Audience:** MXC developers

**Status:** Proposed implementation plan; no production implementation yet.
**Handling:** Confidential, local-only investigation material. Do not publish,
commit, push, or attach to a public issue or PR without explicit authorization.
**Baseline:** `5c331f2f6c3b09fee8cb9f2e5c68df4596455957`.

## Objective and scope

Close the network-policy bypass in the Windows Sandbox backend by running every
workload under a separate, local standard-user account inside the guest. Keep
the guest controller elevated so it can configure and retain control of the
firewall and manage workload processes.

The change covers both create-and-run execution and container lifecycle
operations. They must use the same guest workload launcher. Keep the existing
authenticated TCP control and stdio transport; networking remains enabled.

Writable folders deliberately mapped for workloads remain writable. Making those
folders private from workloads is not a goal. Protect only the controller code,
credentials, authentication material, and authority needed to enforce networking.
Likewise, this is not a general guest filesystem isolation redesign.

No new network policy, administrator-workload option, public SDK API, schema
field, host account, custom driver, transport, or backend promotion is proposed.
This closes the demonstrated administrator/firewall bypass; it is not a claim
to prevent every Windows privilege-escalation vulnerability.

## Evidence and remaining work

The standalone prototype demonstrated a guest standard account that could not
disable/reset the firewall, stop its service, create a privileged service, or
access the protected controller's files and process authority. Known-reachable
host HTTP and external HTTPS became unreachable under lockdown, while the
permitted management TCP connection remained operational. Fresh launch,
repeated execution, timeout, cancellation, and missing-credential failure were
also exercised in the harness.

That evidence does not establish that the Rust product launcher, public
execution paths, supported Windows builds, or packaged binaries work correctly.
In particular, the prototype's standard-user launch and native suspended/job
launch were separate implementations. Combining those properties in the
production launcher is an explicit prerequisite, not an already-proven result.

Local prototype and evidence:
`C:\Users\mgudgin\.copilot\session-state\310fb226-b195-45e4-b10a-67d68e63db62\files\wsb-lab`.
Start with `results.json`, `Guest-Bootstrap.ps1`, `LabAgent.cs`,
`NativeWorkload.cs`, and the `option1-final-*` results.

## Current integration points

Paths below are relative to the repository root.

| Area | Current location and required change |
|---|---|
| VM/bootstrap generation | `src\mxc-sdk\src\backends\windows_sandbox\lifecycle\vm.rs`: launches the guest through `bootstrap.cmd` in the writable rendezvous mapping. Remove writable executable bootstrap input from the trusted launch chain. |
| Mapped-path validation | `src\mxc-sdk\src\backends\windows_sandbox\lifecycle\policy.rs`: account for trusted bootstrap/controller roots when checking mapping conflicts, not just conflicts between user mappings. |
| Guest startup | `src\mxc-sdk\src\bin\windows_sandbox_guest\main.rs`: consumes nonce, opens/authenticates channels, locks down firewall, enters executor. Initialize the workload identity and controller protection before announcing readiness. |
| Workload launch | `src\mxc-sdk\src\bin\windows_sandbox_guest\executor.rs`: currently launches `cmd.exe /C` with the controller identity using `tokio::process::Command`. Replace this launch, not the surrounding protocol. |
| Process ownership | `src\mxc-sdk\src\bin\windows_sandbox_guest\job.rs`: currently assigns a running process by PID on a best-effort basis. Make the replacement launch own native handles and require job assignment before execution. |
| Firewall | `src\mxc-sdk\src\bin\windows_sandbox_guest\firewall.rs`: preserve management connectivity; explicitly enable and verify lockdown and protect its executable/tool resolution. |
| Authentication | `src\mxc-sdk\src\backends\windows_sandbox\common\auth.rs`: nonce deletion currently warns and continues. A nonce left workload-readable must prevent workload readiness. |
| Host connection | `src\mxc-sdk\src\backends\windows_sandbox\lifecycle\bridge.rs`: already waits for `Ready`. Preserve framing and expose actionable startup failures through existing diagnostics and errors. |
| Validation | Extend both `tests\scripts\run_windows_sandbox_one_shot_tests.ps1` and `tests\scripts\run_windows_sandbox_state_aware_tests.ps1`. |
| Scheduled validation | `scripts\ci\run_backend_validation_tests.ps1` currently dispatches only the create-and-run suite for this backend. `validation-test-matrix.json` does not currently schedule Sandbox nightly. |

Keep new implementation guest-specific, preferably small `identity.rs` and
`process.rs` modules beside the executor. Reuse existing Windows handle and ACL
helpers where they fit; do not introduce backend cross-dependencies or a
general-purpose credential-launch framework.

## Proposed design

### Guest identity and readiness

a. On each fresh guest boot, create a workload-only local account using native
Windows account APIs and a cryptographically generated password. Use SIDs for
ACLs and group checks rather than localized account/group names. Do not add the
account to Administrators or grant privileged logon rights.

b. Treat unexpected existing accounts or private-directory state as startup
errors unless ownership and configuration can be established safely. Do not
reuse a possibly altered identity silently.

c. Create a protected guest-local controller root with an explicit, protected
DACL before placing secrets or mutable trusted state there. Do not rely on
inherited permissions from `C:\` or on a mapped folder's displayed guest ACL.
The controller executable and any privileged dependencies must be immutable
to the workload, whether kept on the read-only payload mapping or protected
guest-local storage.

Choose private roots outside workload mappings. Reject mappings that would
shadow or contain required trusted controller/bootstrap paths before launching
the VM, and verify the actual guest paths before use. This narrowly protects the
network controller; it does not restrict ordinary workload data mappings.

d. Prefer retaining the authenticated workload token and needed credentials in
controller memory, rather than a password file. Do not put credentials in
command lines, environment blocks, logs, shared mappings, or protocol messages.
Use owned handles and clear secret buffers when their lifetime ends.

e. Consume the existing launch nonce before starting any workload and verify
that no workload-readable copy remains in rendezvous. Make failure to remove
that copy fatal to readiness. Do not assume host-only ACLs distinguish guest
accounts accessing the same mapping.

f. Verify the workload token's SID, group membership, integrity level,
privileges, and absence of an administrator linked token. Establish and verify
firewall lockdown before sending the existing `Ready` message. No failure may
fall back to the controller identity.

g. Reuse the account/profile for repeated lifecycle executions in the same VM.
Destroying that VM discards the account. A fresh create-and-run invocation or
fresh lifecycle VM gets fresh credentials; no host account is created.

### Trusted bootstrap and controller operations

a. Change `.wsb` startup so the first executable/script comes from a read-only
trusted payload, not the writable rendezvous mapping. Prefer invoking the
already read-only guest executable directly and moving necessary bootstrap
logging into the agent. If a script remains necessary, stage it read-only.
Keep rendezvous for bounded data/diagnostics, never privileged executable input.

b. Launch privileged helpers through trusted absolute system paths. Do not
resolve `netsh`, cleanup tools, DLLs, or scripts through workload-writable
`PATH`, working directories, profiles, or temporary directories. Do not let a
workload's requested working directory change the controller's own directory.

c. Ensure workload processes cannot open the controller for token duplication,
process injection, memory access, or handle duplication. Prevent inheritance of
controller tokens, sockets, jobs, files, and authentication material. Pass only
the child-side stdio handles needed by the workload.

d. Keep privileged operations internal to the controller. Do not add a generic
elevated command endpoint or an administrator retry path for workload failures.

### Workload launcher

a. First establish which native Windows launch API works in the stock guest
under its actual controller token. Compare an explicit local logon/token plus
process creation with `CreateProcessWithLogonW` as needed. Verify required
privileges, profile handling, stdio redirection, suspended creation and handle
inheritance together. API choice is a bounded implementation prerequisite;
do not assume an elevated token has every required privilege.

b. Replace the existing spawn in `execute_script` with one guest-local launcher
that creates the process as the validated standard identity, suspended. Retain
the original process/thread handles, assign the process to a kill-on-close job,
then resume it. Failure at any step terminates the suspended process, releases
resources, and returns an execution/startup error.

c. Adapt the owned pipe handles to the existing Tokio stdio bridges. Preserve
command-line quoting, stdin EOF, separate stdout/stderr, exit status, bounded
drain, and error mapping. Do not route normal execution through the lab's
PowerShell/.NET controller or mapped-folder request protocol.

d. Use a standard-user environment and profile with workload-writable temp and
default work directories. Honor supported requested working directories and
mapped paths. Do not leak controller-only environment values or silently fall
back to an elevated profile. Document expected identity/profile differences;
do not accidentally add previously unsupported environment customization.

e. Keep the job owned by the active execution. Timeout, cancellation,
controller disconnect, controller exit and ordinary child exit must clean up
descendants and pipes according to existing execution semantics. Surface
cleanup failures. Remove dependence on a privileged `taskkill` fallback for
the new launcher; job assignment must not be best-effort.

### Firewall behavior

a. Preserve default-deny guest networking and the existing host IP/listener-port
management exception. Explicitly enable the firewall for every profile and
verify the effective policy before readiness; a command returning success is
not the sole evidence of enforcement.

b. Pre-authorize the trusted controller before binding, with no interactive
firewall prompt. Treat failure as startup failure rather than continuing into
an unattended prompt or uncertain initialization state.

c. Constrain management rules to the protected controller executable where
supported, and reserve the management listener exclusively. Test whether a
standard workload can bind/reuse the allowed source port or otherwise exploit
the management exception to reach other host services. Passing only the
firewall-disable regression is insufficient.

d. Keep control and all three stdio channels working across repeated `exec`
reconnections. Network/firewall mutation failures are workload results, not
controller failures, and must not break subsequent ordinary commands.

## Compatibility and release treatment

The intended default is standard-user execution for every Windows Sandbox
workload, through both execution modes and every currently authorized entry
point. Do not add an opt-out that restores administrator workload execution.

Commands requiring guest administrator rights will stop working. User identity,
profile paths, `HKCU`, temp paths and some file permissions will change. Record
these intentional differences and their effect on existing examples/tests.
Ordinary mapped-folder read/write behavior must remain intact.
Mappings that overlap trusted controller/bootstrap paths must fail explicitly,
rather than weakening controller protection; document that compatibility limit.

Propose treating this as a documented security-servicing correction to the
backend's existing network-isolation promise. Obtain maintainer agreement on
that compatibility/release treatment before implementation; do not assume that
unchanged JSON makes the behavior change automatically backward-compatible.
Follow the repository's design approval process for changed enforcement.
Keep this planning/review confidential until publication is authorized.

Preserve accepted request shapes, experimental authorization, supported
execution modes and error envelopes. Do not edit stable schemas, invent a
workload-user configuration field, or enable Windows Sandbox in SDK surfaces
that currently reject experimental backends. If the agreed design later needs
an API/contract change, resolve that separately before implementing it.

## Delivery sequence

Each item is a reviewable, buildable change. Keep any published review history;
do not create a public issue, PR or branch stack as part of this local plan.

| Item | Work | Exit criterion |
|---|---|---|
| a | Agree on compatibility and confidential design scope; validate native standard-user suspended launch, redirected stdio, safe inheritance and job assignment in the stock guest. | The API path and required privileges are known, or a specific blocker is recorded. No production security claim yet. |
| b | Add identity/private-state ownership and integrate the shared standard-user launcher, job-before-resume, bootstrap trust and readiness checks. Include ordinary execution and launch-failure tests. | Both real execution modes run as the standard account; initialization/launch failures never run as administrator. Do not present an unused helper as completion. |
| c | Complete effective firewall verification and management-exception containment, with reachable-control network regressions and repeated-execution recovery. | The original bypass fails through the real backend, permitted management remains functional, and alternate use of the management exception is blocked. |
| d | Wire both suites into suitable scheduled validation; update backend/reference and compatibility documentation. | Required scenarios actually execute on a Sandbox-capable scheduled host, with recorded results and no green skip-only run. |

Items b and c together constitute the security fix and must ship together.
Item d is a release gate, not optional follow-up coverage.

## Validation and definition of done

### Regression and functional coverage

Extend the existing suites, sharing only genuinely common fixtures. Drive the
actual `wxc-exec --experimental` create-and-run and lifecycle flows, not a
standalone guest harness substituted for the product. Use supported request
contracts and preserve the existing experimental authorization gates.

| Area | Required assertions |
|---|---|
| Identity | Workload and descendants are the expected standard SID, non-admin, with no linked elevated token. Controller remains privileged. No workload account appears on the host. |
| Original bypass | Workload attempts firewall disable/reset, policy modification and service stop; those fail, effective policy stays enabled/default-deny, and blocked traffic remains blocked. Show the meaningful regression failing before the fix and passing after it. |
| Controller protection | Workload cannot read credentials/nonce, replace trusted code, obtain privileged controller process/token handles, or inherit controller handles. An intentionally writable workload mapping remains usable. |
| Real network controls | A test-only elevated fixture, unavailable to workload commands, demonstrates host-service and pinned external reachability before the restrictive policy; then the real standard workload cannot reach them under lockdown. Do not expose a production administrative test command. Keep controls close enough in time to distinguish network outages from enforcement. |
| Network paths | Exercise host non-management services and external TCP/UDP; exercise IPv6 when a valid allowed control exists. DNS is a separate check, never the only isolation assertion. A required unavailable control produces an explicit inconclusive/failing gate, not an isolation pass. |
| Management exception | Workload cannot reuse the allowed source port/program exception for arbitrary host traffic. Authenticated control, stdin/stdout/stderr, reconnects and repeated `exec` still work. |
| Execution behavior | `cmd` and PowerShell, quoting, requested working directory, Unicode paths/output, stdin EOF, nonzero exit, separate streams, large output, intended read-only/read-write mappings and ordinary descendants. |
| Lifetime | Timeout, caller cancellation/disconnect, early child exit with surviving descendants, controller termination, subsequent lifecycle `exec`, stop and deprovision. Verify process-tree and pipe cleanup, not just a nonzero result. |
| Failure closed | Account creation/logon, private ACL setup, nonce removal, token validation, firewall setup/verification, process creation and job assignment failures cannot launch a workload elevated. Use internal fault seams, not a public security-bypass switch. |
| Freshness | Repeat on fresh guests and across stop/start and independent create-and-run invocations; no stale credentials, weakened policy, leaked handles or surviving test-owned VM. |
| Packaging/platform | Test the packaged guest/daemon pair, supported Windows Sandbox hosts and every architecture MXC actually ships/supports for this backend. The lab's single nested-VM build is not the support matrix. |

Network fixtures must have bounded waits, narrowly scoped temporary host rules,
and ownership-scoped cleanup. Pre-authorize listeners before binding to avoid
the interactive prompt encountered in the lab. Capture addresses used and
control outcomes; do not classify intermittent DNS or unreachable services as
enforcement success. Never kill unrelated Sandbox sessions during validation.

### Commands and CI

Planned developer commands, not commands run for this documentation change:

```powershell
# From src, in the documented Windows build environment:
cargo fmt --all -- --check
cargo build -p mxc-sdk --bin wxc-windows-sandbox-guest --bin wxc-windows-sandbox-daemon
cargo test -p mxc-sdk --bin wxc-windows-sandbox-guest
cargo test -p mxc-sdk --lib -- windows_sandbox
cargo clippy -p mxc-sdk --all-targets -- -D warnings

# From the repository root; builds/stages the executor and its sidecars:
.\build.bat
.\tests\scripts\run_windows_sandbox_one_shot_tests.ps1 -BinDir <built-binary-directory>
.\tests\scripts\run_windows_sandbox_state_aware_tests.ps1 -WxcExePath <built-binary-directory>\wxc-exec.exe
```

Replace placeholders with the actual staged binary directory; record each exact
command, architecture, Windows build, result and executed scenario set during
implementation. Add focused unit tests for nontrivial token, handle and failure
ownership logic, but do not use them as a substitute for guest enforcement tests.

Before using the existing functional scripts on a shared host, make the touched
fixtures safe for that environment: their current broad stale-process cleanup
must not terminate unrelated Sandbox owners or erase unrelated lifecycle state.
Use the backend's ownership proof and fail clearly when the single slot is busy.

The validation runbook currently marks Windows Sandbox blocked because runner
images lack the optional feature. Supply a suitable runner image/pool, extend
the dispatcher to run both suites serially, and add Sandbox to the corresponding
nightly trigger. Require the new scenarios to execute, not merely return zero
because a prerequisite caused the suite to skip. If that infrastructure is not
available, record the release gate as blocked instead of claiming CI coverage.

### Documentation and completion

Update the canonical backend guide and reference to describe the standard-user
workload, elevated controller, network guarantee, intentional admin/profile
compatibility changes, prerequisites and actionable startup errors. Update the
versioning document with the agreed servicing treatment and the validation
runbook with what scheduled tests actually prove. Keep detailed reproduction
material confidential until authorized for disclosure.

Done means the actual MXC backend passes the coverage above in both execution
modes, packaged artifacts use the fixed path, scheduled coverage is operational,
and no failure path executes workload code as the elevated controller. Preserve
ordinary writable mappings. Leave no experiment-owned host account, firewall
rule, listener or VM behind. A successful lab harness alone does not meet this
definition.
