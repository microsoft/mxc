# Debugging workloads inside the process container

Attaching a debugger to a process running inside an MXC sandbox is harder than
debugging a normal process, for reasons that are inherent to containment:

- **You cannot put the debugger in front of the process.** The usual flow — the
  debugger creates the target with `DEBUG_PROCESS` and owns it from instruction
  zero — is unavailable. A sandboxed process must be created by MXC through the
  OS sandbox-creation API with a fully-formed sandbox spec, and a debugger has
  no way to issue that call. Nor can you redirect the launch with a classic
  Image File Execution Options `Debugger` value: that substitutes the debugger
  for the target image, so the debugger would end up running *inside* the
  container, restricted by the very policy you are trying to investigate.
- **Attaching afterwards is usually too late.** The interesting failures — a DLL
  failing to initialize, a config file that cannot be read — happen in the first
  few milliseconds and are over long before you can attach by hand.
- **The workload may not fail *visibly* at all.** Deny-by-default turns a
  missing grant into a generic "Access is denied" deep inside someone else's
  library.

> **What is *not* the problem: access to the process.** Containment restricts
> what the sandboxed process can reach; it does not hide that process from you.
> A same-user debugger can open a running AppContainer process with
> `PROCESS_ALL_ACCESS` without elevation — mandatory integrity control's
> no-write-up rule blocks *low-to-high* access, not the high-to-low direction a
> debugger needs. So if you can catch the process while it is still alive,
> ordinary attach works. The difficulty is one of *timing and launch control*,
> which is exactly what the hook below addresses.

This document covers the techniques available today, in the order you should
reach for them.

> **Platform.** Everything here is **Windows-only** and applies to the
> ProcessContainer backends (classic AppContainer and BaseContainer, which share
> `backends/appcontainer/common`). For the other backends see the
> [per-backend guides](../../README.md#documentation).

## First: which process are you debugging?

| You want to debug | Use |
|---|---|
| **MXC itself** — config parsing, policy mapping, backend/tier selection, launch failure | Attach to `wxc-exec.exe` normally. It is an ordinary unsandboxed process; no special setup is needed. |
| **The sandboxed workload** — your app, once it is running under containment | [Debug on launch](#debug-on-launch) (below). |
| **Neither — you just want to know what the sandbox blocked** | [Learning mode and denial capture](#finding-out-what-the-sandbox-blocked). Usually the right answer, and far cheaper than a debugger. |

A large fraction of "I need a debugger" situations are actually policy gaps.
Try [`--audit`](../learning-mode/capabilities.md#three-learning-mode-flows)
first; it will tell you what the workload tried to touch without you setting
foot in a debugger.

## Debug on launch

The OS-side process sandbox has a **debug-on-launch hook**: a registry-configured
debugger that is started as part of a sandboxed launch. It is the spiritual
counterpart of the classic
[Image File Execution Options](https://learn.microsoft.com/windows-hardware/drivers/debugger/debugging-a-uwp-app-using-windbg)
`Debugger` value, with the one difference that matters here — instead of
*substituting* the debugger for the target image (which would put the debugger
inside the container), it launches the debugger **alongside** the target,
outside the container, and hands it the target's PID.

> **This is a mitigation, not a feature.** It exists to unblock developers until
> a designed solution ships. It is gated off by default (see
> [Enabling the hook](#enabling-the-hook)), the configuration surface is not a
> supported API, and it can change or disappear without notice. Do not build
> tooling on top of it.

### What it does

The **OS sandbox launch path** implements this hook — not MXC. MXC passes an
ordinary sandboxed-launch request; when the hook is enabled the OS changes how
that request is carried out. Nothing in the MXC config turns it on or off.

When the hook is enabled:

1. The sandboxed process is created **suspended**. Its initial thread has not
   run a single instruction, so nothing in the workload's startup path has
   happened yet.
2. The OS reads the debugger command line from the registry (see
   [Configuring the debugger](#configuring-the-debugger)).
3. If a command line is configured, it is launched **under the caller's token**
   — that is, as *you*, outside the sandbox — with the sandboxed process's
   **process ID and thread ID appended**, following the same convention used for
   on-launch debugging of packaged apps:

   ```text
   <configured debugger command line> -p <PID> -tid <TID>
   ```

4. The debugger attaches and resumes the process, and you get control at the
   very first instruction.

If **no** command line is configured, step 3 is skipped and the process simply
**stays suspended**. That is a deliberate escape hatch: you can attach by
whatever means you like and resume manually. Be aware that manually attaching to
the suspended process is known to be finicky — prefer configuring a debugger
command line and letting the hook launch it.

### Enabling the hook

The debug hooks live in their own OS feature group, and the root hook is
**disabled by default on every build**, release branches included. It is only
turned on in internal Windows engineering test runs. On a normal build —
including internal flighting builds — the hook is inert and the registry value
below is never read.

The feature flag IDs are not published here because they are OS-side and change
across branches. To check whether a given feature flag is on, MXC reads the
Windows Feature Store the same way it does for BaseContainer:

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FeatureManagement\Overrides\<priority>\<featureId>
    EnabledState = 2   (REG_DWORD; 2 means enabled)
```

`<priority>` is `4` or `8`. See `check_velocity_keys` in
[`src/backends/appcontainer/common/src/launch_diagnostics.rs`](../../src/backends/appcontainer/common/src/launch_diagnostics.rs)
for the implementation MXC uses to report disabled flags in launch diagnostics,
and [`tests/scripts/README.md`](../../tests/scripts/README.md) for the flags the
E2E suite already depends on.

### Configuring the debugger

Set the debugger command line in:

```text
HKLM\SOFTWARE\wxc
    debugOnLaunch = "<debugger command line>"   (REG_SZ)
```

Writing under `HKLM` requires elevation. The value is a command line, not just
an image path, so you can include switches; the PID/TID arguments are appended
to whatever you put there.

#### WinDbg

WinDbg is the configuration that has been verified end to end — it launches,
attaches, and resumes correctly.

```powershell
# Run elevated. Substitute the path to your own WinDbg install.
$windbg = 'C:\Debuggers\windbgx.exe'

New-Item -Path 'HKLM:\SOFTWARE\wxc' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\wxc' -Name 'debugOnLaunch' `
    -Value $windbg -Type String
```

Because the value is a command line rather than a bare image path, quote it the
way a command line would be quoted if the path contains spaces, and append any
switches you want the debugger to start with.

To turn it back off, remove the value:

```powershell
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\wxc' -Name 'debugOnLaunch'
```

#### Visual Studio

**Not verified.** Visual Studio's on-launch attach path for packaged apps
differs from WinDbg's, and pointing `debugOnLaunch` at `devenv.exe` has not been
confirmed to work. If you need Visual Studio today, the pragmatic route is to
attach it to the still-suspended process (leave `debugOnLaunch` unset) and
resume by hand, accepting the rough edges noted above.

### Caveats

- **Leave it off when you are done.** A stale `debugOnLaunch` value means
  *every* sandboxed launch on the machine tries to spawn a debugger, which will
  look like a hang to anything that runs MXC non-interactively — including test
  suites and CI.
- **The debugger is not contained.** It runs under your token, outside the
  sandbox, by design: a debugger inside the container could not do its job.
  Consequently, what you can see and touch from the debugger does **not**
  reflect the sandbox's restrictions. Do not use the debugger's own view as
  evidence of what the workload is allowed to do.
- **The suspended window is real.** Anything with a timeout around sandbox
  startup — including MXC's own `process.timeout` — is still counting while you
  sit at the first instruction. Set `process.timeout` to `0` (no timeout) while
  debugging.

## Forcing learning mode without editing the config

The same debug hook group includes an **inject-learning-mode hook**. When
enabled, it adds one of the two learning-mode capabilities to every sandboxed
launch:

| Variant | Capability injected | Enforcement |
|---|---|---|
| 1 | `learningModeLogging` | **Unchanged** — accesses stay denied, denials are recorded. |
| 2 | `permissiveLearningMode` | **Relaxed** — every access check is allowed and recorded. |

If the launch already names one of the two capabilities explicitly, the hook
leaves it alone; it never overrides an explicit choice.

This exists for the case where you do not control the config being passed to
MXC — an app generates it, or it is baked into a harness — but you still need to
see what the workload is reaching for. When you *do* control the config, prefer
the supported entry points instead:
[`processContainer.learningMode`](../learning-mode/capabilities.md#how-to-enable-them)
for deny-and-record, or `wxc-exec --audit` for permissive audit.

> **Variant 2 turns off deny-by-default** for every sandboxed process on the
> machine while it is enabled — not just the one you are debugging. It is a
> machine-wide weakening of containment. Turn it off as soon as you are done,
> and never enable it on a machine handling anything you care about.

See [Learning-mode capabilities](../learning-mode/capabilities.md) for what the
two capabilities mean, how the resulting events are collected, and the shape of
the denials output.

## Finding out what the sandbox blocked

Before reaching for a debugger, use the machinery built for exactly this
question:

| Tool | Use it for |
|---|---|
| [`wxc-exec --audit`](../learning-mode/capabilities.md#three-learning-mode-flows) | Bringing a new workload up. Runs permissively, records every access check, and emits `denials.json` plus an `Adjusted_*.json` config with the missing grants already filled in. |
| [`captureDenials`](../learning-mode/capabilities.md#relationship-to-denial-capture) | Programmatic capture from an app or test. `mode: "block"` keeps enforcement on; `mode: "allow"` audits. Returns a structured path to the denials document. |
| [Diagnostics console](../diagnostics.md) | Watching a run live. `MXC_DIAG_CONSOLE=1` plus `mxc-diagnostic-console.exe` streams the parsed request, sandbox spec, process lifecycle, and OS-side ETW events in one window. BaseContainer only. |

The denials document names the resource in a form you can paste straight back
into a policy — an absolute path for files, the capability name for
capabilities — so the loop is usually "audit, copy the grant, re-run" rather
than "single-step through startup".

## Common launch failures

If the workload never gets far enough to debug, check these first. MXC already
detects each one and reports it as a launch diagnostic, so read `wxc-exec`'s
error output before attaching anything.

| Symptom | Cause | Fix |
|---|---|---|
| `packaged_app` | The target is a packaged (MSIX) app. Packaged apps cannot be launched inside a container. | Install an unpackaged build. |
| `dll_init_failed_ui_required` — exit code `0xC0000142` (`STATUS_DLL_INIT_FAILED`) from PowerShell | The sandbox is blocking Win32k syscalls, which PowerShell needs to initialize. | Set `ui.allowWindows: true`. |
| `missing_filesystem_access` | `pwsh.exe` before 7.7 needs read-only access to the drive root to start. | Add the drive root to `readonlyPaths`, or upgrade to pwsh 7.7+. |
| `feature_not_enabled` — `E_NOTIMPL` from the sandbox API | The BaseContainer feature is not enabled on this build. | Enable the required feature flags, or accept the automatic AppContainer fallback. |

The heuristics behind these live in
[`launch_diagnostics.rs`](../../src/backends/appcontainer/common/src/launch_diagnostics.rs).

## Related documentation

- [Learning-mode capabilities](../learning-mode/capabilities.md) — what gets
  recorded, and the three consumption flows
- [MXC diagnostics](../diagnostics.md) — live cross-layer tracing and log
  collection
- [Process Container: adding OS features](./guide.md) — the MXC ↔ OS FlatBuffer
  contract
- [Windows OS-version policy support](./os-version-support.md) — which policy
  aspects each Windows release can actually enforce
