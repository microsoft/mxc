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
debugger that is started as part of a sandboxed launch. It is configured through
[Image File Execution Options](https://learn.microsoft.com/windows-hardware/drivers/debugger/debugging-a-uwp-app-using-windbg)
(IFEO), but through its own value — **not** the classic `Debugger` value, and the
distinction is the whole point. `Debugger` *substitutes* the named program for
the target image, which here would run the debugger **inside** the container,
restricted by the very policy you are trying to investigate. This hook instead
launches the debugger **alongside** the target, outside the container, and hands
it the target's PID.

> **This is a mitigation, not a feature.** It exists to unblock developers until
> a designed solution ships. It is off by default (see
> [Availability](#availability)), the configuration surface is not a
> supported API, and it can change or disappear without notice. Do not build
> tooling on top of it.

### What it does

The **OS sandbox launch path** implements this hook — not MXC. MXC passes an
ordinary sandboxed-launch request; when the hook is enabled the OS changes how
that request is carried out. Nothing in the MXC config turns it on or off.

When the hook is enabled:

1. The sandboxed process is created and its initial thread is **suspended**, so
   nothing in the workload's startup path has run yet.
2. The OS looks up the debugger command line under the **target executable's**
   IFEO key (see [Configuring the debugger](#configuring-the-debugger)).
3. If a command line is configured, it is launched **under the caller's token**
   — that is, as *you*, outside the sandbox — with the sandboxed process's
   **process ID and thread ID appended**, following the same convention used for
   on-launch debugging of packaged apps:

   ```text
   <configured debugger command line> -p <PID> -tid <TID>
   ```

4. The debugger attaches and **is responsible for resuming** the target. You get
   control at the very first instruction.

If **no** debugger command line is configured for that executable, the hook
drops the suspend and the process runs normally. There is no "leave it suspended
and attach by hand" mode: without a configured debugger you get an ordinary
launch, so configuring the value is the only way to use this hook.

### Availability

The debug-on-launch hook is **off by default and is not available on generally
available Windows builds**. It is a developer aid that only functions in
specific internal development configurations. Nothing in the MXC config, CLI, or
SDK turns it on, and how it is enabled is out of scope for this document.

The practical test is behavioral: with the hook active and a debugger configured
for your executable, a sandboxed launch visibly stops and your debugger comes up
before the workload runs. If the workload instead runs straight through, either
the hook is not active on your build or the value below is not set for that
executable. If you believe you should have access to it and do not, ask through
the usual internal channels rather than trying to enable it yourself.

### Configuring the debugger

The debugger command line is read from the **target executable's** Image File
Execution Options key, under a dedicated `SecurityEnvironmentDebugger` value:

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<yourapp.exe>
    SecurityEnvironmentDebugger = "<debugger command line>"   (REG_SZ)
```

Two consequences worth internalizing:

- **It is scoped to one executable**, keyed by image name — not to MXC, and not
  to sandboxed launches in general. Set it on the program you actually want to
  debug. Note that this is the *sandboxed workload's* exe, not `wxc-exec.exe`.
- **It does not collide with normal IFEO debugging.** `SecurityEnvironmentDebugger`
  is a separate value from `Debugger`, so setting it does not change how the
  program behaves when launched outside a sandbox.

Writing under `HKLM` requires elevation. The value is a command line rather than
a bare image path, so you may include switches; the PID/TID arguments are
appended to whatever you put there.

#### WinDbg

WinDbg is the configuration that has been verified end to end — it launches,
attaches, and resumes correctly.

```powershell
# Run elevated. Substitute your executable and your WinDbg install path.
$exe    = 'myapp.exe'
$windbg = 'C:\Debuggers\windbgx.exe'
$key    = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe"

New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name 'SecurityEnvironmentDebugger' -Value $windbg -Type String
```

If the debugger path contains spaces, quote it the way a command line would be
quoted.

To turn it back off, remove the value:

```powershell
Remove-ItemProperty -Path $key -Name 'SecurityEnvironmentDebugger'
```

#### Visual Studio

**Not verified.** Visual Studio's on-launch attach path for packaged apps
differs from WinDbg's, and pointing `SecurityEnvironmentDebugger` at Visual
Studio has not been confirmed to work. Use WinDbg unless you are prepared to
work out the Visual Studio invocation yourself.

### Caveats

- **Remove the value when you are done.** A stale `SecurityEnvironmentDebugger`
  makes every *sandboxed* launch of that executable spawn a debugger, which
  looks like a hang to anything running MXC non-interactively — test suites and
  CI included. Because the value is keyed by image name, this bites hardest on
  common interpreters: setting it on something like `python.exe` or
  `pwsh.exe` affects every sandboxed run of that interpreter, not just yours.
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

There is also an **inject-learning-mode hook**, subject to the same
[availability](#availability) constraints as debug-on-launch. When active, it
adds one of the two learning-mode capabilities to every sandboxed launch:

| Mode | Capability injected | Enforcement |
|---|---|---|
| Non-permissive | `learningModeLogging` | **Unchanged** — accesses stay denied, denials are recorded. |
| Permissive | `permissiveLearningMode` | **Relaxed** — every access check is allowed and recorded. |

If the launch already names either capability explicitly, the hook leaves it
alone; it never overrides an explicit choice.

This exists for the case where you do not control the config being passed to
MXC — an app generates it, or it is baked into a harness — but you still need to
see what the workload is reaching for. When you *do* control the config, prefer
the supported entry points instead:
[`processContainer.learningMode`](../learning-mode/capabilities.md#how-to-enable-them)
for deny-and-record, or `wxc-exec --audit` for permissive audit.

> **The permissive mode turns off deny-by-default** for every sandboxed process
> on the machine while it is active — not just the one you are debugging. It is
> a machine-wide weakening of containment. Turn it off as soon as you are done,
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
