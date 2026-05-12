# Downlevel-fallback threat model (Tier 3)

This document states what the Tier 3 fallback (`appcontainer-dacl`) is
designed to defend against, what it explicitly does not, and the
qualitative gaps versus Tier 1 (`base-container`). It exists so that
callers choosing between MXC isolation tiers — or operators auditing
agent runs — can reason about residual risk without having to
re-derive it from the implementation.

Scope: this document covers only the WXC executor's tier-selection
fallback chain. Linux (LXC), macOS (seatbelt / state-aware), MicroVM,
Hyperlight, and Isolation-Session paths have their own threat models.

## Tier summary

| Tier | Mechanism                                                | When selected |
|------|----------------------------------------------------------|---------------|
| T1   | `Experimental_CreateProcessInSandbox` (BaseContainer)    | Preferred when the API is present |
| T3   | AppContainer + host-DACL augmentation                    | Fallback when T1 absent |

Tier 2 (AppContainer + `bfscfg.exe`) was removed in phase 4.5 — see
that PR for rationale. On post-25H2 Windows builds T1 is preferred;
on pre-T1 builds T3 is the fallback. There is no environment in
which T2 would be the right answer.

## What T3 is

A T3 run executes the agent's script inside a Windows AppContainer
process whose access to host paths is governed by ACEs added to the
host filesystem's DACLs for the duration of the run, then restored.

- **Principal:** an AppContainer SID derived from the configured
  container name. Low-trust by default; opt-in capabilities
  (`internetClient`, etc.) widen what kernel services accept.
- **Filesystem policy:** rw paths, ro paths, denied paths from the
  policy are translated into Allow / Allow-read-only / Deny ACEs for
  the AppContainer SID on each path. Applied before the child runs;
  removed when the runner returns (or by the orphan-reaper on a
  subsequent MXC start if the runner crashed).
- **UI policy:** `JOB_OBJECT_UILIMIT_*` bits applied via a Job Object
  attached to the suspended child before `ResumeThread`. When
  `ui.disable=true`, the Win32k syscall-disable mitigation is also
  applied via `UpdateProcThreadAttribute` before the child runs any
  user-mode code.
- **Network policy:** the existing network-manager surface (proxy
  insertion, optional capability-based blocking).
- **Lifetime:** `DaclManager`'s `Drop` removes the ACEs after the
  child exits. State files at
  `%LOCALAPPDATA%\Microsoft\MXC\dacl-restore\<run-id>.json` are
  written before each ACE application and consumed by the
  orphan-reaper at MXC startup, so a crash mid-run is recoverable.

## In scope (what T3 defends against)

T3 is designed to prevent the agent's script from:

1. **Reading host filesystem content** outside the rw + ro path set.
   DACL deny ACEs and the AppContainer baseline together restrict
   read access.
2. **Writing host filesystem content** outside the rw path set. Same
   mechanism.
3. **Acquiring stronger privileges** than the AppContainer SID's
   default by abusing UI subsystem entry points (clipboard, input
   injection, system-settings change, display-settings change,
   foreign UI handle use, desktop switch, logoff/shutdown,
   input-method-editor changes, Win32k syscall surface). UILIMIT bits
   gate these.
4. **Initiating an interactive logoff or shutdown** of the host
   session. `JOB_OBJECT_UILIMIT_EXITWINDOWS` short-circuits
   `ExitWindowsEx` before any session-side dispatch.
5. **Persisting host modifications across the run boundary** beyond
   files written into rw paths. The host's DACL state is restored on
   normal exit; the orphan-reaper handles abnormal exit.
6. **Tampering with `bfscfg.exe`** by indirect call. T3 never invokes
   `bfscfg.exe` — phase 4.5 removed every call site. (This is a
   25H2-specific concern: on 25H2 the binary is present but fatal.)

## Out of scope (what T3 does not defend against)

These are explicit non-goals. If your threat model includes any of
them, T3 is not the right tier.

1. **Filename guess-and-check.** A child that already *knows* (or
   guesses) a filename inside a granted path can confirm its
   existence via path-by-name lookup (`if exist <known-path>`).
   Granted-path file metadata is openable by name. This is a
   weak leak — the child needs prior knowledge — but it does mean
   names of files inside rw/ro paths are not secret from the child.

   This was originally formulated as a broader "enumeration" risk;
   see the *Empirically resolved* section below for what 25H2
   actually permits.

2. **Side-channel attacks via shared kernel namespace.** T3 inherits
   the host's:
   - Object Manager namespace (events, mutexes, sections, named
     pipes, mailslots are visible by name)
   - Process and thread enumeration (`CreateToolhelp32Snapshot`,
     `NtQuerySystemInformation`)
   - Registry (HKLM keys with ACLs that grant the AppContainer SID
     are reachable; HKCU is the launching user's hive)

   AppContainer adds integrity gating but not isolation. A
   determined attacker can use these surfaces for reconnaissance.

3. **Tampering with other AppContainer profiles** that share the
   same `container_id`. Concurrent MXC runs against the same
   container name share an AppContainer profile and SID. T3
   serializes ACE mutations on shared paths via per-path named
   mutexes, but two concurrent runs with the same container_id
   against overlapping paths is undefined-behavior territory.

4. **Resource-exhaustion attacks on the host.** T3 does not apply
   `JOB_OBJECT_LIMIT_PROCESS_MEMORY`, `JOB_OBJECT_LIMIT_PROCESS_TIME`,
   `JOB_OBJECT_LIMIT_JOB_OBJECT_TIME`, or active CPU rate-controls.
   A script can consume host resources. T1's spec also does not
   currently impose these.

5. **Filesystem state visible to other processes during the run.**
   T3 mutates real host ACLs for the run's duration. Other processes
   on the host see the modified ACLs while the run is in flight. If
   a service or a parallel user happens to read those ACLs, they
   observe state that didn't exist a moment earlier and won't exist
   a moment later.

6. **TOCTOU between ACL apply and process create.** The sequence is
   "apply ACEs → CreateProcessW (suspended) → assign Job Object →
   ResumeThread." Not atomic. A parallel actor racing with the ACL
   apply could observe partial state. Mitigated for parallel MXC by
   the per-path mutex; not eliminated for arbitrary external actors.

7. **Symbolic-link / junction-point attacks where the attacker
   controls the link target.** If the rw set includes a directory
   the agent can write to, and that directory permits creating
   symlinks (rarely, by default), the agent could try to redirect a
   later operation to a foreign target. The runtime relies on
   Windows' own symlink-creation privilege gating; T3 does not add
   defenses here.

8. **Persistence via the AppContainer profile.** The profile
   continues to exist after the run; only the ACEs are removed.
   Anything the agent wrote to AppContainer-local storage
   (`%LOCALAPPDATA%\Packages\<profile>\`) survives. By design — same
   on T1.

## Qualitative gaps versus T1

These are *categorical* — not bugs we can patch by writing more code.
They flow from "AppContainer + host DACLs" being a fundamentally
different shape than "kernel-level sandbox with its own filesystem
view and object namespace."

1. **Filesystem namespace visibility.** T1 gives the child a filtered
   filesystem view: paths outside the policy don't exist for the
   child. T3 leaves the entire host filesystem visible; DACLs
   determine access but not visibility.
2. **Object Manager / registry isolation.** T1 (presumably) has its
   own object directory and reduced registry surface. T3 shares the
   host's.
3. **Host-side ACL flicker.** T1 doesn't touch host filesystem state.
   T3 does, for the run's duration.
4. **`WRITE_DAC` prerequisite.** T1 doesn't require the launching
   user to have `WRITE_DAC` on policy paths. T3 does — without it
   the run fails fast with a clear error.

Items 1 and 2 are the load-bearing ones for the "is T3 sufficient?"
decision.

## Empirically resolved

### Directory enumeration on Win11 25H2 (build 26200)

`test_scripts/Test-PathEnumeration.ps1` runs a forced-T3 child against four
sibling directories (rw / ro / denied / control), each pre-staged
with a known filename, and asks two questions: can the child stat a
known-name file (path-by-name lookup) and can the child enumerate
the directory (`dir /b`)?

Result on 25H2:

| Directory | Policy        | Stat by name | Enumerate |
|-----------|---------------|--------------|-----------|
| rw        | granted rw    | VISIBLE      | **BLOCKED** |
| ro        | granted ro    | VISIBLE      | **BLOCKED** |
| denied    | explicit deny | HIDDEN       | BLOCKED   |
| control   | no policy     | HIDDEN       | BLOCKED   |

Findings:

1. **Directory enumeration is universally blocked** for the
   AppContainer child, even on paths where DaclManager explicitly
   granted `FILE_GENERIC_READ` (which on a directory includes
   `FILE_LIST_DIRECTORY`). The AppContainer's filesystem-access
   policy denies `FindFirstFile` regardless of DACL state. This is
   *stronger* than the threat model previously assumed.
2. **Path-by-name lookup** works for granted paths and fails for
   non-granted paths. The information disclosure surface reduces
   to the "filename guess-and-check" weak leak described in
   out-of-scope item #1.
3. **There is no broader enumeration leak.** A child cannot
   discover filenames it doesn't already know.

Usability consequence: agent scripts that legitimately want to
`dir` their working directory will fail under T3 in the current
implementation — including in paths the policy explicitly granted.

Root cause and resolution path are tracked in microsoft/mxc#304.
Empirically confirmed: `FindFirstFile` requires `FILE_TRAVERSE`
for an AppContainer-recognized SID on every ancestor of the
target directory, all the way to the volume root. Granting
`FILE_GENERIC_READ` on the leaf isn't sufficient if the chain
above the leaf is broken. The traverse chain is broken by default
for the C: drive on a stock Windows install because no
AppContainer-recognized SID is granted traverse on `C:\` or
`C:\Users\`, and a non-admin user lacks `WRITE_DAC` to add it.

The fix requires (a) a one-time admin setup that grants
`ALL APPLICATION PACKAGES:(X)` on `C:\` and `C:\Users\` using
`Set-Acl` with non-inheriting flags, plus (b) per-run `DaclManager`
extension to grant traverse on user-owned ancestors between
`%USERPROFILE%\` and the policy leaf. Until that lands, T3
supports stat-by-name only.

Empirical confirmation: `test_scripts/Investigate-T3DriveTraverse.ps1`
on a drive with `ALL APPLICATION PACKAGES:(X)` granted at its root
makes `dir /b <rw>` succeed inside T3. See microsoft/mxc#304 for
the full setup recipe and ongoing implementation work.

Reproduce locally:

```powershell
./test_scripts/Test-PathEnumeration.ps1
```

The script builds wxc-exec, sets up a scratch tree, runs the
probe, and prints the per-directory result with a headline. Pass
`-SkipBuild` if binaries are fresh; `-KeepArtifacts` to preserve
the scratch tree for inspection.

### What is T1's actual surface?

Still open. This document describes T3 in detail; T1 is referred
to only by contrast. A second document describing what
BaseContainer actually isolates would let us compare cleanly. We
have less direct visibility into T1's internals — a separate task.

## Recommendations for callers

- **If your threat model is "agents shouldn't be able to
  read / write outside their declared policy":** T3 is appropriate.
  T1 is preferred when available; T3 is a defensible fallback on
  pre-T1 builds.

- **If your threat model is "agents shouldn't be able to *observe*
  anything about the host they didn't bring with them":** T3 is not
  strong enough. Use T1 if available; otherwise consider running
  the workload in MicroVM or Hyperlight (separate documents).

- **If you need hermetic execution** (no host-visible side effects
  during or after the run, including ACL flicker): T3 is not
  appropriate. Use a VM-based backend.

- **If you cannot guarantee `WRITE_DAC` on policy paths** for the
  user running MXC: T3 will refuse with `WriteDacUnavailable`.
  Either run as a user that has it, or do not use the WXC executor
  on this host.

## Maintenance

This document should be updated when:
- A new tier is added to the WXC fallback chain
- An empirical answer to one of the open questions lands
- A scope item moves between "in scope" and "out of scope" (in
  either direction)
- A categorical gap between T1 and T3 is closed by an OS or runtime
  change

Last revised: phase 5 (initial draft).
