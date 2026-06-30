# captureDenials consumer guide

Status: **Draft for review.** Owner: learning-mode capture feature.
Related: [`architecture.md`](./architecture.md) (box layout and runtime data flow),
[`deployment-and-lifecycle.md`](./deployment-and-lifecycle.md) (shim provisioning and
lifecycle), [`../host-prep.md`](../host-prep.md) (install/uninstall command reference).

This document defines the **complete integration contract** for an application that
consumes `captureDenials` directly from the native `wxc-exec` binary. **MXC does not
ship an SDK wrapper for this flow.** The SDK provides only the generic spawn surface
and the `captureDenials` configuration field; the consuming application is
responsible for parsing the denial stream, presenting the consent experience,
expanding policy, and re-spawning the workload. The behaviors and constraints
required to implement this correctly are specified below.

The governing model is: **the application decides, Tessera enforces, MXC translates,
and the user consents inside the application.** MXC's responsibilities are limited to
(a) enforcing the policy it is given, (b) emitting a structured denial signal when the
workload reaches the policy boundary, and (c) executing exactly one workload per
invocation. MXC does not prompt the user, does not loop, and does not own the consent
experience.

---

## 1. Scope and platform support

- **Windows only at present.** The capture path is implemented on Windows using ETW
  and the `MxcLearningModeShim` service. The Linux and macOS adapters are stubs that
  return `NotSupported`; a configuration with `captureDenials: true` on those
  platforms will not capture denials. Applications must verify platform support
  before depending on the feature.
- **Resource scope is filesystem and network only.** `resourceType` is one of `file`,
  `network`, or `other`. **Registry capture is not supported in MXC at this time** and
  applications must not depend on registry denials. The current Windows backend
  produces `file` denials; `network` is reserved for the forthcoming WFP capture work,
  and `other` is the catch-all classification (COM, IPC, and similar).
- **Backend is `processcontainer` (AppContainer).** captureDenials is wired for the
  Windows process-container backend.
- **One-shot invocations only.** `captureDenials` is honored on the one-shot spawn
  path. It is not part of the state-aware lifecycle (provision, start, exec, and so
  on); the state-aware configuration parser does not carry the field.

---

## 2. One-time host provisioning

Capture requires a shared, machine-wide privileged service (`MxcLearningModeShim`)
to be installed once per machine. Installation is an explicit, elevated,
out-of-band administrative action and must never be performed as an application,
runtime, or package-install side effect:

```
wxc-host-prep install-learning-mode-shim     # elevated; idempotent no-op if present
```

Uninstall revokes the `SeSystemProfilePrivilege` grant only when host-prep recorded
that it performed the grant:

```
wxc-host-prep uninstall-learning-mode-shim
```

> **Important.** When the shim is not installed or not running, the run still
> succeeds and produces **zero denials**, which is indistinguishable from a
> well-behaved workload if only `totalDenials` is examined. Applications must
> inspect `captureDenialsActive` in the summary (see §4) to distinguish the two
> cases. A robust consumer additionally performs a fast preflight — a read-only
> Service Control Manager status probe — and fails with an actionable message
> ("shim not installed — run `wxc-host-prep install-learning-mode-shim` as
> administrator") before initiating a run that would otherwise capture nothing.

The capture host must also have the process-container velocity key enabled, which is
the standard prerequisite for any `processcontainer` workload.

---

## 3. Enabling capture in the configuration

Set `captureDenials: true` at the **top level** of the container configuration. It is
a first-class field — not a member of `experimental` — and defaults to `false`:

```jsonc
{
  "version": "0.7.0-alpha",
  "containerId": "my-workload",
  "containment": "processcontainer",
  "captureDenials": true,
  "process": { "commandLine": "cmd /c type \"C:\\Users\\me\\secret.txt\"" },
  "filesystem": { "readonlyPaths": [], "readwritePaths": [] }
}
```

Begin with a least-privilege policy (narrow `readonlyPaths` and `readwritePaths`),
allow the workload to reach the policy boundary, capture the resulting denials, and
expand only the paths the user approves (see §6).

---

## 4. The denial stream contract

### Framing

Denials are streamed as **`0x1E`-framed NDJSON**. Each record consists of the single
byte `0x1E` (ASCII Record Separator), followed by a compact JSON object, followed by
`\n`:

```
\x1e{"type":"denial",...}\n
\x1e{"type":"denial",...}\n
...
\x1e{"type":"summary",...}\n          // always last; the stream terminator
```

The workload's own standard output and error are interleaved on the same byte stream
in pipe mode. Because workload output never contains `0x1E`, splitting on the marker
reliably demultiplexes MXC envelopes from workload output. To reconstruct the
workload's standard error, discard every line beginning with `0x1E` and retain the
remainder verbatim.

### `denial` record (one per denied access)

```jsonc
{
  "type": "denial",
  "path": "C:\\Users\\me\\secret.txt",        // canonical; NT prefix already stripped
  "resourceType": "file",                       // file | network | other
  "accessType": "read",                         // read | write | execute | unknown
  "pid": 1234,                                   // sandbox PID that hit the denial
  "filetime": 132847890123456789                // Windows FILETIME (100ns since 1601 UTC)
}
```

Keys are camelCase and enum values are lowercase. This wire format is guarded by
tests; the key names and casing are to be treated as a stable contract.

### `summary` record (always last)

```jsonc
{
  "type": "summary",
  "exitCode": 1,                       // the WORKLOAD's exit code (see §8)
  "totalDenials": 3,                   // count of unique (path, accessType) pairs
  "captureDenialsActive": true,        // must be checked (see note below)
  "deniedResourcesTruncated": false,   // true if the denial list reached the cap
  "childProcessesObserved": 2,         // best-effort Toolhelp child-PID count
  "descendantPidsCovered": 2,          // descendants attached to the live ETW filter
  "deniedResources": [ /* full deduped array; same set as the live lines */ ]
  // "rawEventCount": N                // present only when MXC_DENIAL_VERBOSE=1
}
```

- **`captureDenialsActive`** is `true` only when the runner successfully attached the
  ETW collector. A value of `false` indicates that capture was requested but could
  not be activated (the shim was unreachable, the session failed to start, and
  similar). Both outcomes yield `totalDenials: 0`, so this flag is the only reliable
  means of distinguishing a clean run from a run that captured nothing. The field is
  always present.
- **`deniedResources`** is the consolidated, deduplicated list, embedded in the
  summary so that an application may perform a single race-free read after exit rather
  than accumulating the live records. An empty array indicates the workload ran and
  nothing was denied (cross-checked against `captureDenialsActive`).
- **`deniedResourcesTruncated`** is `true` when the denial set reached the internal
  cap and the list is therefore partial. Applications should surface this so the user
  is aware that additional denials may exist.
- **`descendantPidsCovered`** versus **`childProcessesObserved`**: denials from
  descendant processes flow into the same stream as the root's. `descendantPidsCovered`
  — the number of descendants attached to the live ETW filter — is the authoritative
  metric for "how many descendants contributed denials" and should be used for any UI
  messaging. `childProcessesObserved` is a best-effort Toolhelp poll retained for
  back-compatibility and should be treated as a cross-check, not as a signal that
  denials are missing.

### Two consumption modes

- **Live, per denial.** Records may be read as they arrive, enabling per-denial
  prompting or logging during the run.
- **Consolidated, per run.** The live records may be ignored in favor of reading
  `deniedResources` from the summary after exit. This is the simpler, race-free option
  and is the basis for the approve-and-retry experience.

---

## 5. Transports and PTY handling

The denial bytes are identical across transports; only the destination differs. The
destination is selected once per invocation by the application through an environment
variable. MXC does not auto-detect a terminal.

| Workload execution mode | Set `MXC_DENIALS_PIPE`? | Denials are delivered on |
|---|---|---|
| **Piped** (application owns stdout/stderr) | No | `wxc-exec`'s **stderr**, `0x1E`-framed |
| **Under a PTY / ConPTY** (interactive) | **Yes** (`MXC_DENIALS_PIPE=<name>`) | the named pipe `\\.\pipe\<name>` |

> **Important.** Under a pseudoconsole the workload owns the terminal: standard
> output, standard error, cursor movements, and color codes are multiplexed into a
> single byte stream. Framed JSON on that stream would corrupt the rendered terminal
> and could not be parsed back out reliably. An application that allocates a PTY
> **must** set `MXC_DENIALS_PIPE` to a pipe name; `wxc-exec` then writes the identical
> `0x1E` stream out-of-band to `\\.\pipe\<name>`, leaving the terminal clean. The
> variable must be set to the base name only (without the `\\.\pipe\` prefix, which
> `wxc-exec` prepends). Routing is explicit: MXC will not infer the pipe from a
> terminal check.

Operational notes:

- **Ordering.** Create the named-pipe server before spawning `wxc-exec` so that the
  pipe exists when the child opens it.
- **Fallback.** If `MXC_DENIALS_PIPE` is set but the pipe cannot be opened (the server
  is not listening, the name is mistyped), `wxc-exec` logs a warning and falls back to
  stderr rather than failing the workload. Applications must not assume that setting
  the variable guarantees nothing will appear on stderr.
- A minimal inbound named-pipe server reference — create, accept, read to EOF, with a
  self-connect mechanism so the accept cannot block indefinitely — is provided by
  `DenialPipeServer` in `src/testing/wxc_e2e_tests/src/denial_consumer.rs`.

---

## 6. The approve-and-retry loop

Enforcement is non-blocking: a denied operation fails inside the workload at the
moment of denial; the workload observes an access-denied result and proceeds or exits
accordingly. Granting a path subsequently cannot reverse an operation that has already
failed — a grant takes effect only on the next run. The loop is therefore:

```
spawn (captureDenials: true, least-privilege policy)
        |
        v
read denials (live and/or from the summary)
        |
        v
prompt the user in the application  -->  user approves a subset of paths
        |
        v
expand the config: add approved paths to filesystem.readonlyPaths / readwritePaths
        |
        v
re-spawn ONCE with the expanded config  -->  still denied? --> prompt again (next round)
```

Required behaviors:

- **Respawn model, not in-place mutation.** MXC applies updated policy by re-spawning
  the workload with the new configuration. There is no live policy mutation of a
  running sandbox; the workload step must tolerate restart and retry.
- **One retry by design; additional rounds are the application's choice.** MXC executes
  exactly one workload per invocation and never loops. A typical consumer caps at a
  single prompt-and-retry round to keep the user in control of each escalation; an
  application that requires multiple rounds drives them itself. This one-retry-by-design
  contract is intentional.
- **Expand additively and never remove existing grants.** Add only the approved paths,
  folding trailing separators and normalizing case for de-duplication.
- **Refuse OS-security-critical paths even when approved.** The expansion step must
  skip paths that would compromise OS security boundaries regardless of user approval.
  The reference `expand_readonly_paths` refuses, among others: `C:\Windows\System32\`,
  `SysWOW64`, `WinSxS`, `Boot`, `Resources`, `Fonts`, `servicing`, and
  `Microsoft.NET\`; the drive-rooted `bootmgr`, `BOOTNXT`, `pagefile.sys`,
  `hiberfil.sys`, `swapfile.sys`, and `$Recycle.Bin\`; and any path still carrying an
  NT device prefix (`\??\` or `\Device\`).

---

## 7. Parsing requirements and edge cases

- **Apply the default noise filters.** Every sandboxed process triggers OS background
  probes that are rarely actionable. The reference filters discard:
  - the AppContainer-default `\REGISTRY\USER\.DEFAULT\…` probes, and
  - the OS loader's `C:\Windows\System32\…` searches ending in `.dll`, `.mui`,
    `.mun`, `.cat`, `.cdf-ms`, or `.nls`.

  Filtering is consumer-side: MXC streams the raw denials and the application decides
  what is actionable. Pass the raw set through unfiltered only when that is the
  intent.
- **Strip NT prefixes defensively.** Paths are emitted canonicalized, but applications
  should strip a leading `\??\` so paths surface as `C:\…`, and must refuse any path
  still carrying `\??\` or `\Device\` during expansion.
- **Deduplication is performed upstream** by `(path, accessType)`; the stream may be
  treated as already unique.
- **`filetime` is a Windows FILETIME** (100-nanosecond intervals since
  1601-01-01 UTC), not a Unix epoch; convert before display.
- **Tolerate unknown fields and verbose mode.** `rawEventCount` appears only under
  `MXC_DENIAL_VERBOSE=1`. Parse leniently so that future additive fields do not break
  existing consumers.
- **Handle parse errors non-fatally.** A line that begins with `0x1E` but is not valid
  JSON should be counted or logged rather than treated as fatal.

---

## 8. Exit-code semantics

`summary.exitCode` is the workload's exit code. Because enforcement is non-blocking, a
denied operation typically causes the workload itself to fail, so a non-zero exit with
denials present is the expected "blocked" outcome. Following a successful grant and
re-spawn, an exit code of `0` is expected. `totalDenials: 0` must not be treated as
success on its own; it must be evaluated together with `captureDenialsActive: true` and
the workload exit code.

---

## 9. Consent boundary

- MXC and Tessera do not present any OS-level or UAC-style prompt for these
  escalations. All consent wording, intent interpretation, scoping (once, session, or
  always), persistence, and audit are owned by the application.
- MXC provides only the enforcement primitive (the policy supplied to it) and the
  denial signal (this stream). The decision to expand policy and re-spawn rests with
  the application.

---

## 10. Reference implementation

The end-to-end reference — the `0x1E` NDJSON parser, the default filters, NT-prefix
stripping, additive policy expansion with system-critical refusal, and the
`MXC_DENIALS_PIPE` named-pipe server — is implemented in:

- `src/testing/wxc_e2e_tests/src/denial_consumer.rs` — the consumer-side logic.
- `src/testing/wxc_e2e_tests/tests/e2e_windows_capture_denials.rs` — a four-phase
  native end-to-end test that drives `wxc-exec` directly and validates default-deny
  capture, approve and re-spawn, the `MXC_DENIALS_PIPE` side channel, and a
  multi-round approve-and-retry loop.

Applications reimplement the same contract in their own language; the Rust port is the
authoritative reference for behavior.

---

## 11. Out of scope (roadmap)

The following are intentionally out of scope at present and are listed so that
applications do not design around them prematurely:

- **Denial-event metadata enrichment.** Richer fields — such as finer operation
  granularity, the policy rule or category responsible for the denial, and a
  host-resolvable versus non-overridable (IT/platform) indicator — are planned but not
  yet emitted. The current record provides `path`, `resourceType`, `accessType`,
  `pid`, and `filetime`.
- **In-place policy update** of a running sandbox is not available; use the respawn
  model.
- **MXC-computed proposed configuration.** At present the consumer computes the
  expanded configuration from the approved denials. A future direction is for MXC to
  return a proposed configuration that would resolve the denial; until then,
  applications own the expansion and the system-critical refusal.
- **Blocking denial / pause-on-denial.** Enforcement is non-blocking (asynchronous
  denial); there is no mode that pauses the workload while the user decides. Use the
  capture, approve, and respawn loop.
- **Registry capture** and **Linux/macOS capture** are not supported.
