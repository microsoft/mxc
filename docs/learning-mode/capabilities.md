# Learning-mode capabilities

MXC sandboxes are **deny-by-default**: when a workload touches a file, registry
key, or other resource the policy does not grant, the access is blocked and the
OS returns the usual "Access is denied" error. For non-trivial workloads this is
operationally fragile — the author must enumerate every path the workload will
ever touch up front, or hand the operator a stack trace and ask them to guess.

**Learning mode** turns those denied accesses into observable events. It is
enabled per-run through two Windows-specific policy capabilities. These
capabilities are the *inputs* to learning mode; the machinery that collects and
surfaces the resulting denial events is layered on top in later work.

> **Platform support.** Learning-mode capabilities are **Windows-only** and
> apply to the AppContainer-based backends (classic AppContainer and
> BaseContainer, which share `backends/appcontainer/common`). On other platforms
> the capability strings are ignored.

## The two capabilities

The two capabilities are **semantically distinct and must not be conflated**:

| Capability              | Behavior                                              | Enforcement                          |
| ----------------------- | ----------------------------------------------------- | ------------------------------------ |
| `learningModeLogging`   | Logs every **failed** access check (deny-and-record). | **Unchanged** — accesses stay denied. |
| `permissiveLearningMode`| Logs **every** access check and **allows** it (audit / allow-all). | **Weakened** — the container no longer enforces deny-by-default. |

### `learningModeLogging` — deny-and-record

The OS records each access check that *would have been denied*, but the access
is **still denied**. Containment is unchanged, so this is safe to use as a
diagnostic aid: the workload behaves exactly as it would without learning mode,
while producing a record of what it tried and failed to reach.

### `permissiveLearningMode` — audit / allow-all

The OS records **every** access check and **allows** it. This is an audit mode:
it answers "what would this workload touch if nothing were blocked?" but it does
so by **not enforcing deny-by-default** for the duration of the run.

Because it relaxes containment, `permissiveLearningMode` is **security-sensitive**:
whenever it is present, both the AppContainer and BaseContainer runners emit an
always-visible **security warning** on the host's stderr. In-process Rust callers
can also inspect it through `Sandbox::warnings()` or `Output::warnings`. It is a
reserved internal capability enabled by the dedicated audit/capture entry points.

The parser rejects both learning-mode capability names in
`processContainer.capabilities`, case-insensitively. This prevents a policy from
selecting contradictory modes or bypassing the security-sensitive entry points.

## How to enable them

Enable deny-and-record through the dedicated `learningMode` setting:

```jsonc
{
  "processContainer": {
    "learningMode": true
  }
}
```

Enable permissive audit mode through the CLI:

```text
wxc-exec --audit --config <config>
```

These entry points inject the reserved capability strings internally; users
must not add them directly to `processContainer.capabilities`.
When either learning-mode capability is in effect the runner emits a diagnostic
describing the mode (informational logging for `learningModeLogging`, an
always-visible stderr security warning for `permissiveLearningMode`).

## Three learning-mode flows

Learning-mode telemetry is consumed through three distinct flows. They differ in
*who* runs them, *how* the capability is supplied, and *whether* deny-by-default
stays enforced:

| Flow | Audience | Entry point | Enforcement |
| ---- | -------- | ----------- | ----------- |
| **Developer inner-loop** | The author bringing a workload up | `--audit` CLI flag | Relaxed (allow-all) |
| **App / user-configurable** | Apps that let end users tune their own config | `captureDenials` (`mode: "block-and-log"`) / `learningModeLogging` | Enforced (deny-and-record) |
| **Fleet auditing** | IT admins | `captureDenials` (`mode: "allow-and-log"`) / `permissiveLearningMode` | Relaxed (allow-all) |

1. **Developer inner-loop (`--audit`).** A developer runs `wxc-exec --audit`
   with ProcessContainer containment to discover the capabilities and paths
   their process needs. `--audit` is rejected for every other Windows backend.
   It triggers UAC, injects `permissiveLearningMode`, and drives a WPR/ETW
   permissive-learning-mode trace for the run. This is typically a static
   config the developer iterates on locally.

   ```
   wxc-exec --audit --config <config>
   ```

2. **App / user-configurable (`captureDenials` block-and-log / `learningModeLogging`).**
   An app wants to let its users "configure" their own sandbox. Each user
   workflow differs, so the app records what was blocked, presents it through its
   own UX, and re-generates the config with the new paths/capabilities.
   Deny-by-default stays enforced — the workload behaves exactly as it would in
   production while the denials are recorded.

3. **Fleet auditing (`captureDenials` allow-and-log / `permissiveLearningMode`).**
   IT admins audit access checks across a fleet by running MXC instances in
   permissive learning mode. This flow does **not** trigger UAC: the capability
   is supplied through config and takes effect directly, allowing and recording
   every access check.

## Relationship to denial capture

Injecting these capabilities makes the OS *emit* learning-mode events. The
Windows-only `captureDenials` config switch drives collecting those events and
surfacing the resulting denials to the caller. Its `mode` selects how each
ungranted access is handled while it is recorded:

- `mode: "block-and-log"` (default) maps onto `learningModeLogging`
  (deny-and-record) — the app / user-configurable flow.
- `mode: "allow-and-log"` maps onto `permissiveLearningMode` (allow-and-record)
  — the fleet-auditing flow.

The capture pipeline is delivered incrementally and is documented separately as
it lands.
