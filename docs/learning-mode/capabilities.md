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
| `learningMode`          | Logs every **failed** access check (deny-and-record). | **Unchanged** — accesses stay denied. |
| `permissiveLearningMode`| Logs **every** access check and **allows** it (audit / allow-all). | **Weakened** — the container no longer enforces deny-by-default. |

### `learningMode` — deny-and-record

The OS records each access check that *would have been denied*, but the access
is **still denied**. Containment is unchanged, so this is safe to use as a
diagnostic aid: the workload behaves exactly as it would without learning mode,
while producing a record of what it tried and failed to reach.

### `permissiveLearningMode` — audit / allow-all

The OS records **every** access check and **allows** it. This is an audit mode:
it answers "what would this workload touch if nothing were blocked?" but it does
so by **not enforcing deny-by-default** for the duration of the run.

Because it defeats containment, `permissiveLearningMode` emits a **security
warning** in the run diagnostics. It is nevertheless **permitted in every build,
including release**, because it is a legitimate auditing tool. Callers are
responsible for only enabling it against workloads and on hosts where allowing
all accesses is acceptable.

## How to enable them

Add the capability string to the policy's `capabilities` array:

```jsonc
{
  "capabilities": ["learningMode"]
}
```

or, for audit mode:

```jsonc
{
  "capabilities": ["permissiveLearningMode"]
}
```

Capability strings are resolved to AppContainer capability SIDs and attached to
the child process's `SECURITY_CAPABILITIES` exactly like any other capability —
no separate switch is required to *inject* them. When either capability is
present the runner logs a diagnostic line describing the mode in effect
(informational for `learningMode`, a security warning for
`permissiveLearningMode`).

## Relationship to denial capture

Injecting these capabilities is only the first step. Enabling a learning-mode
capability makes the OS *emit* learning-mode events; a separate, experimental
`captureDenials` switch (Windows-only, behind `--experimental`) will drive
collecting those events and surfacing the resulting denials to the caller. That
capture pipeline is delivered incrementally and is documented separately as it
lands.
