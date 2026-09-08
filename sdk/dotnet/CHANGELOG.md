# Changelog

All notable changes to `Microsoft.Mxc.Sdk` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The state-aware lifecycle surface shipped in 0.8.0 was incomplete: it could
provision only a single implicit backend, and several phases had no way to
carry per-phase policy. Completing it required changing signatures that 0.8.0
had already published, so **the next release must be a minor bump (0.9.0), not
a 0.8.x patch**. Package versions are bumped in a dedicated release PR (see
"Update package versions to 0.8.0", #1006), not here.

### Removed

- `MxcSandboxProcess.WaitBlocking()` is no longer public. It bypassed the
  managed policy deadline, so calling it directly granted the workload a second
  full timeout budget (see "Fixed" below). Use `Wait()` / `WaitAsync()`, which
  enforce the deadline.
- `StartSandboxOptions` is replaced by `StateAwarePhaseOptions`, which every
  non-provision phase now shares.

### Changed (breaking)

- `MxcLifecycle.ProvisionSandbox` takes the backend as a required leading
  `StateAwareContainment` argument, and its options parameter widened from
  `ProvisionSandboxOptions` to the abstract `StateAwareProvisionOptions`.
  `ProvisionSandboxOptions` still exists and now derives from that base, so
  object initializers are unchanged — add the containment argument:

  ```csharp
  // 0.8.0
  MxcLifecycle.ProvisionSandbox(new ProvisionSandboxOptions { … });
  // 0.9.0
  MxcLifecycle.ProvisionSandbox(
      StateAwareContainment.IsolationSession,
      new ProvisionSandboxOptions { … });
  ```

- `StartSandbox`, `StopSandbox`, `DeprovisionSandbox`, and `ExecInSandbox`
  accept an optional trailing options argument. Source-compatible; existing
  call sites keep compiling. Because adding a parameter changes the emitted
  method signature, assemblies compiled against 0.8.0 must be recompiled
  rather than dropped in place.

### Deprecated

- `SandboxPolicy.CaptureDenials` now reports **MXC0001**. It is honored only by
  the compatibility overloads, which relocate it onto
  `ProcessContainerContainment.CaptureDenials`; the
  `Run(SandboxRequest)` / `Spawn(SandboxRequest)` paths ignore it. Set
  `ProcessContainerContainment.CaptureDenials` instead. Removed in 1.0.

### Fixed

- `Wait()` / `WaitAsync()` no longer grant a second full timeout budget. Once
  the managed deadline elapsed, the wait delegated to the native blocking wait,
  which takes no deadline and re-applies the policy timeout as a duration from
  that call — so a 1000 ms timeout could take ~2000 ms to return, with the
  control lock held throughout. The deadline path now terminates the workload
  and reaps it, reporting `TimedOut`.
- Malformed lifecycle sandbox ids are classified as `MalformedId` rather than
  `UnsupportedContainment` (an id with an empty prefix, such as `":payload"`)
  or throwing `NullReferenceException` (`default(SandboxId)`), matching the
  native parser.
