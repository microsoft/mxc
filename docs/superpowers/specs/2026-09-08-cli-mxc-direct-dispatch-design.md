# CLI + MXC Inline Dispatch Design

## Problem

The initial CLI + MXC validation run never received a runner because it used
the legacy 1ES label form. Elliot's ScaleSet migration in #1093 changed 1ES
jobs to use the pool name directly as `runs-on`. After applying that correction,
the job received the intended T1 VM but failed before checkout because the
`copilot` environment secret was not available through the indirectly called
reusable workflow.

## Design

Keep `.github/workflows/Validation.Tests.Scheduled.yml` as the manual entry
point because it already exists on the default branch and can therefore be
dispatched from a feature ref before merge. Define the T1 build job directly in
that workflow, with `environment: copilot` and
`runs-on: 1es-mxc-windows-prerelease-t1-x64`.

Remove `.github/workflows/Validation.CopilotCli.Mxc.Job.yml`. A new directly
dispatchable workflow cannot be invoked through the GitHub API until the file
exists on the default branch, while a reusable workflow boundary does not
receive the environment secret used by this lane.

## Data and credential flow

1. A repository administrator dispatches `Validation.Tests.Scheduled.yml` with
   `plan: copilot-cli-build` from the feature branch.
2. The inline `copilot-cli-build` job references the `copilot` environment
   directly.
3. `GHCP_CLI_SOURCE_READ` is consumed only by the private CLI checkout with
   `persist-credentials: false`.
4. The workflow checks out latest MXC `main` and CLI `main`, builds the combined
   CLI, verifies provenance and runtime hashes, and uploads only sanitized
   evidence.

## Failure handling

- A missing environment secret fails at private checkout.
- Runner, toolchain, dependency, build, hash, and smoke-test failures remain
  explicit.
- Cleanup runs unconditionally and removes only the exact source and staging
  paths created by the job.

## Validation

- Parse the changed YAML.
- Run the existing 14 PowerShell contract tests.
- Dispatch `Validation.Tests.Scheduled.yml` from the feature branch with
  `plan: copilot-cli-build`.
- Confirm the job receives the T1 ScaleSet runner.
- Confirm the log reports the environment secret source and the private
  checkout succeeds.
- Follow the build to a terminal result and inspect the sanitized provenance
  artifact.
