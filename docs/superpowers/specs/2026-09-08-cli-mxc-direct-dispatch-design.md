# CLI + MXC Direct Dispatch Design

## Problem

The initial CLI + MXC validation run never received a runner because it used
the legacy 1ES label form. Elliot's ScaleSet migration in #1093 changed 1ES
jobs to use the pool name directly as `runs-on`. After applying that correction,
the job received the intended T1 VM but failed before checkout because the
`copilot` environment secret was not available through the indirectly called
reusable workflow.

## Design

Make `.github/workflows/Validation.CopilotCli.Mxc.Job.yml` the manual entry
point by using `workflow_dispatch`. Its build job continues to specify
`environment: copilot` and uses
`runs-on: 1es-mxc-windows-prerelease-t1-x64`.

Remove the `copilot-cli-build` option and reusable-workflow call from
`.github/workflows/Validation.Tests.Scheduled.yml`. This avoids retaining a
known-broken invocation path and keeps scheduled backend validation independent
from the private-source build.

## Data and credential flow

1. A repository administrator manually dispatches the dedicated workflow.
2. The job references the `copilot` environment directly.
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
- Dispatch the dedicated workflow from the feature branch.
- Confirm the job receives the T1 ScaleSet runner.
- Confirm the log reports the environment secret source and the private
  checkout succeeds.
- Follow the build to a terminal result and inspect the sanitized provenance
  artifact.
