# Pull request builds

## GitHub Actions (automatic)

Every PR is validated automatically by the GitHub Actions workflows under
`.github/workflows/` (entry point: `Build.yml`). This is the primary PR
signal — it builds and tests on native Windows x64/arm64, Linux x64/arm64,
and macOS arm64 hosts in parallel.

## Azure Pipelines (optional on PRs, required on `main`)

The ADO pipeline (`MXC-PR-Build`) is the official build pipeline that signs
the binaries. It runs automatically on merge to `main` and on a nightly
schedule.

Microsoft ADO policy disables automatic PR-build runs to prevent unreviewed
code (e.g. from external forks) from executing on internal pipeline agents.
A Microsoft employee can manually trigger it on a PR by commenting `/azp run`
on the pull request. Use this when you want to run the official build against
a change before merge.

Pipeline status:
[MXC-PR-Build](https://microsoft.visualstudio.com/Dart/_build?definitionId=192146).