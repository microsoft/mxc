# Pull request builds

## GitHub Actions (automatic)

Every PR is validated automatically by the GitHub Actions workflows under
`.github/workflows/` (entry point: `Build.yml`). This is the primary PR
signal — it builds and tests on native Windows x64/arm64, Linux x64/arm64,
and macOS arm64 hosts in parallel.

## Azure Pipelines (optional on PRs, required on `main`)

The ADO pipeline (`MXC-PR-Build`) is the Azure version of the PR pipeline. The official
and PR Azure pipelines share the same YAML core, so running `/azp run` on a PR before
check-in is a good way to confirm your change does not inadvertently break that core.
It runs automatically on merge to `main`.

Microsoft ADO policy disables automatic PR-build runs to prevent unreviewed
code (e.g. from external forks) from executing on internal pipeline agents.
A Microsoft reviewer with repo write access can manually trigger it on a PR by
commenting `/azp run` on the pull request. Use this when you want to run the Azure
build against a change before merge.

Pipeline status:
[MXC-PR-Build](https://microsoft.visualstudio.com/Dart/_build?definitionId=192146).

## Dependency feed check (`dependency-feed-check`)

GitHub Actions Rust jobs resolve dependencies through the public, anonymous-read
**MxcDependencies** Azure Artifacts feed (`.azure-pipelines/.cargo/config.public.toml`)
instead of crates.io, mirroring the network-isolated ADO PR build. A crate not yet cached
in the feed fails `dependency-feed-check` with an HTTP 401, because the feed only saves a
crate when an authenticated client requests it.

Only someone with Contributor access to the shine-oss Mxc project can run the seed pipeline. To fix it:

1. Run the [**MXC-Update-Feed-Dependencies**](https://dev.azure.com/shine-oss/mxc/_build?definitionId=33)
   pipeline in shine-oss using the **Run pipeline** button, with `prNumber` set to the PR's number.
2. Re-run the failed Rust job.

### Why two feeds

Official (signed) ADO builds use a *separate* internal feed, **Mxc-Azure-Feed**, for the
internal Rust toolchain and 1ES Rust tasks the public feed can't serve. It auto-refreshes
on every official build (nightly and per trigger), so only the public **MxcDependencies**
feed needs the manual steps above.