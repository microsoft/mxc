# Pull request builds

## GitHub Actions (automatic)

Every PR is validated automatically by the GitHub Actions workflows under
`.github/workflows/` (entry point: `Build.yml`). This is the primary PR signal —
it fans out to the reusable `Build.Windows.Job.yml`, `Build.Linux.Job.yml`, and
`Build.MacOS.Job.yml` workflows, which build and test on native Windows
x64/arm64, Linux x64/arm64, and macOS arm64 hosts, then runs the lint,
versioning, and SDK jobs.

### Local Node SDK package validation

From `sdk/node`, run `npm run typecheck` before pushing SDK changes. It builds
the SDK and unit tests, packs the SDK, installs it into an isolated temporary
integration project, and compiles every integration test. To repeat only the
packed-package check after building the SDK, run `npm run typecheck:integration`.
Neither command runs sandbox workloads.

The integration jobs install a packed SDK rather than building `sdk/node/dist`
in the checkout. Test-only private type imports must resolve from the installed
package, matching the runtime helpers. The isolated check prevents local
checkout build output from hiding missing package imports.

### Linux LXC dispatch coverage

The primary Linux build runs pinned LXC discovery, engine dispatch, exact-JSON
FFI routing, and SDK-helper tests on x64 and arm64. These routing tests need
neither LXC nor root: the backend rejects their invalid configuration before
creating a container. The FFI pin selects
`extern_spawn_json_reaches_the_lxc_backend`, which exercises `mxc_spawn_json`.
Keep the workflow selector aligned when renaming the test; the step fails if a
pin runs no passing tests, even when Cargo exits successfully.

### LXC (`lxc-e2e.yml`)

A separate workflow, because the primary Linux lane does not install LXC and
does not run as root. It triggers on PRs targeting `main`, so a PR stacked on
another branch gets no LXC gating until it is retargeted — dispatch it manually
for a stacked head.

The Linux .NET SDK job also installs LXC and runs the public V1
`MxcContainerLxcE2ETests` as root. Keep its test filter aligned with the class
name; the job rejects an empty selection or a run without passing tests.

### Local Windows SDK proxy checks

The Node, .NET, and Rust SDK tests can exercise ProcessContainer with an external
unpackaged, non-AppContainer proxy. The client uses egress deny, ingress allow,
and host loopback allow, with no `allowedProxyPeer`. WinHTTP uses the native
per-container proxy configuration without a workload-side proxy override.

Set `MXC_TEST_PROXY_ORIGIN_URL` to an HTTP origin reachable by the proxy and
`MXC_TEST_PROXY_EXPECTED_BODY` to a nonempty substring of its response. Use a
non-loopback origin for this WinHTTP scenario. Set
`MXC_ENABLE_PROCESSCONTAINER_PROXY_TESTS=1` for Node and .NET. Node starts the
package's `wxc-test-proxy.exe`; .NET and Rust require an already-running proxy at
`MXC_TEST_PROXY_URL`. Keep that proxy alive until both suites finish.

| Directory | Selector |
| --- | --- |
| `sdk/node/tests/integration` (after build) | `node --test --test-name-pattern="unpackaged proxy" dist/windows-process-container.test.js` |
| `sdk/dotnet` | `dotnet test Microsoft.Mxc.Sdk.Tests/Microsoft.Mxc.Sdk.Tests.csproj --filter FullyQualifiedName~MxcContainerProxyE2ETests` |
| `src` | `cargo test -p mxc-sdk --test streaming_processcontainer processcontainer_unpackaged_proxy_reaches_origin -- --ignored --test-threads=1` |

Select the current native build using `MXC_FFI_DIR` for Node and the managed
prebuilt-native MSBuild properties for .NET. These are opt-in host tests, not
substitutes for the PR build matrix.

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