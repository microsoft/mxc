# Pull request builds

> **Audience:** MXC developers

## GitHub Actions (automatic)

Every PR is validated automatically by the GitHub Actions workflows under
`.github/workflows/` (entry point: `Build.yml`). This is the primary PR signal —
it fans out to the reusable `Build.Windows.Job.yml`, `Build.Linux.Job.yml`, and
`Build.MacOS.Job.yml` workflows, which build and test on native Windows
x64/arm64, Linux x64/arm64, and macOS arm64 hosts, then runs the lint,
versioning, repository-consistency, and SDK jobs. Repository consistency also
checks that `mxc-sdk` is the only Rust release crate and has a valid package
name, version, description, repository, and license.

`W365.Node.Fixture.Build.Job.yml` compiles the isolated Windows Node fixture
library once on `windows-latest` alongside shipping builds. Node 24 and 26
integration jobs download the same DLL rather than repeating Cargo setup and
compilation after packaging. Both versions still run the complete fixture.
The caller forwards the producer result, and Windows consumers fail before
testing if it did not succeed, including when a previous run attempt left an
artifact behind. Unix integration jobs retain their existing native builds.

Native W365 loopback TLS fixtures run in parallel through
`W365.Fixture.Test.Job.yml`, not in the binary build jobs. They retain the same
Windows, Linux and macOS host coverage and require every named scenario to
pass. The aggregate check is `w365-fixture-tests / W365 fixtures`; packaging
does not depend on it. See the [fixture coverage and required-check rollout
instructions](ci-validation-infrastructure.md#offline-tls-fixtures).

Windows release workspace suites run independently through
`Test.Windows.Job.yml` on native x64 and ARM64 hosts. `Build.Windows.Shared.Job.yml`
first builds the production executor and sidecars once per architecture.
Alongside it, `Build.Windows.Fixtures.Job.yml` runs the existing standalone
module-lifetime example build with the same release profile, features, hosts
and linker. Workspace lanes download its same-run DLL and PDB instead of
repeating that build after production finishes. The fixture producer uses a
dedicated dependency cache, seeded read-only from the existing workspace-test
cache when cold.
The workspace consumer and cold seed declare the same complete `shared-key`
namespace, preserving the existing architecture-specific cache names.
For rust-cache, `shared-key` replaces the whole key base; it does not combine
with a separate `key` input. Fixture-owned caches retain their own names.
Both cached x64 producers retain the targeted `hyperlight-host` regeneration
step after cache restoration and before building. Its generated surrogate
assets are not retained by the dependency cache; restoring compiled metadata
alone is insufficient.
Artifact validation and workspace tests download that same-run Cargo snapshot,
including source timestamps and build-script outputs, so compatible compilation
can be reused rather than repeated. Snapshots are kept for one day.
Workspace and artifact-validation consumers keep separate architecture-specific
caches of compiled external dependencies. These cover example, workspace-test,
minimal-feature, filesystem-probe, NVX-staging, and debug-executor builds.
They complement the production snapshot: registry-only caching would download
source archives but still recompile these dependency variants.
Workspace crates and test executables are not added to that dependency cache.
The transfer contains a Zstandard-compressed PAX archive and a JSON metadata
sidecar bound to the archive's SHA-256 checksum. Upload stores the compressed
bytes without compressing them again. Restore validates the metadata and
checksum before extracting once; it does not scan the compressed archive to
find metadata.
Version-resource build scripts also watch Git HEAD and its referenced ref.
Snapshots record hashes and timestamps for those inputs, not their contents.
Restore rejects mismatched Git inputs and restores timestamps only after
checking the existing files, without replacing Git references or configuration.
Make `windows-build / Shared Windows build` a required status check when
rolling out shared compilation, so failed producers block merging even when
their consumers cannot start.
Each workspace lane checks that both producers succeeded, downloads the
module-lifetime example, and runs the full unfiltered workspace tests with
its existing release features. Failed, skipped or cancelled producer results
fail the workspace aggregate even if an earlier run attempt left artifacts.
Cargo's normal example compilation in that full suite is unchanged, as is the
minimal-feature NVX gate that runs afterward. The suites
retain their release W365 cases as well as the separate debug fixture coverage.
Packaging does not wait for workspace tests; make
`windows-workspace-tests / Windows workspace tests` a required status check
before merging the job extraction. The NVX module-lifetime gate follows its
example into the workspace suite. The existing Windows build checks retain
their focused telemetry, filesystem-probe, NVX artifact, and package validation.
The packaged-crate verification runs once on a separate native x64 package
validation job, alongside those checks. It receives only the signed runtime
data already staged by production, not another production compilation or
Cargo snapshot. The unchanged helper builds tests from the extracted crate
archive and runs its required signature/integrity scenario. Its Cargo outputs
retain the existing target-directory behavior and use a separate dependency
cache, seeded read-only from artifact validation when cold.

Run `node --test scripts/tests/cargo-build-snapshot.test.js` to check raw and
compressed snapshot reuse locally; `tar` must support Zstandard compression.
The regression builds a small crate with a build script,
deletes its output, changes its source timestamp to simulate a fresh checkout,
changes Git HEAD's timestamp, restores the snapshot, and requires Cargo to
reuse the existing compilation. It also checks that a mismatched checkout is
rejected without overwriting its Git references or source files, and that
archive corruption is rejected before extraction.
Repository-consistency CI runs the same check.

The shared Windows build, artifact validation, workspace tests, and telemetry
component jobs select `rust-lld.exe` from the toolchain pinned in
`src/rust-toolchain.toml`. The job-scoped
`CARGO_TARGET_<TRIPLE>_LINKER` setting is applied before cache selection and
matches between the producer and consumers. Optimization, debug information,
features, and test selection retain their existing settings.

Both shared-build hosts run `node --test scripts/tests/windows-linker.test.js`
before the workspace build. It links an optimized DLL and executable for the
selected architecture, calls an exported function through the DLL's import
library, requires PDBs for both outputs, and verifies that setup uses the pinned
toolchain even when invoked from the repository root.

Windows builds first run host-only regression checks for loopback command
quoting and native-process output capture. These verify direct and
shell-wrapped launches, normal stdout/stderr capture, and prompt failure when
an exited process leaves a descendant holding an output handle. Result-gate
regressions also reject empty selections and skipped SDK streaming cases.
These checks do not require PSEC; scheduled ProcessContainer hosts execute the
prebuilt public SDK streaming tests from the Windows SDK test bundle.

The MicroVM infrastructure suite also packs real npm fixture archives and
checks their file lists and contents. It invokes the configured npm CLI
directly, resolving the Windows shim's prefix once rather than for every pack.
Each pack retains a 30-second subprocess budget, including initial resolution,
and failures report npm timing output. The watchdog owns the npm process,
not an intermediate command shell.

### Telemetry component build checks

The Windows workflow also runs a separate `Telemetry component` check on native
x64 and arm64 hosts. It checks that the default release build loads the bundled
signed DLL, an empty component path builds without routing, and a tampered DLL
fails Authenticode verification. Each failure fails the check.
These jobs also run the consent and policy unit suites in release mode with
default features, once per architecture, using their existing Cargo target
directory. The commands retain the same profile and feature configuration as
the artifact lane; moving them avoids blocking artifact publication on this
separate test compilation.

Make `windows / Windows validation` a required status check when rolling out
this split. It fails unless both artifact validation and both telemetry host
lanes, plus the x64 package verification, succeed. Existing artifact and
workspace check names stay unchanged.

Run locally on Windows from the repository root:

```powershell
.\scripts\ci\check-telemetry-component.ps1
```

The script uses `src\target\telemetry-component-check` for its Cargo output,
removes the tampered copy, and restores the caller's environment.

### Native module lifetime regression

From `src`, run:

```text
cargo build --locked -p mxc-sdk --example module_lifetime_fixture
cargo test --locked -p mxc-sdk --test module_lifetime
```

The fixture runs the production filesystem probe until it times out. The test
then closes its library handle, releases the blocked operation, and checks that
the worker can finish. Removing the probe's module pin must fail this regression.
It runs in a subprocess so an unload
regression cannot crash the test runner. The full native Cargo test suites also
run this test in the independent Windows workspace suites and the macOS build.
Windows builds the standalone fixture in its early producer; macOS builds it
before its suite. Both Linux
matrix lanes explicitly build the fixture and run the test in their release
profile with the lane's target.

### Filesystem probe request deadlines

The Windows and Linux builds run public SDK requests with a blocked existence,
object-identity, or delegation probe. Separate cases let those checks finish,
then block Bubblewrap denied- or granted-path resolution, LXC rebound/denied-mount resolution,
or WSLC overlap canonicalization. Each must return a path-specific timeout
without executing the workload. WSLC coverage also calls container provisioning.
A separate process enforces a 15-second watchdog so a missing timeout fails
rather than hanging CI. Fault injection is compiled only under `cfg(test)`;
shipping libraries and executors contain no blocking-path switch.

Run locally from `src`:

```text
cargo test --locked -p mxc-sdk --lib filesystem_probe::launch_tests:: -- --ignored --skip lxc_mount_paths_reject_stalls
cargo test --locked -p mxc-sdk --lib --features wslc filesystem_probe::launch_tests:: -- --ignored
```

Use the first command on Linux (with Bubblewrap installed) and the second on
Windows. Run `lxc_mount_paths_reject_stalls` separately as root with the LXC
command-line tools installed. It creates an empty container without downloading
an image or starting a workload, uses private container storage, and verifies
timeout cleanup. The builds stage `mxc-filesystem-probe-tests` (`.exe` on Windows)
alongside the executor artifacts, but exclude it from the published npm SDK
package. Scheduled Bubblewrap, LXC, and WSLC suites
require this executable, verify the expected tests are present, and run their
backend's cases without rebuilding.

### .NET SDK validation

The SDK, behavioral tests, and Native AOT smoke test target `net8.0` and
`net10.0`; samples and the console driver target `net10.0`. Use the .NET 10 SDK
selected by the root `global.json`; its Microsoft.Testing.Platform runner
selection also applies to `dotnet test`. Windows test bundles explicitly
publish `net10.0`; the Azure two-branch template selects `net8.0` for older
checkouts that do not support `net10.0`.

The .NET SDK job builds and tests both frameworks on Windows, Linux, and macOS.
The Linux LXC and Bubblewrap regression checks and Windows optional-backend
checks run separately for each framework and reject empty test selections.
It installs the pinned Rust toolchain before building either framework.
On Windows, its native Cargo builds use that toolchain's LLVM linker, as
the shipping and workspace jobs do. Default and optional-backend builds,
both test frameworks, Native AOT publishing, and package validation retain
their existing configurations and test selections.
It publishes and runs the reflection-free JSON Native AOT smoke test for
both .NET 8 and .NET 10, then packs the SDK and installs it into separate
temporary .NET 8 and .NET 10 applications outside the checkout. Each application
calls the platform and backend discovery APIs without `MXC_FFI_DIR` and checks
that its managed SDK assembly matches the package asset for its target
framework. An unsupported-host result is valid; native loading, interop, and
deserialization exceptions still fail the check. These package checks do not
require an available containment backend. Each consumer also checks that
execution fails when its packaged native library is removed.

From `sdk/dotnet`, run:

```text
dotnet build Microsoft.Mxc.Sdk.slnx -c Release
dotnet test --solution Microsoft.Mxc.Sdk.slnx -c Release --no-build
```

To run the same packed-SDK check as CI, use PowerShell 7 from any directory:

```powershell
& <repo>\scripts\ci\test-dotnet-package.ps1
```

First build the solution as above to restore its dependencies. The script
packs the SDK in Release configuration, runs both temporary consumers, and
removes their isolated package caches and output afterward. Use
`-Configuration Debug` to pack a Debug build instead. It temporarily clears
`MXC_FFI_DIR` and restores the caller's value when finished. The temporary
directory must be outside a checkout. Both .NET 8 and .NET 10 runtimes must be
installed.

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

The Linux .NET SDK job also installs Bubblewrap and strictly runs
`MxcContainerBubblewrapE2ETests.Spawn_OutlivesTheThreadThatSpawnedIt`. The
backend availability gate turns a missing Bubblewrap prerequisite into a
failure, and the exact-method filter plus result-count check ensures the
regression itself ran and passed.

### WSLC gateway image

`wslc-gateway-image-check` rebuilds the committed WSLC gateway images on
Windows x64 and fails if they don't match the source. Regenerate them with
`scripts/build-wslc-gateway-image.ps1`; see
[WSLC gateway image](wslc-gateway-image.md).

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

### Local Windows capture diagnostics benchmark

From `src`, run:

```text
cargo test --release -p mxc-sdk --lib benchmark_high_cardinality_network_capture -- --ignored --nocapture
```

This opt-in benchmark exercises the production network extractor, bounded
aggregation, denial deduplication, v5 document construction, JSON writing, and
version-specific validation. It compares repeated signatures with changing
filter IDs and ephemeral local ports for connections to the same destination,
at 4,096, 100,000, and 1,000,000 events. It reports retained groups, output bytes,
post-TDH processing time, document construction/writing time, and average
version-dispatching validation versus direct v5 deserialization time.
It also checks denial and overflow accounting. Timings are measurements, not
CI pass/fail thresholds. This synthetic decoded-event workload excludes TDH
decoding, ETL I/O, and native trace stop/close, so it is not an end-to-end OS
capture or teardown measurement.

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