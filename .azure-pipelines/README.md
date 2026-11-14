# Configuration Strategy

> **Audience:** MXC developers

## Local development

Developers should use public registries like `crates.io`
and `npmjs` directly so they can iterate quickly.

## For CI/Pipelines

### Central Feed Services
Production CI pipelines use an Azure Artifacts feed (CFS) to source dependencies
from crates.io and npmjs, helping ensure secure and vetted consumption of third‑party packages.
(Microsoft engineers can consult the internal "Central Feed Services" documentation for setup details; external readers can treat the centralized feed as a Microsoft-internal Azure Artifacts mirror of the public registries.)

### Production Build and Release pipelines
- The ADO pipeline is the official build pipeline that signs the binaries and
  drives public releases. It runs on merge to `main` and on a nightly schedule.
- The shared build stages assemble the managed and native .NET SDK binaries
  into two `Microsoft.Mxc.Sdk` NuGet packages in both official and unofficial
  builds. Official builds sign the managed and native binaries before packaging,
  then sign and verify each package through ESRP with CP-401405. The NuGet.org
  payload keeps the project version; the internal-test payload includes the
  unique Azure Pipelines build ID in its prerelease version so repeated
  publications do not collide.
- A fast .NET pipeline validation stage runs in parallel with the Rust builds.
  It verifies the .NET 10 SDK/runtime setup and packs both NuGet variants with
  synthetic native inputs so pipeline and package-contract failures surface
  without waiting for the cross-platform Rust artifacts.
  Both variants contain managed assemblies under `lib/net8.0` and `lib/net10.0`;
  applications targeting .NET 8 or .NET 9 use the .NET 8 assembly.
- `1ES.Release.Nuget.yml` publishes the signed .NET SDK and optional NVX runtime
  packages to the internal `Mxc-Azure-Feed` by default, or to NuGet.org through
  ESRP. Both packages are selected by default, with the SDK published first.
  If a release partially succeeds, select only the unpublished package when
  retrying. Use the same build artifact and version for both packages: the NVX
  runtime depends on the matching SDK, and the pipeline cannot check an
  already-published package on NuGet.org.
  `scripts/ci/test-nuget-release-selection.ps1` exercises package selection and
  validation without publishing.
- `1ES.Release.Npm.yml` publishes the signed SDK and optional NVX runtime npm
  packages through ESRP. Both are selected by default, with the SDK first.
  When retrying a partial release, select only the unpublished package from
  the same build and version.

Release artifacts include their package-selection scripts, so release jobs
do not need a repository checkout. Choose a build artifact containing the
appropriate selector script.

### Rust crates.io release

`1ES.Release.Crates.yml` is a manual pipeline. `dryRun` defaults to `true` and
runs `cargo publish --dry-run` from any ref after creating the release archives.
Publishing through ESRP requires an immutable `refs/tags/v*` tag and explicitly
setting `dryRun` to `false`.

- `mxc-sdk` uses the workspace version and complete crates.io metadata.
- `Invoke-CratePackage.ps1` verifies that `mxc-sdk` is the only Rust release
  crate and packages it into the release artifact.
- Azure Pipelines packages `mxc-sdk` once using the private Rust toolchain and
  dependency feed.
- The publish template owns the crate list; release operators cannot override
  it at queue time. GitHub CI rejects any difference from the validated list.
- Every release runs Cargo's crates.io dry run before the publish job submits
  the package through ESRP.

### PR Pipelines
- GitHub Actions runs the PR validation build automatically on every pull
  request — it mirrors the ADO build stages on native hardware for faster
  developer iteration.
- The ADO pipeline can also be triggered on PRs via `/azp run`
  (see [pull request builds](../docs/development/build-and-test/pull-requests.md)) when reviewers want
  to run the official build against a change before merge.
