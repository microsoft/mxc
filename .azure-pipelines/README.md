# Configuration Strategy

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
  into two unsigned `Microsoft.Mxc.Sdk` NuGet packages in both official and
  unofficial builds. Official builds sign the managed and native binaries
  before packaging. The NuGet.org payload keeps the project version; the
  internal-test payload includes the unique Azure Pipelines build ID in its
  prerelease version so repeated publications do not collide. Both payloads use
  neutral suffixes because release inputs reject unsigned `.nupkg` files.
- A fast .NET pipeline validation stage runs in parallel with the Rust builds.
  It verifies the .NET SDK/runtime setup and packs both NuGet variants with
  synthetic native inputs so pipeline and package-contract failures surface
  without waiting for the cross-platform Rust artifacts.
- `OneBranch.DotNet.Release.yml` selects the payload for the requested target,
  restores its `.nupkg` suffix, signs and verifies it, and publishes it to the
  internal `Mxc-Azure-Feed` by default. Queue-time selection can instead publish
  the fixed-version package publicly to NuGet.org through the `MXC Nuget`
  service connection.

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
  (see [docs/pull-requests.md](../docs/pull-requests.md)) when reviewers want
  to run the official build against a change before merge.