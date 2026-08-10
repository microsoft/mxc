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

### IsolationSession OS artifact packaging

`1ES.IsoSession.Artifacts.yml` is a manually queued 1ES pipeline that:

1. Resolves x64 and ARM64 Windows `BIN` drops from a BNS `BuildGuid`.
2. Downloads only the required IsolationSession binaries.
3. Extends a restricted metadata-only SDK NuGet into separate `.x64` and
   `.arm64` packages.
4. Builds native MSI and bootstrapper EXE installers for both architectures.
5. Applies the existing IsolationSession test-signing policy and publishes
   pipeline artifacts.

Queue parameters include `buildGuid`, `monthId`, `patch`, and the restricted
Azure Artifacts feed coordinates for the base metadata package. The base
package version must be `0.<YYYYMM>.0` for the selected `monthId`.

This pipeline does not publish publicly. The generated NuGets retain WinMD
metadata whose redistribution requires documented approval, and test-signed
artifacts must be production-signed before release.

### PR Pipelines
- GitHub Actions runs the PR validation build automatically on every pull
  request — it mirrors the ADO build stages on native hardware for faster
  developer iteration.
- The ADO pipeline can also be triggered on PRs via `/azp run`
  (see [docs/pull-requests.md](../docs/pull-requests.md)) when reviewers want
  to run the official build against a change before merge.