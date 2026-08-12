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
2. Downloads the six required IsolationSession runtime binaries.
3. Builds and test-signs x64 and ARM64 MSI/bootstrapper EXE artifacts in
   parallel.
4. Publishes separate x64 and ARM64 installer artifacts with release metadata
   and provenance.

Queue parameters include `buildGuid`, `monthId`, and `patch`. The canonical
release contract is `monthId + patch`, rendered as MSI/bundle `YY.M.patch.0`.

This pipeline does not build or publish the SDK NuGet because the BNS `BIN`
drop does not contain the two IsolationSession WinMDs. Test-signed installer
artifacts must be production-signed before release.

### PR Pipelines
- GitHub Actions runs the PR validation build automatically on every pull
  request — it mirrors the ADO build stages on native hardware for faster
  developer iteration.
- The ADO pipeline can also be triggered on PRs via `/azp run`
  (see [docs/pull-requests.md](../docs/pull-requests.md)) when reviewers want
  to run the official build against a change before merge.