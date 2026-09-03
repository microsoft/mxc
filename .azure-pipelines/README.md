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
2. Downloads the required IsolationSession runtime binaries and both WinMDs.
3. Builds and Microsoft-signs x64 and ARM64 MSI/bootstrapper EXE artifacts in
   parallel.
4. Builds `Microsoft.Windows.AI.IsolationSession.SDK` from those OS outputs,
   including the x64 activation shim and version-selection sidecar.
5. Publishes separate x64 and ARM64 installer artifacts plus one aggregated
   release artifact with the SDK NuGet, release metadata, and provenance.

Queue parameters include `buildGuid`, `monthId`, and `patch`. The canonical
release contract is `monthId + patch`, rendered as MSI/bundle `YY.M.patch.0`.

For non-release validation, keep `signingMode=test`,
`signingKeyCode=CP-230072`, and `enablePromotion=false`.

For a release-candidate run, set `signingMode=production`,
`signingKeyCode=CP-230012`, and `enablePromotion=true`. The pipeline builds and
signs once, then waits on both a manual validation step and the configured
Azure Pipelines environment before publishing those exact bytes. After
supported-SF2 qualification, resume the validation and approve the environment
check. Set `publishToRestrictedFeed` on the same run to publish the aggregated
SDK NuGet to the configured internal Azure Artifacts feed before the x64 and
ARM64 MSI release jobs submit the signed installers to ESRP CDN.

### PR Pipelines
- GitHub Actions runs the PR validation build automatically on every pull
  request — it mirrors the ADO build stages on native hardware for faster
  developer iteration.
- The ADO pipeline can also be triggered on PRs via `/azp run`
  (see [docs/pull-requests.md](../docs/pull-requests.md)) when reviewers want
  to run the official build against a change before merge.