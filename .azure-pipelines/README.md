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
When the original BNS drops have expired, set `sourcePipelineRunId` to a
retained successful run from this pipeline. The build downloads that run's
architecture artifacts, validates their BuildGuid/branch/architecture, and
restages only the six lifted binaries plus two WinMDs. Any historical
`IsoSessionCore.dll` in the retained artifact is ignored so the corrected
inbox-Core contract remains enforced.

If publication fails after a release candidate has already passed manual
qualification, set `promotionSourceRunId` to that qualified run. The pipeline
skips rebuilding, downloads the exact aggregated artifact from the selected
run, repeats its production-signing and hash checks, and retries internal NuGet
publication. ESRP MSI publication is intentionally unavailable in this retry
mode.

For non-release validation, keep `signingMode=test` and
`enablePromotion=false`.

For a release-candidate run, set `signingMode=production` and
`enablePromotion=true`. The pipeline derives the approved signing policy:
`CP-230072` for test builds and `CP-230012` for production builds. It builds and
signs once, then waits on a manual validation step before publishing those exact
bytes. After supported-SF2 qualification, resume the validation. Set
`publishToRestrictedFeed` on the same run to publish the aggregated SDK NuGet
to the configured internal Azure Artifacts feed. Keep
`publishMsiToEsrp=false` while the release must remain Microsoft-internal; the
production-signed MSI/bootstrapper files remain available as internal ADO
pipeline artifacts. Set `publishMsiToEsrp=true` only after the ESRP CDN
destination is approved for the intended external visibility.

### PR Pipelines
- GitHub Actions runs the PR validation build automatically on every pull
  request — it mirrors the ADO build stages on native hardware for faster
  developer iteration.
- The ADO pipeline can also be triggered on PRs via `/azp run`
  (see [docs/pull-requests.md](../docs/pull-requests.md)) when reviewers want
  to run the official build against a change before merge.