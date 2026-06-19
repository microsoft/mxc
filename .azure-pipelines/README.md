# Configuration Strategy

## For Developers

Developers should to use public registries like `crates.io`
and `npmjs` directly so they can iterate quickly.

## For CI/Pipelines

### Central Feed Services
Production CI pipelines use an Azure Artifacts feed (CFS) to source dependencies
from crates.io and npmjs, helping ensure secure and vetted consumption of third‑party packages.
(Microsoft engineers can consult the internal "Central Feed Services" documentation for setup details; external readers can treat the centralized feed as a Microsoft-internal Azure Artifacts mirror of the public registries.)

### Production Build and Release pipelines
- The ADO pipeline is the official build pipeline that signs the binaries and
  drives public releases. It runs on merge to `main` and on a nightly schedule.

### PR Pipelines
- GitHub Actions runs the PR validation build automatically on every pull
  request — it mirrors the ADO build stages on native hardware for faster
  developer iteration.
- The ADO pipeline can also be triggered on PRs via `/azp run`
  (see [docs/pull-requests.md](../docs/pull-requests.md)) when reviewers want
  to run the official build against a change before merge.

### Public crates.io mirror feed (fork/PR builds)

Fork PRs lose `System.AccessToken`, so the network-isolated ADO build cannot
authenticate to the internal feed. Those builds instead redirect crates.io to
the **public, anonymous-read** `MxcDependencies` feed
([`.cargo/config.public.toml`](.cargo/config.public.toml)). Anonymous clients
can only read crate versions that have already been **saved** to that feed;
pulling a not-yet-cached version from the crates.io upstream requires
authentication and otherwise returns HTTP 401.

Because fork PRs only run the GitHub Actions gates (which build against real
crates.io), a fork-PR lockfile bump can introduce a brand-new transitive crate
that was never cached in the public feed — and the next in-repo PR or `main`
push then fails `cargo fetch` with a 401.

[`Seed.Cargo.Feed.yml`](Seed.Cargo.Feed.yml) closes that gap. It runs on `main`
whenever `src/Cargo.lock` changes (and on a daily schedule), and authenticated-
downloads every locked crate's `.crate` file via
[`scripts/ci/seed-cargo-feed.ps1`](../scripts/ci/seed-cargo-feed.ps1), which
permanently saves each version into the feed. It requires the variable group
`MXC-Public-Feed-Seeding` with a secret `publicFeedPat` (a PAT with Packaging
Read scope on the org backing the feed). The script can also be run locally to
seed the feed on demand:

```pwsh
$env:CARGO_FEED_PAT = '<pat>'
pwsh ./scripts/ci/seed-cargo-feed.ps1
```