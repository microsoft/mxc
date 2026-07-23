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

### PR Pipelines
- GitHub Actions runs the PR validation build automatically on every pull
  request — it mirrors the ADO build stages on native hardware for faster
  developer iteration.
- The ADO pipeline can also be triggered on PRs via `/azp run`
  (see [docs/pull-requests.md](../docs/pull-requests.md)) when reviewers want
  to run the official build against a change before merge.

## npm SDK packaging: meta + per-platform binary packages

`@microsoft/mxc-sdk` is a **meta package that ships no native binaries**. Each
host's executor binaries are delivered through one of six per-platform
packages, which the meta package lists as exact-pinned `optionalDependencies`:

```
@microsoft/mxc-sdk-win32-x64     @microsoft/mxc-sdk-win32-arm64
@microsoft/mxc-sdk-linux-x64     @microsoft/mxc-sdk-linux-arm64
@microsoft/mxc-sdk-darwin-x64    @microsoft/mxc-sdk-darwin-arm64
```

npm's `os`/`cpu` filtering installs only the package matching the consuming
host, so an install downloads just that host's payload.

### Pipeline flow

- **Build** (`Build_Binaries`) produces the `wxc-binaries-*` / `lxc-binaries-*` /
  `mxc-binaries-*` artifacts.
- **Package** (`Package.NpmSdk.Job.yml`) stages each artifact into
  `sdk/node/platform-packages/<os>-<arch>/`, verifies versions/pins are in sync
  (`scripts/sync-platform-package-versions.js --check`), packs the meta package
  (artifact `mxc-npm-sdk-package`) and each per-platform package whose primary
  binary is present (artifact `mxc-npm-sdk-platform-packages`), then runs a
  **release-completeness gate** that fails the build unless every
  `@microsoft/mxc-sdk-*` optional dependency the meta package pins has a matching
  packed tarball.
- **Release** (`1ES.Release.yml`) publishes the **platform packages first**, then
  the **meta package last** — the meta's exact-pinned optional deps must already
  exist on the registry when it is published.

### One-time / ops setup (manual — not automated here)

- **Register the six package names** under the `@microsoft` npm org with the same
  access, provenance, and signing settings as `@microsoft/mxc-sdk`
  (`@microsoft/mxc-sdk-{win32,linux,darwin}-{x64,arm64}`). The release step cannot
  create org-scoped names that do
  not yet exist with the right permissions. **Recommended preflight:** before the
  meta publish, verify each name exists under the expected org/provenance and that
  the exact version is either being published this run or already present.
- **Lockfile integrity is bootstrapped at first publish.** Until the platform
  packages exist on the registry, `sdk/package-lock.json` records them as stubs
  with no `resolved`/`integrity` (you cannot hash an unpublished tarball). After
  the **first** successful publish, run `npm install --package-lock-only` in
  `sdk/` and commit the lockfile so the optional-dep entries gain
  `resolved`/`integrity`; subsequent `npm ci` then verifies the native-binary
  tarball hashes.
- **Partial-publish recovery.** Platform-first / meta-last is two ESRP steps and
  is not atomic: if it fails after publishing some platform packages, those
  versions are immutable (re-publishing the same version returns `403`). Recover
  by bumping the version (`src/Cargo.toml` + `sdk/package.json`, then
  `node scripts/sync-platform-package-versions.js`) and re-running the release.
- **Offline / air-gapped mirrors** must carry all six platform packages, not just
  the meta package.
- **Cross-compiled consumers** (e.g. building a Windows VS Code bundle on a Linux
  agent) get the *agent's* platform package from a plain `npm install`. Such
  consumers must use npm's `--os`/`--cpu` install overrides (npm 10+) or a
  packaging step that force-installs the target platform package.