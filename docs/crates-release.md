# Publishing MXC Crates to crates.io

This document describes the Azure DevOps pipeline that publishes MXC's Rust
crate workspace to [crates.io](https://crates.io) via ESRP Release.

## Overview

The **1ES.Release.Crates** pipeline (`.azure-pipelines/1ES.Release.Crates.yml`)
packages and publishes the 21-crate release closure from the MXC Rust workspace
in a single pipeline run:

1. **Package stage** — checks out the release ref the run was queued against and
   runs `cargo package` on a Windows, a Linux, and a macOS agent, each carrying a
   `-p` flag per crate. The Windows leg uploads the `.crate` files as the
   `mxc-crates-package` artifact; the other two legs are verification that the
   closure builds natively on those systems.
2. **Publish stage** — downloads that artifact and publishes each `.crate` to
   crates.io through ESRP, one `EsrpRelease@12` task per crate, leaf-first,
   pausing `publishDelaySeconds` after each one to give crates.io time to
   serve the new version before the crate that depends on it goes up.  The
   pause is a fixed delay, not a check: network isolation forbids this job
   from reading crates.io, so nothing confirms the version is visible.  Each
   ESRP task is capped at `esrpTimeoutMinutes`, so a release that hangs fails
   that crate and stops the run instead of consuming the job timeout.

No `CARGO_REGISTRY_TOKEN` exists in this repository. ESRP holds the publishing
credentials and publishes under the `microsoft-oss-releases` account.

## Crate list

The crates to publish are the `crateOrder` parameter in
`.azure-pipelines/templates/Publish.CratesIo.Job.yml`, which is the only place
the list is written down. This document deliberately does not repeat it. The
packaging job derives the same order at run time and holds no copy either, so
there is nothing to keep in sync.

To see the current list without opening that file:

```pwsh
pwsh scripts/ci/Get-CrateOrder.ps1
```

21 crates ship today, but that count is derived, not declared — the script
above is the authoritative answer.  Their names are provisional until the
public naming
scheme is approved.

One name is deliberately not the obvious one.  The Hyperlight backend crate in
`src/backends/hyperlight/common` is named
`mxc-alpha-test-hyperlight-common`, not `hyperlight_common`, because crates.io
treats `-` and `_` as equivalent when checking name collisions and
`hyperlight-common` is already published from
github.com/hyperlight-dev/hyperlight.  That crate is also marked
`trustpub_only`, so co-ownership would not have permitted an ESRP token
publish.  Do not "correct" this name back — doing so makes the crate
unpublishable.  The directory keeps its original `hyperlight/common` path; only
the package name changed.

## Publish order

`crateOrder` is leaf-first, because each crate must already be on crates.io
before anything that depends on it can publish.

The list is literal YAML because `${{ each }}` expands when the pipeline
compiles, before any step has run, so the ESRP tasks cannot be generated from
an order computed during the run.

`scripts/ci/Get-CrateOrder.ps1` computes that order from
`cargo metadata`, and is both what the packaging job runs and how the literal
is regenerated:

```pwsh
pwsh scripts/ci/Get-CrateOrder.ps1 -Yaml
```

`-Yaml` prints paste-ready `- name` lines. Run it after adding or removing a
crate and replace the `crateOrder` default with its output. Because packaging
calls the same script, the packaged set is always the true closure of
`mxc-alpha-mxc-sdk`, whatever the literal says — the literal only decides what gets
published.

Nothing validates the literal against the packaged set before the release, and
mostly nothing needs to:

- **Wrong order** — crates.io rejects an upload whose dependency is not live
  yet, naming the dependency it could not resolve. The release stops at the
  first crate that is out of place.
- **A name in the list that was not packaged** — a typo, or a crate removed
  from the workspace. Staging fails on that crate with `expected exactly one
  .crate for <name>, found 0`, before ESRP is reached.
- **A packaged crate missing from the list** — this is the one gap. It ships
  in the artifact but generates no ESRP task, so nothing fails: it is simply
  never published. Regenerating the list is what prevents this.

## How versions are determined

All crates declare `version.workspace = true` in their own `Cargo.toml`, so the
single `version` field in `src/Cargo.toml` is the version
that ships. The pipeline does not set or override the version — it packages
whatever `src/Cargo.toml` contains at the tagged commit. To release a new
version:

1. Bump the version in `src/Cargo.toml`.
2. Commit and push.
3. Cut a release branch named `release/v<major>.<minor>.<patch>[-rc<n>]` (for
   example `release/v0.8.0`) from the commit you are releasing, and confirm
   the `release/*` ruleset has frozen it — see
   [Choosing the release ref](#choosing-the-release-ref).
4. Run the pipeline against that branch.

Re-running against the same ref re-packages the same version, which crates.io
rejects (duplicate version).

## Choosing the release ref

There is no ref parameter to type. The pipeline packages **the ref the run is
queued against**, chosen from the ref selector at the top of the **Run
pipeline** dialog.

`Validate_Release_Ref` accepts exactly two shapes:

| Ref | Example | How it is queued |
|---|---|---|
| `refs/heads/release/*` | `release/v0.8.0` | Picked in the Run dialog — **use this** |
| `refs/tags/v*` | `v0.8.0` | REST API |

Use the **branch**. For a GitHub-backed pipeline the Run dialog reliably
enumerates branches, so a release branch is what an operator can actually
select. Tags are accepted so a run can also be queued against the repo's
existing `v<semver>` tags through the REST API.

Selecting a **commit** does not work. A commit-queued run is still
branch-contextual: `Build.SourceBranch` reports the containing branch
(`refs/heads/main`), not the SHA, so the gate rejects it.

The gate fails the run for anything else — `main`, a feature branch, or an
unrelated tag — and both the package and publish stages depend on it, so
nothing is checked out or published from a non-release ref. That stage is
marked `isSkippable: false`, so it also cannot be switched off in the Run
dialog's **Stages to run** panel.

Azure DevOps offers no way to filter that selector, which is why the guard
exists. For enforcement outside the pipeline's own YAML, add a **branch
control check** to the ESRP service connection in the Azure DevOps UI.

### Freezing the release branch

**The gate proves a run came from a release ref. It cannot prove that ref is
immutable.** A branch moves unless something stops it, and the pipeline would
package wherever it points at run time.

Freeze `release/*` with a **GitHub ruleset** on the repository — Settings →
Rules → Rulesets — targeting `release/*` and blocking pushes, force-pushes,
and deletion, with no bypass list. Rulesets are the current mechanism and can
target branches and tags; classic branch protection can also freeze a branch
by restricting who may push, but is less expressive. This is a **repository
setting**, not something this pipeline can enforce, and it requires repo admin
rights.

Because the ref supplies the pipeline definition as well as the source,
changing anything about how a release is built — including this pipeline —
means cutting a new release ref.

## Running the pipeline (step-by-step)

### 1. Dry run (recommended first)

1. In Azure DevOps, navigate to Pipelines → find the pipeline registered
   against `.azure-pipelines/1ES.Release.Crates.yml`.
2. Click **Run pipeline**.
3. In the ref selector at the top of the dialog, pick the release branch
   (for example `release/v0.8.0`).
4. Set the one parameter:

   | Parameter | Value |
   |---|---|
   | **Dry run** (`dryRun`) | Leave at `true` — this is the default. |

   The Run dialog shows exactly this one field, because a release is defined
   by *which ref you picked*, not by what you type. Everything else is derived
   or fixed. The ESRP owner and approver are not fields — they are fixed to
   the identity that queued the run; see [ESRP identity](#esrp-identity).
   `crateOrder` is not a field either — it is a dependency order, not an
   operator choice. It has a default in `Publish.CratesIo.Job.yml`; to change
   it, edit that file on the release ref.

5. Click **Run**.
6. Confirm the package stage succeeds. The **Publish Crates.io Packages** stage
   stays visible and is reported as **Skipped** — on a dry run that is the
   expected result, not a failure. A dry run deliberately does not execute the
   publish job, so there are no per-crate `DRY RUN:` lines to look for.

   **What a dry run does not cover.** Because the publish job does not run at
   all, a dry run proves the crates build and package on all three OSes — and
   nothing beyond that. In particular it does *not* validate `crateOrder`:
   packaging derives its own order and ignores the list, so only a real
   release exercises it. It also does not exercise the pipeline artifact
   round-trip, the ESRP staging directory, or ESRP itself. A green dry run is
   evidence about the crates, not about the publish path.

### ESRP identity

The six ESRP signing fields (`serviceName`, `tenantId`, `azureKeyVaultName`,
`authCertName`, `signCertName`, `clientId`) come from the **`MXC-ESRP-Signing`**
variable group, the same group `.azure-pipelines/1ES.Build.Official.yml` uses
for code signing. The pipeline must be granted access to that group in ADO.

ESRP Release additionally needs owner and approver emails. The
`MXC-ESRP-Signing` group was inspected through the ADO REST API and contains
exactly the six signing keys above — it does **not** contain `OwnersEmail` or
`ApproversEmail`.  Both are therefore fixed in `1ES.Release.Crates.yml` to the
predefined variable `$(Build.RequestedForEmail)` — the email of whoever queued
the run — so the person releasing owns and approves their own release, with no
address typed and no individual hardcoded in the repository.

They are deliberately **not** pipeline parameters.  Anything declared under
`parameters:` renders as an editable field in the Run dialog, and an email
address is not a decision the person clicking Run should be asked to make:
there is no right answer for them to know, and a typo submits a release to the
wrong owner.

The value is a macro token, not a literal address: the `${{ }}` template
substitutions preserve the literal string `$(Build.RequestedForEmail)`, which
Azure DevOps expands at runtime in the `EsrpRelease` task's `owners` and
`approvers` inputs, since macro syntax is expanded in task inputs after
template expansion.

To release under a different owner or approver, change the value in
`1ES.Release.Crates.yml` and cut a new release ref.  That is intentional: the
ref supplies the pipeline definition as well as the source, which is what makes
a release reproducible from its ref alone.

`Build.RequestedForEmail` is the queuer's email for a manually queued run, but
it can resolve empty for a run started by a service identity or a schedule.
Nothing checks it up front, so an empty value surfaces at the `EsrpRelease`
task on a real release rather than before packaging.  If this pipeline is ever
automated rather than queued by a person, set an explicit address in the YAML.

### 2. Real release

Same pipeline and ref selection as above, but **set `dryRun` to `false`**. It
defaults to `true`, so publishing is always an explicit choice — there is no
way to reach crates.io without deliberately clearing that box.

Step 6 above does **not** apply to a real release, and the difference is the
check that tells you whether you actually published: the **Publish Crates.io
Packages** stage must *run* this time. If it still reports **Skipped**, then
`dryRun` was not cleared and **nothing was published** — the run is a dry run
that succeeded, not a release.

Each crate publishes sequentially via ESRP. If any crate fails, later crates
are skipped (the job fails).

**This step is irreversible.** crates.io does not allow a name to be deleted
or reused once a version exists, and the pipeline has no atomic publish and no
rollback: a failure partway through leaves everything already sent to
crates.io public. Do not clear `dryRun` until crate naming is settled and ESRP
`Rust` content type is enabled — see
[Prerequisites / known blockers](#prerequisites--known-blockers).

## Network isolation

The publish job runs on a 1ES pool with CFSClean network isolation — crates.io
is **not reachable** from the agent. Dependency resolution during packaging goes
through whichever mirror the build configured: official builds and the release
pipeline use the internal `Mxc-Azure-Feed`, appended to the workspace cargo
config by `.azure-pipelines/templates/Cargo.Setup.Private.yml` from
`.azure-pipelines/.cargo/config.toml`; unofficial and fork builds, including the
PR packaging legs, use the anonymous public `MxcDependencies` mirror appended by
`Cargo.Setup.Public.yml` from `.azure-pipelines/.cargo/config.public.toml`. ESRP
itself handles the outbound publish to crates.io.

Packaging passes `--registry` naming that same feed to work around
[rust-lang/cargo#17196](https://github.com/rust-lang/cargo/issues/17196), open
and reproducible on the pinned toolchain at the time of writing: with `[source.crates-io] replace-with` active, cargo
registers the temporary overlay holding the just-packaged workspace siblings
under the pre-replacement source id but looks it up under the post-replacement
one, so the overlay is silently bypassed and each sibling is searched for in the
feed, where it does not exist. The value must name a registry the effective
cargo config declares, or cargo fails with "registry index was not found in any
configuration" before packaging starts.

Because `--registry` already steers resolution to the temporary overlay,
per-crate verification builds succeed and packaging deliberately does *not*
pass `--no-verify`. Nor does it pass `--allow-dirty`: the files the pipeline
writes into the tree — the workspace `.cargo/config.toml`, and `rustup-init`
plus its `.sha256` sidecar at the repo root — all lie outside every package
directory, so none of them makes a package dirty. A dirty-tree failure during
packaging therefore means a crate source really was modified, and should stop
the release.

## Prerequisites / known blockers

These must be resolved before the first real (non-dry-run) publish:

1. **OSPO OSS-release registration** — the crate closure must be registered in
   OSPO's open-source release tracker before ESRP will accept a `Rust`
   content-type release.
2. **ESRP `Rust` content-type onboarding** — the ESRP service connection must
   have the `Rust` content type enabled, requested through the ESRP onboarding
   portal.
3. **crates.io rate limit** — the default `PublishNew` rate limit is burst-5
   plus 1 per 10 minutes.  `publishDelaySeconds` is set to 660 to wait it out,
   which spends 231 minutes across the closure and is why the publish job
   allows 360 minutes.  An override from help@crates.io would remove the wait.
4. **Pipeline registration** — `.azure-pipelines/1ES.Release.Crates.yml` is new
   and must be registered as a pipeline in Azure DevOps, and that pipeline must
   be authorized to use the `MXC-ESRP-Signing` variable group.

## Pipeline and template files

| File | Purpose |
|------|---------|
| `.azure-pipelines/1ES.Release.Crates.yml` | Top-level release pipeline — the release-ref gate and the stage wiring |
| `.azure-pipelines/templates/Package.Crates.Job.yml` | Packaging job — runs `cargo package` over the derived order and produces the artifact |
| `.azure-pipelines/templates/Publish.CratesIo.Job.yml` | ESRP publish job — declares `crateOrder`, sets a 360-minute job timeout, caps each ESRP release at `esrpTimeoutMinutes`, and runs one staging step, one rate-limit wait, and one `EsrpRelease@12` task per crate |
| `scripts/ci/Get-CrateOrder.ps1` | Computes the leaf-first order from `cargo metadata` — run by packaging, and by a developer regenerating `crateOrder` |
| `scripts/ci/Invoke-CratePackage.ps1` | Packages the closure and copies the `.crate` files where the artifact task reads them — run by the packaging job |
| `src/Cargo.toml` | Workspace version (single source of truth for all crate versions) |

## Comparison with the npm release

The npm SDK release (`.azure-pipelines/1ES.Release.yml`) consumes artifacts from
a **separate** official build pipeline (`MXC-Official-Build`) and publishes a
single `@microsoft/mxc-sdk` package. The crates release is self-contained: it
checks out the release ref, packages, and publishes in one run. This design
exists because 1ES forbids `checkout` in a release *job*, but a normal job in
the same *pipeline* may check out and build.
