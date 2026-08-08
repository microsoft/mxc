# Publishing MXC Crates to crates.io

This document describes the Azure DevOps pipeline that publishes MXC's Rust
crate workspace to [crates.io](https://crates.io) via ESRP Release.

## Overview

The **1ES.Release.Crates** pipeline (`.azure-pipelines/1ES.Release.Crates.yml`)
packages and publishes the 20-crate release closure from the MXC Rust workspace
in a single pipeline run:

1. **Package stage** — checks out the release ref the run was queued against,
   runs one `cargo package` invocation carrying a `-p` flag per crate, and
   uploads the `.crate` files plus a `release-order.json` manifest as the
   `mxc-crates-package` artifact.
2. **Publish stage** — downloads that artifact and publishes each `.crate` to
   crates.io through ESRP, one `EsrpRelease@12` task per crate, leaf-first.

No `CARGO_REGISTRY_TOKEN` exists in this repository. ESRP holds the publishing
credentials and publishes under the `microsoft-oss-releases` account.

## Crate list

The set of packages to publish is the `CRATES` list in
`.azure-pipelines/scripts/crates_release.py`. Listed alphabetically here — the
publish order is *not* a property of this list, see below.

- `appcontainer_common`
- `bwrap_common`
- `hyperlight_common`
- `isolation_session_bindings`
- `isolation_session_common`
- `learning_mode_core`
- `learning_mode_windows`
- `lxc_common`
- `mxc-sdk`
- `mxc_engine`
- `mxc_pty`
- `mxc_telemetry`
- `nanvix_common`
- `nanvix_runner`
- `sandbox_spec`
- `seatbelt_common`
- `windows_sandbox_common`
- `windows_sandbox_lifecycle`
- `wslc_common`
- `wxc_common`

These names are provisional until the public naming scheme is approved.

## Publish order

Leaf-first, because each crate must already be on crates.io before anything
that depends on it can publish. The order is a topological sort of the
workspace dependency graph, computed from `cargo metadata` — nobody works it
out by hand. `package` orders the `.crate` files it builds by that sort, and
the same sort generates the `crateOrder` default in
`.azure-pipelines/templates/Publish.CratesIo.Job.yml`, which drives the ESRP
steps.

`crateOrder` has to be static YAML: `${{ each }}` expands at compile time,
before any script has run, so the ESRP steps cannot be generated from an order
computed during the run. It is therefore a **pasted copy** of the command's
output rather than a live call.

Nothing about pasting is trusted, though. The `Versioning Checks` workflow runs
`crates_release.py check-template` on every pull request, which recomputes the
order and fails the build if the template does not match it exactly — same
crates, same sequence. Editing `CRATES` and forgetting to regenerate is a red
build, not a bad release.

That check exists because the run-time check cannot catch this case.
`verify-order` accepts an ordered *subset* of the packaged closure — that is
deliberate, and it is what makes a partial resume possible — so a `crateOrder`
missing a newly-added crate **passes** it, and the crate is silently never
published. Nothing fails; the only trace is a `PARTIAL RELEASE` warning in a
log read after the fact. A missed publish is also not repairable by re-running,
since the crates that did land cannot be republished. So the drift has to be
caught before the release, at PR time, which is what `check-template` does.

**You do not work the order out by hand.** One command produces it:

```bash
python3 .azure-pipelines/scripts/crates_release.py order
```

That prints the list ready to paste over the `crateOrder` default in
`.azure-pipelines/templates/Publish.CratesIo.Job.yml`. It validates the graph
before printing, so a broken workspace produces a named error rather than a
list that fails halfway through a release.

To add a crate, put the package name anywhere in the `CRATES` list in
`.azure-pipelines/scripts/crates_release.py` — that list is an unordered *set*
of what to publish, not an ordering — then run the command above and paste the
result over `crateOrder`. Both steps are required, and `check-template` is what
catches doing only the first. `verify-order` does **not**: it accepts an ordered
subset by design, so a stale `crateOrder` passes it and the new crate is simply
never published.

## How versions are determined

All crates declare `version.workspace = true` in their own `Cargo.toml`, so the
single `version` field in `src/Cargo.toml` (currently `0.7.0`) is the version
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
rejects (duplicate version). See [Resuming a failed release](#resuming-a-failed-release)
for what to do when only some crates landed.

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
   `crateOrder` is not a field either — it is a dependency-derived topological
   order, not an operator choice, so it lives in
   `.azure-pipelines/templates/Publish.CratesIo.Job.yml` where the dialog
   cannot render it. To change it (to resume a partial release), edit that
   template — see [Resuming a failed release](#resuming-a-failed-release).

5. Click **Run**.
6. Confirm the package stage succeeds and its `check-template` step passes.
   The **Publish Crates.io Packages** stage stays visible and is reported as
   **Skipped** — on a dry run that is the expected result, not a failure. A
   dry run deliberately does not execute the publish job, so there are no
   per-crate `DRY RUN:` lines to look for; the publish order is checked in the
   package stage instead, against `cargo metadata`.

   **What a dry run does not cover.** Because the publish job does not run at
   all, a dry run proves the crates build, package, and are ordered correctly —
   and nothing beyond that. It does *not* exercise the pipeline artifact
   round-trip, `verify-order` against the packaged `release-order.json`, the
   per-crate SHA-256 check in `stage`, the ESRP staging directory, or ESRP
   itself. Those first execute during a real release. A green dry run is
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
The `Validate_Release_Ref` stage therefore checks it at runtime and fails the
run immediately if it is empty or space-only, before anything is checked out or
packaged — an empty value would otherwise submit an ESRP release with no owner
or no approver.  If this pipeline is ever automated rather than queued by a
person, set an explicit address in the YAML.

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

## Resuming a failed release

crates.io rejects duplicate versions. If the pipeline fails partway through
(e.g. crate 7 of 20 fails for a transient reason), crates 1–6 are already
published and cannot be republished.

To resume:

1. Identify which crates were already published (check the pipeline logs — each
   successful `EsrpRelease@12` task confirms its crate).
2. Branch from **the exact commit the failed run used**, not from `main`:

   ```bash
   git switch --detach <sha-of-failed-release-ref>
   git switch -c release/v0.8.0-resume1
   ```

   The already-published crates were built from that commit. Cutting the resume
   branch from `main` instead would package whatever `main` has become since,
   so the second half of the release would be built from different source than
   the first — and if the workspace version has moved, `cargo package` produces
   versions that no longer match what is on crates.io.
3. On that branch, edit the `crateOrder` default in
   `.azure-pipelines/templates/Publish.CratesIo.Job.yml`, removing the
   already-published crates. Keep the remaining entries in their existing
   relative order, and **do not** rerun `crates_release.py order` — that
   regenerates the full closure and would put the already-published crates
   back, which crates.io then rejects. Do not bump the crate version; the
   remaining crates still need to publish at the version that failed.

   Add a `RESUME-SUBSET` marker line directly above `default:`, naming the run
   this is resuming:

   ```yaml
     - name: crateOrder
       type: object
       # RESUME-SUBSET: run 4821 failed after appcontainer_common
       default:
         - bwrap_common
         - windows_sandbox_lifecycle
   ```

   The marker is **required**. Without it the packaging job fails the run,
   because a short `crateOrder` with nothing declaring intent is
   indistinguishable from one somebody forgot to regenerate. With it, the run
   still verifies the remaining crates are in valid dependency order and logs
   every crate it is assuming is already published.
4. Push that branch to `microsoft/mxc` and run the pipeline against it. The ref
   supplies the pipeline definition as well as the source, so the edited
   `crateOrder` only takes effect once it is on the release branch.
5. Merge the `crateOrder` edit to `main` separately, or revert it there once
   the release completes — `main` should end up carrying the full list again,
   with the `RESUME-SUBSET` marker removed, so the next release publishes the
   whole closure. A pull request into `main` that still carries the marker or
   the short list fails `check-template`, which is the intended backstop.

The `verify-order` guard accepts a subset of the original order as long as it
is still in correct leaf-first sequence. It logs a warning naming every
dependency it assumes is already live.

The `check-template` gate runs in two places, and a resume has to satisfy both.
CI runs it on pull requests into `main`; the release pipeline runs it again in
the packaging job, before any artifact is produced, because a release ref can
be pushed straight to `microsoft/mxc` without ever opening a pull request — so
CI alone would leave the irreversible path unguarded.

That is why step 3 requires the `RESUME-SUBSET` marker. Without it the release
pipeline refuses to publish a short list at all, which is the point: a trimmed
`crateOrder` is either a deliberate resume or a forgotten regeneration, and
nothing in the file distinguishes them unless the operator says so. With the
marker, the pipeline still proves the remaining crates are in valid dependency
order and prints exactly which crates it is assuming are already live.

Note that GitHub's `pull_request: branches:` filter matches the **base** branch,
not the source branch, so a pull request *from* a `release/*` branch *into*
`main` does run `check-template` — and should, since `main` must carry the full
list. Only a direct push to `release/*` skips the CI run, which is precisely
the case the release pipeline's own copy of the check covers.

There is no automated resume. The operator asserts what landed by editing
`crateOrder`.

## Network isolation

The publish job runs on a 1ES pool with CFSClean network isolation — crates.io
is **not reachable** from the agent. Dependency resolution during packaging uses
the internal `Mxc-Azure-Feed`, appended to the workspace cargo config by
`.azure-pipelines/templates/Cargo.Setup.Private.yml` from
`.azure-pipelines/.cargo/config.toml`. ESRP itself handles the outbound publish
to crates.io.

Packaging passes `--registry Mxc-Azure-Feed` to work around
[rust-lang/cargo#17196](https://github.com/rust-lang/cargo/issues/17196): with
`[source.crates-io] replace-with` active, cargo registers the temporary overlay
holding the just-packaged workspace siblings under the pre-replacement source
id but looks it up under the post-replacement one, so the overlay is silently
bypassed and each sibling is searched for in the feed, where it does not exist.
The emitted `.crate` files are byte-identical either way.

Because `--registry` already steers resolution to the temporary overlay,
per-crate verification builds succeed and packaging deliberately does *not*
pass `--no-verify`. Nor does it pass `--allow-dirty`: the only file the
pipeline modifies is the workspace `.cargo/config.toml`, which lies outside
every package directory and so does not make any package dirty. A dirty-tree
failure during packaging therefore means a crate source really was modified,
and should stop the release.

## Prerequisites / known blockers

These must be resolved before the first real (non-dry-run) publish:

1. **OSPO OSS-release registration** — the crate closure must be registered in
   OSPO's open-source release tracker before ESRP will accept a `Rust`
   content-type release.
2. **ESRP `Rust` content-type onboarding** — the ESRP service connection must
   have the `Rust` content type enabled, requested through the ESRP onboarding
   portal.
3. **`hyperlight_common` name collision** — crates.io treats `-` and `_` as
   equivalent when checking name collisions, so `hyperlight_common` collides
   with the existing `hyperlight-common` crate, published from
   github.com/hyperlight-dev/hyperlight.  It is the only one of the 20 names
   that is taken today; the other 19 are unregistered.  The crate must be
   renamed or co-ownership obtained before it can be published. Note that
   `hyperlight-common` is marked `trustpub_only` on crates.io, so co-ownership
   alone may not permit an ESRP token publish.
4. **crates.io rate limit** — the default `PublishNew` rate limit is burst-5
   plus 1 per 10 minutes.  A 20-crate first release will be throttled.  An
   override must be requested from help@crates.io before the first publish.
5. **Pipeline registration** — `.azure-pipelines/1ES.Release.Crates.yml` is new
   and must be registered as a pipeline in Azure DevOps, and that pipeline must
   be authorized to use the `MXC-ESRP-Signing` variable group.

## Pipeline and template files

| File | Purpose |
|------|---------|
| `.azure-pipelines/1ES.Release.Crates.yml` | Top-level release pipeline (parameters, release-ref gate, stage wiring) |
| `.azure-pipelines/templates/Package.Crates.Job.yml` | Packaging job — runs `cargo package`, produces artifact |
| `.azure-pipelines/templates/Publish.CratesIo.Job.yml` | ESRP publish job — `verify-order`, stage, publish loop |
| `.azure-pipelines/scripts/crates_release.py` | Helper script (`package`, `order`, `verify-order`, `check-template`, `stage` subcommands) |
| `src/Cargo.toml` | Workspace version (single source of truth for all crate versions) |

## Comparison with the npm release

The npm SDK release (`.azure-pipelines/1ES.Release.yml`) consumes artifacts from
a **separate** official build pipeline (`MXC-Official-Build`) and publishes a
single `@microsoft/mxc-sdk` package. The crates release is self-contained: it
checks out the release ref, packages, and publishes in one run. This design
exists because 1ES forbids `checkout` in a release *job*, but a normal job in
the same *pipeline* may check out and build.
