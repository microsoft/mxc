# MXC developer-loop: setup and maintenance

> **Audience:** MXC consumers and developers

This README owns **navigation, runtime setup, and maintainer tasks**. The bundle
starts with general MXC backend guidance and loads a bounded, enforced Windows
ProcessContainer learning loop only when needed. The executable loop is a trusted
developer-fixture POC, not a tamper-resistant authorization service for hostile workloads.

## Documentation ownership

| Document | Owns | Read it when |
|---|---|---|
| [SKILL.md](SKILL.md) | General entrypoint, containment selection, and links to release-specific SDK guidance | Starting an MXC task |
| [processcontainer-loop.md](processcontainer-loop.md) | Windows learning-loop scope, consent, helper commands, candidate format, stopping, and reporting | Operating the ProcessContainer loop |
| **README.md** | SDK/native-runtime setup, compatibility, and reference maintenance | Setting up the loop or maintaining the bundle |
| [configuration-notes.md](references\configuration-notes.md) | Supported permission changes, scope vocabulary, filesystem/network/UI rules, and sourced evidence | Choosing or reviewing configuration changes |
| [functional-verification.md](references\functional-verification.md) | Agreed checks, stdout record contract, interpretation, and Shell examples | Preparing or interpreting functional checks |
| [policy-1.0.0.md](references\policy-1.0.0.md) | Immutable upstream explanation of the full MXC contract, including backends outside this loop | Looking up relevant MXC behavior |

The [JSON schema](references\mxc-config.schema.1.0.0.json) supplies exact fields
and types for this loop's **1.0.0 configuration contract**, not every SDK release
or backend. `references\manifest.json` pins permission-reference hashes and source
provenance; it is machine metadata, not another guide.

Keep detailed guidance in its owning document and link to it elsewhere.
Do not copy the operating procedure into this README or modify upstream snapshots
to describe helper-specific restrictions.

## Using the bundle

Ask the agent to read [SKILL.md](SKILL.md). It selects the relevant workflow;
reading every document in full is not a prerequisite.

Keep the complete bundle together. `scripts` contains setup, the controller,
boundary reviewer, and reference loader; `examples` contains request/candidate/approval
templates and strengthened Shell enumeration examples. Functional checks run
inside the agreed sandboxed workload; see
[functional verification](references\functional-verification.md) for the conversational
workflow and output contract.

The repository location is `.github\skills\mxc-developer-loop`. Use a skill
installer that supports repository subdirectories, or fetch this directory's
files at a chosen revision while preserving their relative paths. No MXC clone
or source build is required.

The skill bundle and MXC SDK are separate installations. A copy of this directory
can be registered in a client's approved skill location without keeping an MXC
source checkout. Use that client's documented installation method; do not assume
a universal skills directory or automatic discovery. Include `.gitattributes`,
the Markdown files, `scripts`, `references`, and `examples`, not just `SKILL.md`.
Development tests, demo workloads, native binaries, and run artifacts are not
part of this bundle. Copying or registering a skill requires an approved
destination and does not authorize running it.

### Helper interface

CLI output defaults to a compact decision view: latest-run log tails (2000
characters each, with explicit truncation flags), grouped denials retaining all
original indices and PIDs, complete functional evidence/errors, and relevant
proposal reviews. Complete diffs and permission warnings are never shortened.
When the published policy is the latest attempt, its per-check evidence appears
once at the top level, rather than being repeated under `finalConfiguration`.
The prepared baseline is inline initially; terminal results inline the exact
tested policy or, if none completed, the attempted request. Configurations are
digest-checked before being displayed as reviewed/tested.

Append `--full` to any invocation for the full result, including run history,
runtime, and reference metadata. `status "<results-dir>" --full` is read-only
and avoids diagnostic/configuration file rendering; use it to inspect a completed
operation if compact rendering failed, rather than replaying that operation.
The exported programmatic `main(args)` retains its full-result interface;
`cli(args)` applies CLI formatting. All original evidence remains on disk.
Legacy sessions retain their full read-only status output.

Candidate submissions normally omit `configuration`: the helper reads the
agent-edited draft and uses the same snapshot, validation, integrity, and approval
checks. Explicit full-configuration submissions remain supported. Neither route
rewrites the draft or treats `changes` as executable edits.

Every valid proposal returns `awaiting_approval` without activating or executing
the candidate, even for an in-scope grant or removal-only consolidation.
`permissions[].withinScope` records scope membership, not preapproval.
`pendingApproval` includes all candidate permissions; the complete diff must
still be reviewed when that list is empty. The session form always offers
optional free-text functional checks: blank selects exit-code-only verification,
normally exit `0`, when no checks were already requested. Otherwise it invites
additional checks, and blank preserves the requested checks. Neither blank
answer is a request to investigate or invent verification.

Requests may use `commandLineFile` **instead of** `commandLine`. This must be an
absolute path to an existing UTF-8 file containing the exact agreed command.
Initialization strips a BOM and one trailing newline, then saves the resolved
command; later changes to the source file cannot change an active session.

The normal approval question covers activation and one bounded retest. Record
that actual consent with `approvedByCaller: true, retryApproved: true` and invoke
`approve` once; it runs the ordinary bounded retry after releasing the approval
lock. Do not follow it with another `run`. False/omitted `retryApproved` remains
activation-only for older callers and explicit "don't run yet" decisions.
The chained run is bound to the approved proposal ID and digest; if another
operation replaces that candidate before the run acquires its lock, it stops.
Decline plus retry is invalid. No automatic init/propose execution or budget
expansion is enabled. See the [loop workflow](processcontainer-loop.md) for review
and consent requirements.

## Runtime setup

### Requirements

- Windows with working enforced ProcessContainer denial capture.
- Node.js 22 or newer for the helper, which uses only built-in modules.
- A compatible `wxc-exec.exe`, with its native bundle's companion files.
  The helper uses the 1.0.0 request contract, not the SDK's JavaScript APIs.

An SDK installation also requires npm and the selected release's own Node
requirements; check its metadata rather than assuming the helper's minimum
is sufficient. No fixed installation directory or MXC source checkout is required.

### Select and check one runtime

The normal source is an existing `@microsoft/mxc-sdk` installation in a specified
project/tools directory, or an explicitly supplied built runtime. Reuse a path
already provided; otherwise use this short setup question:

**"Have a built MXC runtime or SDK installed? Paste the wxc-exec.exe path or SDK
folder. Leave the MXC field blank to set up the SDK."**

Use one free-text field, **"MXC runtime or SDK path (optional)"**, with
`default: ""`. Ask for a workload executable path separately in the same form
only if it is also missing; that field is not an SDK-install choice. Do not add
fixture plans or repeat the skill's implementation details in the message.

An accepted blank MXC field selects the
[SDK installation flow](#optional-approved-sdk-installation), not immediate
installation consent. Show the exact package/version, source, and destination
in one short confirmation before installing. Cancellation or decline is not an
installation request. Do not pass a blank path to the setup helper.

Do not search PATH, checkouts, unrelated folders, or whole drives. A missing file
at one location is not proof that no installation exists.

Use **one** selector, with an absolute local Windows path:

```powershell
# Standard local npm layout: <prefix>\node_modules\@microsoft\mxc-sdk
node "<skill-dir>\scripts\mxc-setup.cjs" --sdk-prefix "<approved-project-or-tools-directory>"

# An explicitly located package directory, including an unpacked SDK package
node "<skill-dir>\scripts\mxc-setup.cjs" --sdk-root "<approved-mxc-sdk-package-directory>"

# Opt-in override: a complete native bundle or an already-built checkout
node "<skill-dir>\scripts\mxc-setup.cjs" --executable "<approved-native-directory>\wxc-exec.exe"
```

The setup helper reads package metadata and selects
`bin\<host-architecture>\wxc-exec.exe` for SDK inputs. It uses the Windows host's
architecture (`arm64` or `x64`), not an emulated Node process's architecture.
It never imports SDK JavaScript, invokes npm, changes the host, builds a checkout,
or runs a workload. It invokes only the selected runtime's `--help` and `--probe`,
with bounded time/output, and reports diagnostics as JSON on stdout.

The native layout is a packaging assumption, not a promise about every future
SDK. If a release uses a different layout, inspect that exact package's
documentation and supply an explicit executor path. Preserve its companion files.
The helper does not follow path aliases, choose another architecture, or use
`MXC_BIN_DIR` implicitly. If that variable identifies the intended bundle, confirm
its full executor path and pass `--executable`. No runtime is inferred from the
skill's installation location.

| Setup status | Meaning / next step |
|---|---|
| `ready` | Help/probe checks passed for the selected runtime. Use its returned `mxcExecutable` in the request; this is not execution approval or proof of workload success. |
| `sdk_missing` | Package metadata is absent at the exact selected SDK location. Ask for a corrected location or an approved installation. |
| `runtime_missing` | The selected executor is absent. Report the exact path; do not fall back to another copy. |
| `incompatible_runtime` | Help/probe checks failed. Inspect `reason`, `diagnostics`, and any `hostProbe`; an older probe format is not proof the host lacks capture. |
| `blocked` | Invalid input, reference integrity, access, alias, unsupported host, or other setup failure. Report the reason and honor access/policy limits. |

Non-ready setup results also use a nonzero process exit code. Diagnostics include
exit/error details and stdout/stderr tails with explicit truncation flags.
Keep returned source/version and digest metadata with the setup result. Report
missing/incompatible tools explicitly; a replacement requires an explicit path
or separately approved SDK installation, never a silent substitution.

Keep the runtime and skill bundle outside workload write scopes. A project-local
SDK is unsuitable if that project is writable by the workload; use a separate
approved tools location. Reuse an existing compatible bundle where possible.
Source builds are opt-in, separately scoped work, not the normal setup path.

### Optional approved SDK installation

Obtain approval for the package, exact release, trusted source, and new tools
directory outside workload write scopes. Check release requirements and
npm's effective registry; do not change global settings, silently substitute a
version/source, install globally, or modify workload dependency files.

Installation runs dependency setup scripts and writes package metadata. Use only
approved values:

```powershell
npm install --prefix "<approved-new-tools-directory>" --save-exact "@microsoft/mxc-sdk@<approved-version>"
if ($LASTEXITCODE -ne 0) { throw 'MXC SDK installation failed; do not continue.' }
```

Then run setup with `--sdk-prefix` for that directory. Report the installed version
and retain the generated lockfile. Do not update it during an active loop. Installation
consent does not cover workload execution, elevation, or machine-policy changes.
Missing Node/npm, downloads, source builds, or platform support require separately
agreed setup. Never disable TLS/trust controls to make installation work.

### Compatibility and initialization

Before preparing verification wrappers or requesting workload execution, require
setup to return `ready`. It checks `--help` for `--config`, `--dry-run`, and
`--probe`, then invokes **that executor's `--probe`** without a workload. It requires exit `0`,
JSON with a string `tier`, `needsDaclAugmentation: false`, and at least one of
`probes.nativeCaptureAvailable` or `probes.guardedCaptureAvailable` exactly `true`.
Help text mentioning capture or `--audit` is not evidence that these requirements pass.

Missing/nonboolean capture fields mean the selected runtime cannot establish
compatibility with this helper; explicit false values do not confirm available
capture through that runtime. Do not infer host incapability from an older probe
format, treat missing fields as true, or execute the workload to test support.
Package version alone is not compatibility evidence. An SDK can support general
container use yet lack this loop's required capture contract.

The initial probe is not request-specific. Capture can select a different isolation
tier, and guarded capture can require elevation. Native baseline validation and
any separate administrator approval still apply; never infer permission to elevate
from a successful probe. See the [Learning Mode prerequisites](https://learn.microsoft.com/windows/apps/develop/mxc/learning-mode#plan-for-capture-prerequisites).

Initialization records executable/reference digests, probes the host, and
dry-runs the baseline without launching the workload. Every execution rechecks
integrity, refreshes the probe, and native-validates its bounded request. The
bundled schema is an authoring reference, not a substitute for native validation.
These checks do not prove workload success. On loop-initialization failure, the
controller retains the reported JSON in `hostProbe` and
`.internal\setup-probe.stdout.txt`; inspect that evidence rather than repeating
the same probe. A verified replacement
requires a new results directory, preserving the approved workload/scopes and
remaining execution budget. Never modify a failed session or change its pinned
runtime. The standalone setup helper writes no session files; its JSON result
contains its diagnostics.

## Maintenance

### Updating references

`scripts\reference.cjs` requires the schema, policy guide, and configuration notes.
It checks each file against `references\manifest.json` and binds the manifest
digest to the session. This enables offline, portable authoring; the recorded
source revision is provenance, not a requirement to install that exact build.

Keep upstream schema/guide snapshots byte-for-byte unchanged. Their relative
links can point outside this bundle; use the local guide/schema rather than
guessing missing files. Put loop-specific additions only in configuration notes.
After editing those notes, refresh their SHA-256 entry in the manifest and run
the reference integrity check below. Start a new results directory: existing
sessions pin the old digest and must not be edited to resume against new references.

The bundled `.gitattributes` preserves reference bytes instead of allowing Git
to convert line endings and invalidate their hashes. Check reference integrity
without installing an SDK or executing a workload:

```powershell
node -e 'require(process.argv[1]).loadReference()' '<skill-dir>\scripts\reference.cjs'
```

### Saved artifacts

New sessions keep the main deliverables at the results-directory root:

| Artifact | Purpose |
|---|---|
| `baseline.json` | Immutable prepared starting configuration, including enforced capture and the agreed command |
| `final-config.json` | Byte-for-byte copy of the last completed run's policy, published only when the loop stops. Absent if no run completed; existence does not imply success |
| `history.jsonl` | Ordered events: proposal explanations, complete reviewed diffs, exact-candidate approvals, rejection, execution identity, exit/functional outcomes, and evidence paths |
| `summary.json` | Latest execution and functional outcomes, per-check evidence/errors, budgets, pending candidates, and the published final policy's own run/outcomes; no duplicate full run history |

`result.artifacts` gives the main paths plus the editable working configuration.
While a loop is active, `finalConfig` is null. A failed or stopped loop can publish
an earlier tested policy, never a later untested candidate. The policy excludes
run-specific timeout/capture overrides; `lastTestedConfig` links the exact executed
request under `.internal\run-N\`.

`.internal\` holds controller state, the original request, the editable
`working-config.json`, immutable `config-N.json` snapshots, native validation
output, and `run-N\` logs/denial evidence. It also holds one rolling
`submission.json`, `proposal.json`, and `approval.json`, rather than one of each
per proposal. Their historical explanations, reviewed diffs, and actual decisions
are recorded in `history.jsonl`. Approval binds both the proposal ID and candidate
digest; reusing the internal filename cannot reuse an old decision.
Rejected submissions' requested explanations are not validated diffs; only
`proposal_reviewed` events contain helper-reviewed changes. A `run_started`
without `run_finished` does not prove completion and must not be replayed.

The helper updates the history and summary from saved controller state; `status`
only reads and does not add events. Keep internal evidence throughout the loop:
it is still required for integrity checks, diagnostics, and exact execution
provenance. Do not have the agent rewrite history or delete internal artifacts.
The [working-copy procedure](processcontainer-loop.md#editable-working-configuration) still uses
the native edit preview; that draft is never executed directly.

Session format is 5; older results can be read with `status`, not resumed or
migrated. Existing results directories are not modified by this layout change.
Missing checks preserve exit-code-only success with
`functionalCorrectness: not_assessed`. A reported failed check ends the loop as `verification_failed`;
expected-exit runs with missing/invalid records end as `verification_incomplete`.
Verification I/O failures end as `verification_error`. These terminal outcomes do
not authorize another proposal or retry. A `verified` functional outcome means
only that the agreed checks reported passing results; the execution criterion
must also be met for overall `succeeded`.
The helper does not delete results, workloads, or MXC-managed traces. If a runtime
reports retained ETL, `sourceEtlPath` records its location without copying/reading
it. Keep artifacts private and clean up only explicitly scoped, inspected paths.
