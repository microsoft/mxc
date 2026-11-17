# Functional verification

Read this when preparing or interpreting functional checks. The loop/approval
procedure remains in [processcontainer-loop.md](..\processcontainer-loop.md). Exit-code-only sessions may use
`functionalChecks: []`, but must report functional outcome as **not assessed**.
The caller supplies desired outcomes in plain language; the agent determines how
to observe them. Do not require JSON, a test suite, or an explanation of the
workload's output format from the caller.
The session form always offers one optional free-text field, defaulting to an
empty string. If no checks were requested, an accepted blank/whitespace-only
field means `functionalChecks: []` and expected exit `0` (or an explicitly
requested different exit code). Proceed with the unchanged command; do not ask
again, invent checks, or start a verification investigation.

If the caller already requested checks, briefly identify them in the field
description and ask for **additional** checks; blank keeps the requested checks.
Do not omit this opportunity just because the task includes an expected outcome.
Workload documentation or test metadata alone does not request additional checks.
Collect the answer before inspecting code for verification or building wrappers.
Cancelling the form is not consent.

## Agree the strengthened workload

Translate only the agreed outcomes into checks inside the **same sandboxed
workload**. Prefer existing assertions, test results, or documented workload
output when they establish those outcomes. Use
[bounded workload inspection](..\processcontainer-loop.md#read-only-what-the-task-needs)
to find relevant documentation, source, or tests when needed; neither a source
checkout nor a preidentified implementation file is required.

Ask a focused, plain-language question only when the desired outcome remains
unclear, reliable evidence cannot be established from available materials, or a
check needs new access or side effects. Explain the missing fact rather than
defaulting to a request for an "output contract." Do not invent evidence, assume
a source checkout matches a separate build, or silently drop a requested check.

The workload need not already emit the helper's records. Add only the minimum
approved integration needed to translate actual evidence into those records.
Before `init`, show the exact proposed command/script changes,
what each check establishes, and any fixture setup, reads, or side effects.
Obtain agreement to those checks and the revised workload under the normal scope
and replay rules. Keep this explanation brief and outside the short baseline
form message. If the command changes after baseline consent, get concise approval
for that change before `init`, not another full questionnaire. This is an
explicitly strengthened workload, not an unchanged rerun of the original.
Do not change the command, checks, or expected exit during the loop to manufacture
success. A changed contract needs a new approved session.

Prepare `functionalChecks` in the request, for example:

```json
"functionalChecks": [
  {
    "id": "documents-file-found",
    "description": "Enumeration of the intended Documents folder finds the exact caller-owned fixture path"
  }
]
```

Each entry has only a unique lowercase `id` (letters, digits, `_`, `-`, starting
with a letter) and a nonempty `description`. After actually performing a check,
the workload emits exactly one UTF-8 stdout line for that ID:

```text
MXC_FUNCTIONAL_CHECK {"id":"documents-file-found","passed":false,"evidence":"Resolved Documents path was empty; enumeration was not performed"}
```

The record has only `id`, boolean `passed`, and nonempty string `evidence`.
All agreed IDs must report once. Missing, malformed, duplicate, or unexpected
records cannot verify success. Ordinary stdout and an exit code are not records.
For a test suite, derive records from actual assertions and confirm the relevant
tests ran; zero tests, skipped tests, or an unawaited operation do not establish
the outcome. Never emit a constant pass marker or infer one from exit `0` alone.

## Interpret results without overstating them

The helper only evaluates these records; it launches no verifier, reads no
additional host targets, and grants no permissions for verification. A reported
pass is evidence for the agreed checks in this trusted-fixture POC, not independent
host verification or a guarantee of general functional correctness. Host-state
claims need appropriate evidence; a sandbox-visible path or marker alone does not
prove host mutation. Fixture setup/cleanup still needs separately agreed scope.

Always distinguish `metExpectedExitCode` from `functionalCorrectness`; the
compact output retains the complete `functionalVerification` checks/evidence and
errors even when stdout is shortened. A false check ends as `verification_failed`.
An expected-exit run with missing/invalid records ends as
`verification_incomplete`; verification I/O errors end as `verification_error`.
These outcomes do not authorize another proposal or retry. Passing records cannot
rescue an MXC/capture error or unexpected exit. Investigate contradictory evidence.

## Shell enumeration examples

For requested Windows Shell Desktop/Documents enumeration checks, optionally adapt
`examples\shell-enumeration-check.ps1` and the check lists in
`examples\shell-functional-checks.json` (paths relative to the skill root).
These are examples, not required steps or checks for other workloads.
Have the caller agree to an actual host folder and a uniquely named existing
caller-owned file in it; any staging is separately approved. Supply that
independently established folder as `-ExpectedFolder`, not a value derived inside
the sandbox. Supply the file's leaf name as `-FixtureName` and choose
`-Folder Desktop` or `-Folder Documents`.

Copy the matching check list into the request and use the script as the agreed
workload. It does not create/delete fixtures or grant access. It returns `0` when
checking completes even if a check reports false; the helper must evaluate the
records. These examples verify enumeration of one real fixture, not completeness
of the entire folder or file-content access.
