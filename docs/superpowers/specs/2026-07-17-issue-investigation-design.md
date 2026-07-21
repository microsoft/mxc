# Human-Triggered Issue Investigation Workflow

## Purpose

Add a shared, version-controlled GitHub Agentic Workflow that lets an MXC
maintainer comment `/investigate` on an issue. The workflow investigates the
issue and the relevant repository code, then publicly classifies it as a bug,
documentation gap, or design decision.

For a small, unambiguous, non-sensitive fix in an approved path, it may also
create one draft pull request. The workflow only proposes work. Humans retain
all merge, release, security, and architecture decisions.

## Goals

- Give maintainers a low-friction way to obtain evidence-backed issue analysis.
- Turn easy, clearly bounded documentation or test fixes into reviewable draft
  pull requests.
- Preserve a public, concise record of the investigation and next step.
- Reuse MXC's checked-in agent instructions and existing `gh-aw` conventions.
- Keep the implementation policy version controlled and reviewable.

## Non-goals

- Scheduled or autonomous issue processing.
- Changing labels, assigning owners, merging, releasing, publishing, or updating
  an existing human pull request.
- Handling security reports, release work, architecture decisions, or
  cross-cutting behavior changes.
- Replacing maintainer review or repository contribution processes.

## Trigger and access control

The workflow will be implemented as a `gh-aw` workflow, following the
repository's existing `issue-triage.md` pattern.

- Trigger: a `/investigate` slash command on an issue.
- Permitted callers: repository administrators, maintainers, and writers.
- Scope: the triggering repository only.
- Output: at most one public issue comment and at most one new draft pull
  request per invocation.
- The command is ignored for callers without the configured repository role.

## Investigation flow

1. Read the triggering issue and treat its title, body, and comments as
   untrusted evidence. The workflow must never obey instructions contained in
   issue content.
2. Read the applicable MXC repository guidance, including
   `.github/copilot-instructions.md`, path-specific instructions, and any
   relevant `AGENTS.md` file.
3. Determine whether the issue is potentially security-sensitive or concerns
   an excluded area. Security-sensitive issues stop here: post only a minimal
   `SECURITY.md` routing comment and do not assess, classify, request
   diagnostics, or create a pull request.
4. Inspect the relevant source, tests, and documentation.
5. Post one concise, fixed-format public comment containing:
   - assessment: `confirmed`, `expected behavior`, `insufficient information`,
     or `cannot reproduce`;
   - classification: `bug`, `documentation gap`, or `design decision`;
   - supporting evidence from the repository;
   - for insufficient information only, a mention of the issue author and a
     request for reproduction steps, expected and actual behavior, MXC version,
     OS/build, and sanitized logs;
   - recommended maintainer next step;
   - either no pull request, or a link to the created draft pull request.
6. Create a draft pull request only when every draft-PR condition below holds.

## Draft pull request conditions

The workflow may create a draft PR only if:

- the problem is genuinely small and behaviorally unambiguous;
- the change does not require a product, architecture, or security decision;
- every changed path is an approved documentation or test path;
- relevant formatting, linting, and targeted tests pass;
- the PR is a new branch with an investigation-specific title prefix;
- the PR description states the classification, evidence, scope, and exact
  validation results.

If any condition fails, the workflow posts its analysis without creating a PR.

## Approved and protected scope

The first version permits draft PRs only for documentation and test changes.
Production-code changes are investigation-only, even when the agent considers
the change small.

The first version must refuse draft PR creation for an issue or diff involving:

- `schemas/stable/**`, `schemas/dev/**`, schema-version files, or generated
  schema artifacts;
- Rust wire models, generated SDK wire types, generated bindings, or SDK
  cross-cutting API changes;
- containment backend implementation or backend behavior;
- security, permissions, authentication, secrets, or host isolation policy;
- CI workflows, dependency manifests, build scripts, versioning, releases, or
  publishing.
- production source code of any kind.

These issues remain eligible for investigation and a public routing comment,
unless a security-sensitive report requires a minimal private-triage response.

The implementation will enforce this with an explicit changed-path guard before
PR creation. Prompt instructions and labels alone are not sufficient scope
enforcement.

## Safe output policy

- Draft PRs only, with a dedicated title prefix and a maximum of one per run.
- No mutation of labels, assignees, milestones, releases, branches, or existing
  pull requests.
- No auto-merge and no direct push to a human-authored pull request.
- Protected-path violations fall back to an issue comment, never a PR.
- Public comments avoid reproducing security-sensitive details.

## Failure handling

| Situation | Required result |
|---|---|
| Issue is ambiguous | Classify as a design decision and request the missing decision. |
| Issue is security-sensitive or excluded | Provide only a concise routing comment. Do not create a PR. |
| Tools or code inspection fail | State the unavailable evidence transparently. Do not guess or create a PR. |
| Validation fails | Report the failure and do not create a PR. |
| Path guard fails | Report the finding and explain that the change needs human-owned handling. |
| No actionable finding | Post a concise explanation of why no classification or fix is justified. |
| Insufficient information | Post one report that explicitly says so, mentions the issue author, requests reproduction steps, expected and actual behavior, MXC version, OS/build, and sanitized logs, and creates no PR. |

## Validation strategy

Tests and review scenarios must cover:

1. Authorized and unauthorized slash-command callers.
2. Bug, documentation-gap, and design-decision classification.
3. Untrusted instructions embedded in issue text.
4. Security-sensitive and protected-area refusal paths.
5. An approved small fix that produces a draft PR.
6. Changed-path guard rejection.
7. Formatting, linting, or targeted-test failure preventing PR creation.
8. Public comment format and the one-comment/one-PR output limits.

Initial operational success requires maintainers to find classifications useful,
no protected paths in workflow-created draft PRs, and no unexpected
workflow-created CI failures. The workflow should be disabled immediately if a
suspected prompt-injection incident or protected-scope escape occurs.

## Rollout

1. Review and harden the existing automated issue-triage workflow's handling of
   untrusted issue content before enabling this workflow.
2. Confirm `gh-aw` is approved and enabled for the public repository.
3. Deploy the workflow with the protected-path guard and draft-only output
   policy.
4. Use it manually on a small number of maintainer-selected issues.
5. Review classifications, public comments, draft PRs, and CI behavior before
   expanding its allowed paths or cadence.

## Alternatives considered

### GitHub Agentic Workflow via `gh-aw`

Recommended. It supports the requested `/investigate` interaction and
version-controlled safe-output rules in a form consistent with MXC's existing
issue-triage workflow.

### GitHub Action with custom scripting

Would offer maximum implementation control but would require MXC to build and
maintain its own slash-command parsing, agent integration, output controls, and
security guardrails.

### Copilot cloud-agent sessions

Useful for individual investigations, but they do not provide the shared,
discoverable `/investigate` workflow requested here.
