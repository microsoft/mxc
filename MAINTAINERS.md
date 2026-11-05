# MXC maintainer guide

> **Audience:** MXC developers

This guide covers feature acceptance and spec approval. Contributor steps and
spec requirements are in the
[feature authoring guide](docs/development/guides/authoring-a-new-feature.md).
For technical review, use the
[MXC review guidance](.github/skills/mxc-code-review/SKILL.md).

## Help contributors shape a feature

- Thank contributors for the problem reports, ideas, designs, and code they
  share. Understand their use case before suggesting a solution.
- Help agree on scope and record who plans to contribute in the tracking issue.
  Explain whether a spec is needed and what the next step involves.
- Apply `feature-accepted` after that agreement. It records a shared direction
  for design work, not a release commitment or a completed design review.
- Explain decisions and tradeoffs, including when a proposal does not fit the
  project. Where useful, discuss a smaller scope or another approach.
- Record scope or contributor changes in the issue. If the agreed direction
  is no longer viable, discuss why and the options with the contributor, remove
  `feature-accepted`, and make clear which work needs to pause.

Maintainers apply approval labels to record their review decisions. Contributors
can ask for a status update or clarification in the issue; they do not need to
guess what is missing.

## Approve the specs

Use the contributor guide's
[spec requirements](docs/development/guides/authoring-a-new-feature.md#when-a-spec-is-required)
to determine which documents are needed.

- Review the feature design and any required API proposal in the same
  documentation-only PR. Both need approval before merge.
- Give actionable feedback: explain the concern, its effect, and what would
  resolve it. Distinguish required changes from suggestions, and acknowledge
  the contributor's reasoning and improvements.
- After approving the design, ask the proposer to change its status from
  **Proposed** to **Accepted**. Verify that update before merging.
- After merge, apply `design-approved` to the tracking issue. Apply `api-approved`
  only when a public API proposal was approved and merged.
- Add an issue comment linking the merged PR, checked-in specs, and remaining
  implementation work.
- If there are no public API changes, include
  `API review: Not applicable - no public API changes.` in that comment.
  Do not apply `api-approved`.

Labels record decisions; they do not replace review and merge. If implementation
arrives before agreement on scope or a required spec merge, acknowledge the
effort and help the contributor return to the design discussion. Explain what
needs to be settled before implementation review and agree on whether to pause
or close the PR.

## Handle design changes

Discuss material design or API changes with the contributor and explain which
parts need another review. Remove the affected approval labels while the spec
is revised, then restore them after approval and merge. Pause implementation
of those changes during review; unrelated work that still follows the agreed
design can continue.

## Complete the feature

Keep the tracking issue open through spec and intermediate implementation PRs.
Close it only when the agreed implementation, functional validation, and
documentation are complete. The final implementation PR may close the issue;
otherwise, close it after confirming that work is finished.

Thank the contributors and recognize the work that made the feature possible.
