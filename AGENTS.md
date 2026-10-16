# MXC agent instructions

Read and follow [.github/copilot-instructions.md](.github/copilot-instructions.md)
before writing or reviewing code. It contains MXC's architecture, compatibility,
security, build, and SDK rules. The expectations below apply in addition.

## Design for the codebase, not just the feature

- Understand the existing flow before editing: callers, shared helpers,
  backend ownership, errors, cleanup, and affected SDK entry points. A working
  happy path is not enough; check how the change composes with existing behavior.

- Put behavior where it belongs. Parsers decode contracts and preserve field
  presence; backend-specific defaults, policy checks, and enforcement belong
  in the backend, not shared parsing code.

- Reuse the normal implementation path. Do not add a parallel helper, a
  feature-specific variant, or a narrow exception just to make a feature work.
  If the design cannot express the feature cleanly, refactor the responsible
  component while preserving existing callers and behavior.

- Choose the simplest design that fits the current requirements. Add an
  abstraction only when it solves a real problem; do not build for imagined
  reuse. Name functions for their responsibility, not a growing list of cases.

- Consider whether a maintainer can understand and safely extend the result.
  Completing the requested feature does not excuse duplication, misplaced
  responsibilities, weakened checks, or hidden failure paths.

- If adding a feature requires replacing or deleting a large part of a
  subsystem, split the work into reviewable vertical slices: a small part of
  the feature working through the relevant layers, with its tests. Separate
  prerequisite refactoring from behavior changes; keep each step buildable
  and preserve existing behavior. Do not attempt the whole rewrite at once.

## Write for everyday developers

Use plain, precise language in code reviews, comments, documentation, and
handoffs. Explain the concrete behavior and consequence; avoid invented jargon
and research-paper language. Be concise without leaving out the detail needed
to understand or act. Neither verbosity nor oversimplification is helpful.

Keep comments sparse and short: explain a non-obvious reason or constraint,
not what the next line does. Prefer clear names and straightforward code.

Documentation should describe the finished design, behavior, and usage, not
an agent's thought process, implementation diary, or discarded approaches.
Update the relevant canonical document rather than adding overlapping Markdown.
Document only what the reader needs: supported behavior, usage, prerequisites,
limitations, and useful error remedies. Include implementation detail only when
it explains a necessary maintenance or design decision, in developer docs.

Separate paragraph-length Markdown list items with a blank line; keep short
lists compact.

## Require meaningful behavior coverage

- For a feature, add or extend a functional validation test in the applicable
  CI suite. Backend behavior must run in scheduled/nightly validation on
  the relevant hosts; adding a test file without wiring it into CI is not enough.

- For a bug fix, add a regression scenario that exercises the reported failure
  through the relevant public API or backend flow and checks the correct result.
  Where practical, show that it fails before the fix and passes afterward.

- Prefer tests of useful behavior, feature interactions, and failure handling
  over many tiny checks of implementation details. Extend existing scenarios
  rather than duplicating them.

- Unit tests, including tests at the bottom of `.rs` files, are useful for
  isolated logic but do not replace functional validation. Do not judge
  coverage by test count or tests that merely repeat the new implementation.

- Follow the [validation runbook](docs/development/build-and-test/ci-validation-infrastructure.md)
  and backend guide. Check that the intended scenario actually runs and asserts
  behavior on a suitable host. State what was not run or cannot be covered;
  do not invent evidence. Documentation-only changes do not need runtime tests.

For reviews, use the [MXC review skill](.github/skills/mxc-code-review/SKILL.md).
Focus on high- and medium-severity defects and consolidate findings into one
review, rather than creating extra review rounds for nits or optional cleanup.
