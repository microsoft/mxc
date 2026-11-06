## 📖 Description
<!--
Describe what this PR changes, why, and any limitations.

Thanks for contributing! Link the issue so reviewers can follow the discussion.
For features and changes requiring a spec, maintainers record the agreed scope
with `feature-accepted`. Schema/policy changes, new or changed public APIs,
new backends, large refactors, and new crates need an approved and merged spec
before implementation, including draft implementation PRs. Include API proposals
in the spec PR so we can review the design together.
See [contributor guidance](https://github.com/microsoft/mxc/blob/main/CONTRIBUTING.md#plan-features-together).
If you are unsure which steps apply, ask in the issue; maintainers will help.
-->

## 🔗 References
<!--
Link related issues, PRs, or docs.

For spec and intermediate implementation PRs, use `Refs #<issue-number>`.
Keep the feature issue open for coordination until implementation, functional
validation, and documentation are complete. Reserve closing keywords in PR
descriptions and commit messages, and closing links, for the final implementation
PR.
-->

## 🔍 Validation
<!-- How did you test? List manual steps or note automated test coverage. -->

## ✅ Checklist
<!-- Place an "x" between the brackets to check an item. e.g: [x] -->

- [ ] Signed the [Contributor License Agreement](https://cla.opensource.microsoft.com)
- [ ] Linked to an issue
- [ ] For features or changes requiring a spec: linked the issue with maintainer-applied `feature-accepted`
- [ ] For implementation: linked the required approved and merged design/API spec, or explained why no spec is required
- [ ] Feature issue remains open unless this PR completes all agreed implementation, validation, and documentation
- [ ] Updated documentation (if applicable)
- [ ] Updated [Copilot instructions](copilot-instructions.md) (if build, architecture, or conventions changed)
- [ ] If this PR changes `Cargo.lock`, the `dependency-feed-check` check passes (see [pull request builds](https://github.com/microsoft/mxc/blob/main/docs/development/build-and-test/pull-requests.md))

## 📋 Issue Type
<!-- Select the type that best describes this PR -->
- [ ] Bug fix
- [ ] Feature
- [ ] Task

<!--
GitHub Actions runs the PR validation build automatically. The ADO pipeline
(`MXC-PR-Build`) is the Azure version of the PR pipeline, kept in parity with the GitHub
Actions build; it runs on merge to `main`, and Microsoft reviewers with write access can trigger it
on a PR with `/azp run`. See [pull request builds](https://github.com/microsoft/mxc/blob/main/docs/development/build-and-test/pull-requests.md).

If the `dependency-feed-check` check fails on a new dependency, the crate must be added to
the feed before the PR can pass. See [pull request builds](https://github.com/microsoft/mxc/blob/main/docs/development/build-and-test/pull-requests.md)
for the steps.
-->