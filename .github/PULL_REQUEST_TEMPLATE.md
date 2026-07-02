## 📖 Description
<!-- Describe what this PR changes, why, and any limitations. -->

## 🔗 References
<!-- Link related issues, PRs, or docs. Use "Resolves #1234" to auto-close. -->

## 🔍 Validation
<!-- How did you test? List manual steps or note automated test coverage. -->

## ✅ Checklist
<!-- Place an "x" between the brackets to check an item. e.g: [x] -->

- [ ] Signed the [Contributor License Agreement](https://cla.opensource.microsoft.com)
- [ ] Linked to an issue
- [ ] Updated documentation (if applicable)
- [ ] Updated [Copilot instructions](.github/copilot-instructions.md) (if build, architecture, or conventions changed)
- [ ] If this PR changes `Cargo.lock`, the `dependency-feed-check` check passes (see [docs/pull-requests.md](https://github.com/microsoft/mxc/blob/main/docs/pull-requests.md))

## 📋 Issue Type
<!-- Select the type that best describes this PR -->
- [ ] Bug fix
- [ ] Feature
- [ ] Task

---

GitHub Actions runs the PR validation build automatically. The ADO pipeline
(`MXC-PR-Build`) is the Azure version of the PR pipeline, kept in parity with the GitHub
Actions build; it runs on merge to `main`, and Microsoft reviewers with write access can trigger it
on a PR with `/azp run`. See [docs/pull-requests.md](https://github.com/microsoft/mxc/blob/main/docs/pull-requests.md).

If the `dependency-feed-check` check fails on a new dependency, the crate must be added to
the feed before the PR can pass. See [docs/pull-requests.md](https://github.com/microsoft/mxc/blob/main/docs/pull-requests.md)
for the steps.