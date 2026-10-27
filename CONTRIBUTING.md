# MXC Contributor's Guide

> **Audience:** MXC developers

Below is our guidance for how to report issues, propose new features, and submit contributions via Pull Requests (PRs).

Ideas, questions, bug reports, and code contributions are all welcome. You
do not need a finished design to join the discussion. Sharing your use case
helps us understand what matters to you and find a useful path forward together.

**Proposing a feature?** Start with
[planning it together](#plan-features-together).

**Maintaining the project?** See [MAINTAINERS.md](MAINTAINERS.md) for feature
discussion, review, and follow-through responsibilities.

## Open Development Workflow

The MXC team carries out development in the open. When the team finds issues we file them in this repository. When we propose new ideas or think up new features, we file new feature requests. When we work on fixes or features, we create branches and work on those improvements. And when PRs are reviewed, we review them in public.

The point of doing all this work in public is to ensure that we are holding ourselves to a high degree of transparency, and so that the community sees that we apply the same processes and hold ourselves to the same quality bar as we do to community-submitted issues and PRs.

### Issue Triage

The team triages new issues daily through a shared developer and PM rotation.
During triage, the team uses labels to categorize, manage, and drive the project
workflow. Issues are categorized into one of four types — **Bug**, **Feature**,
**Documentation**, or **Task** — and all new issues receive the `Needs-Triage`
label until an area label is applied and a response records the next step.
Remove `Needs-Triage` then, including when the response asks for more information;
use `Needs-Author-Feedback` while awaiting the author's reply.
Assignment is separate: work is assigned when its scope is clear and someone
is ready to take it.

See [How MXC is managed](./docs/repository-management.md) for area ownership,
release milestones, community prioritization, and SDK versioning.

Maintainers record feature decisions and requests for more information in
the GitHub issue.

Please keep an eye on GitHub notifications so we can work through questions
together. If you need more time, let us know. When a discussion becomes inactive,
maintainers may close it with an explanation; you are welcome to return with
more information.

### Maintainer issue investigation

Repository administrators, maintainers, and writers can comment `/investigate`
on an issue to request an evidence-backed classification. The workflow posts one
public comment identifying the issue as a bug, documentation gap, or design
decision, with a recommended next step.

When the report lacks enough information to reach a classification, it explicitly
mentions the issue author and requests reproduction steps, expected and actual
behavior, MXC version, OS/build, and sanitized logs. It does not create a PR for
that outcome.

For a small, unambiguous documentation or test-only change, it may also create
one draft PR. It never merges, releases, assigns owners, changes labels, or
updates an existing PR. It does not create PRs for production code, schemas,
generated SDK files, containment behavior, CI, dependencies, versioning, or
security-sensitive work.

Do not use `/investigate` for a security report. Follow
[SECURITY.md](./SECURITY.md) instead.

---

## Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.** Instead, please report them to the Microsoft Security Response Center (MSRC). See [SECURITY.md](./SECURITY.md) for full details.

> ⚠️ When reporting BSODs or security issues, **do not** attach memory dumps, logs, or traces to GitHub issues. Send them to `secure@microsoft.com` referencing the GitHub issue. For application crashes, include a Feedback Hub link if possible.

---

## Start a conversation

An issue is a place to ask questions, share a problem, or explore an idea with
the team. Before investing in an implementation, find or open an issue so we
can connect related work, discuss the approach, and help you focus your effort.

### Search existing issues first

Before filing a new issue, search existing open and closed issues. It is likely that someone else has found the problem you're seeing, and someone may be working on or have already contributed a fix.

If no existing item describes your issue or feature, please file a new one.

### File a new issue

We provide four issue templates under [`.github/ISSUE_TEMPLATE/`](./.github/ISSUE_TEMPLATE/). Pick the one that matches your situation:

| Category | When to use | Template |
|----------|-------------|----------|
| 🐛 Bug Report | Something is broken or behaving unexpectedly | `Bug_Report.yml` |
| 🚀 Feature Request / Idea | A proposal for new functionality or an improvement | `Feature_Request.yml` |
| 📚 Documentation Issue | Docs are incorrect, incomplete, or confusing | `Documentation_Issue.yml` |
| 📋 Task | An actionable work item that doesn't fit the above | `Task.yml` |

**Complete the information requested in the template**. The more information you provide, the more likely your issue will be understood and addressed. Helpful information includes:

* The platform you're on (Windows / Linux / macOS) and architecture (x64 / ARM64).
* Which containment backend is involved.
* The MXC version or commit you're using.
* **Detailed reproduction steps** — what exact JSON config, command, or SDK call triggers the issue.
* Prefer pasted text (command output, error messages, JSON snippets) over screenshots.
* **If you intend to implement the fix or feature yourself, say so in the issue!** Otherwise we may pick it up or label it `Help-Wanted`.

### Show support for an issue

If you're affected by an issue, use the original issue's 👍 reaction to help us
understand its impact. Comments with additional use cases or reproduction
details are welcome; reactions work well when you have no new information to add.

---

## Contributing fixes and features

Thank you for considering a contribution. Early discussion helps contributors
and maintainers build a shared understanding before committing to larger work.

### Plan features together

Follow the [feature authoring guide](./docs/development/guides/authoring-a-new-feature.md):

1. Share the problem and desired outcome in an issue. If you would like to
   contribute, say so. Work with maintainers on scope; they record the shared
   plan with `feature-accepted`.
2. For changes needing a design/API spec, develop and review it together in a
   documentation PR. Approval and merge come before implementation, including
   draft implementation PRs, so contributors can build on an agreed design.
3. Implement the agreed design with functional tests and documentation. Use
   the issue to coordinate progress until the agreed work is complete.

Maintainers will help clarify the next step, explain tradeoffs and decisions,
and work through review feedback with you. Not every proposal can be included,
but each deserves a thoughtful response.

The guide defines [when a spec is required](./docs/development/guides/authoring-a-new-feature.md#when-a-spec-is-required),
templates and file layout, approval labels, and the schema, backend, and SDK
implementation stages. It applies to human and agent-authored contributions.

### Documentation audiences

Human-facing Markdown documentation includes one visible audience marker immediately below its title:

- `> **Audience:** MXC consumers` for people configuring, embedding, or operating MXC.
- `> **Audience:** MXC developers` for repository design, architecture, build, test, and maintenance material.
- `> **Audience:** MXC consumers and developers` when a document genuinely serves both groups.

Do not add these markers to legal text, GitHub templates or workflow prompts, or agent instruction files.

Place developer-only documentation under the appropriate `docs/development/`
subdirectory. Keep consumer and mixed-audience documentation in the main
`docs/` tree, and keep implementation-specific READMEs beside the code or tests
they describe.

### Experimental features

Follow the [feature guide](./docs/development/guides/authoring-a-new-feature.md)
for implementation order and the
[versioning design](./docs/development/architecture/versioning.md) for development
contracts, publication, and experimental authorization.

### Help Wanted

Issues that are ready for development but have no owner are labeled `Help-Wanted`. If you're looking for a place to start, those are a good entry point.

---

## Development

### Contributor License Agreement

This project requires contributors to sign the [Microsoft Contributor License Agreement (CLA)](https://opensource.microsoft.com/cla/). You will be prompted by the CLA bot the first time you open a PR; once you have signed it, you do not need to do so again.

### Fork, Clone, Branch, and Create your PR

Start with the approach discussed in your issue. For features, the
[feature guide](./docs/development/guides/authoring-a-new-feature.md) explains
how to agree on scope and complete any design review before implementation.

1. Fork the repository if you haven't already.
2. Clone your fork locally.
3. Create a feature branch.
4. Open a [Draft Pull Request](https://github.blog/2019-02-14-introducing-draft-pull-requests/) early.
5. Work on your changes and push them to the branch.
6. Build and validate locally (see below) before marking the PR ready for review.

### Project layout

```
src/                Rust workspace (wxc-exec, lxc-exec, mxc-exec-mac, mxc_common, etc.)
sdk/                TypeScript SDK (@microsoft/mxc-sdk)
docs/               Schema and configuration documentation
tests/              Test collateral (examples, configs, scripts)
schemas/            JSON schemas (stable + dev)
.azure-pipelines/   1ES Pipeline Templates configuration
```

### Building MXC

MXC has a Rust core (under `src/`) and a TypeScript SDK (under `sdk/node/`). The full project layout and commands are documented in the [README](./README.md). The short version:

**Windows** — `build.bat`:

```cmd
build.bat                  :: Release build for current architecture
build.bat --debug          :: Debug build
build.bat --all            :: Release build for both x64 and ARM64
build.bat --with-microvm   :: Include NanVix micro-VM binaries
```

**Linux** — `./build.sh`:

```bash
./build.sh                    # Release build
./build.sh --debug            # Debug build
./build.sh --rust-only        # Only Rust binaries, skip SDK
./build.sh --with-hyperlight  # Build with the Hyperlight micro-VM backend (x86_64 only)
```

**macOS** — `./build-mac.sh` (requires Xcode Command Line Tools):

```bash
./build-mac.sh             # Release build for native architecture (seatbelt backend)
./build-mac.sh --debug     # Debug build
./build-mac.sh --all       # Build for both aarch64 and x86_64
./build-mac.sh --rust-only # Only Rust binaries, skip SDK
```

The macOS build produces an unsigned `mxc-exec-mac` binary; codesigning and notarization happen at release time.

**Individual components**:

```bash
# Rust workspace (from src/)
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target aarch64-pc-windows-msvc
cargo build --release -p lxc                                       # Linux only — builds lxc-exec
cargo build --release -p mxc_darwin --target aarch64-apple-darwin  # macOS only — builds mxc-exec-mac

# SDK (from sdk/node/)
npm install && npm run build
```

### Updating npm dependencies

Dependency upgrades produced by commands such as `npm install`, `npm update`,
and `npm audit fix` may change one of these lockfiles:

- `sdk/node/package-lock.json`
- `sdk/node/tests/integration/package-lock.json`
- `scripts/versioning/package-lock.json`

Microsoft developers resolve npm packages through an internal 1ES feed. That
feed can write internal `ms-feed-*` tarball URLs and SHA-1 integrity values into
a lockfile. Because this is a public repository, committed lockfiles must
instead use `https://registry.npmjs.org` URLs that external contributors can
access and SHA-512 integrity values.

After an npm command changes a lockfile through the internal feed, normalize it
from the repository root using PowerShell 7.3 or later:

```powershell
pwsh -File .\scripts\normalize-npm-package-lock.ps1 `
    .\sdk\node\package-lock.json
```

Run the script once for each changed lockfile. It downloads affected tarballs
through the internal feed, verifies their existing integrity value, computes
SHA-512, and restores the public npm registry URL. It makes no changes when a
lockfile already contains public URLs. CI checks every tracked
`package-lock.json`. Resolved dependencies must either be repository-relative
`file:`/path references or HTTPS artifacts from `registry.npmjs.org`; npmjs
artifacts must have a valid SHA-512 integrity value. Installed package records
must declare their source; workspace source and bundled-package records are
handled explicitly.

### Linting and formatting

Before submitting a PR, run the linters and formatters that already exist in the repo:

```bash
# Rust (from src/)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

The Rust style guidelines used in this repo are documented in [`.github/instructions/rust.instructions.md`](./.github/instructions/rust.instructions.md).

### Testing

Testing is a key component in the development workflow. We expect contributors to add or update tests alongside their changes.

Features need functional coverage in the applicable CI suite, and bug fixes
need a regression scenario for the reported failure. Backend behavior belongs
in the scheduled/nightly validation suites on suitable hosts; see the
[validation runbook](docs/development/build-and-test/ci-validation-infrastructure.md).
Unit tests support isolated logic but do not replace this behavior coverage.
Documentation-only edits do not need runtime tests.

```bash
# Rust unit tests (from src/)
cargo test --workspace
cargo test -p mxc-sdk --lib                         # Consolidated library unit tests
cargo test -p mxc-sdk --lib -- config_parser        # Filter by test name

# SDK unit and integration tests (from sdk/node/)
npm test
npm run test:integration

# Rust end-to-end tests against the built binaries (from src/)
cargo test -p mxc-sdk --test 'wxc_e2e_tests_*'              # Invokes MXC binaries directly
cargo test -p mxc-sdk --test 'wxc_e2e_tests_*' -- --ignored # Include stress tests
```

PowerShell and shell helper scripts that drive the executor end-to-end live under `tests/scripts/` and require a local build. See the [README](./README.md) and the [SDK README](./sdk/node/README.md) for more.

### Code review

When the change is ready, mark the Draft PR as **Ready for Review**. The PR
template asks you to confirm CLA acceptance and update agent guidance if build
commands, architecture, or key conventions change. Technical repository rules
live in [`.github/copilot-instructions.md`](./.github/copilot-instructions.md).
[`AGENTS.md`](./AGENTS.md) references those rules and adds design, communication,
and validation expectations; `CLAUDE.md` points to that guidance.
Repository-specific review checks live in the
[MXC code-review skill](./.github/skills/mxc-code-review/SKILL.md).

PR builds don't run automatically — Microsoft ADO policy requires a Microsoft employee to comment `/azp run` to start the `MXC-PR-Build` pipeline. See [pull request builds](./docs/development/build-and-test/pull-requests.md) for details.

Reviewers will look for:

* Correctness and security — MXC is a sandboxing system, so containment policy changes get extra scrutiny.
* Tests covering the new or changed behavior.
* Documentation updates when behavior covered by existing docs changes (e.g., `docs/schema.md` for schema changes, the relevant backend doc in `docs/` for runner changes, `sdk/node/README.md` for SDK API changes).
* Code style consistent with the rest of the repo.

It may take several review cycles. The result should be solid, testable, conformant code that is safe to merge.

### Preserve PR review history

Once a PR is open, including a draft, its commit history helps reviewers track
what changed between reviews. This applies to feature design specs, API
proposals, and implementation PRs.

- Push focused follow-up commits for review feedback.
- Rebasing, squashing, amending published commits, and force-pushing are highly
  discouraged unless a maintainer explicitly requests them.
- If conflicts with `main` arise, merge `main` into the PR branch and resolve
  them in the merge commit instead of rebasing.

Clean up commit history before opening the PR, not during review.

### Merge

Once your PR has been reviewed and approved, a maintainer will merge it into `main`. Your PR will be automatically closed when the merge completes.

---

## Thank you

Thank you in advance for your contribution!
