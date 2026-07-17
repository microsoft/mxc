# MXC Contributor's Guide

Below is our guidance for how to report issues, propose new features, and submit contributions via Pull Requests (PRs).

## Open Development Workflow

The MXC team carries out development in the open. When the team finds issues we file them in this repository. When we propose new ideas or think up new features, we file new feature requests. When we work on fixes or features, we create branches and work on those improvements. And when PRs are reviewed, we review them in public.

The point of doing all this work in public is to ensure that we are holding ourselves to a high degree of transparency, and so that the community sees that we apply the same processes and hold ourselves to the same quality bar as we do to community-submitted issues and PRs.

### Issue Triage

The team triages new issues regularly. During triage, the team uses labels to categorize, manage, and drive the project workflow. Issues are categorized into one of four types — **Bug**, **Feature**, **Documentation**, or **Task** — and all new issues receive the `Needs-Triage` label until a team member has reviewed them.

If you file issues or create PRs, please keep an eye on your GitHub notifications. Issues and PRs that remain unanswered for several days after a request for information may be closed.

### Maintainer issue investigation

Repository administrators, maintainers, and writers can comment `/investigate`
on an issue to request an evidence-backed classification. The workflow posts one
public comment identifying the issue as a bug, documentation gap, or design
decision, with a recommended next step.

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

## Before you start, file an issue

Please follow this simple rule to help us eliminate any unnecessary wasted effort and ensure an efficient use of everyone's time:

> 👉 If you have a question, think you've discovered an issue, would like to propose a new feature, etc., then find or file an issue **BEFORE** starting work to fix or implement it.

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

### Do not post "+1" comments

> ⚠️ Do not post "+1", "me too", or similar comments — they add noise to an issue.

If you're affected by an issue but don't have new information to add, upvote the original issue by hitting its 👍 reaction. That way we can measure impact.

---

## Contributing fixes and features

For those willing to help fix issues or implement features:

### To spec or not to spec

Some issues are quick and simple to describe. Once a team member has agreed with your approach, skip ahead to "Fork, Clone, Branch, and Create your PR" below.

Some changes require careful thought and a written design before implementation. For these, we'll request a short design document — typically a markdown file under `docs/` or a detailed comment on the issue describing the proposed configuration schema changes, runner behavior, or SDK API surface. Driving towards agreement in writing, before any code is written, often results in simpler code and less wasted effort.

### Experimental features

New, in-development features in MXC live behind an `experimental` JSON section in configuration and are only active when the binary is invoked with `--experimental`. If you're adding a new feature, follow the step-by-step checklist in [`docs/authoring-a-new-feature.md`](./docs/authoring-a-new-feature.md), which walks through the schema, Rust, and test-config changes required. The schema versioning model and promotion path from experimental to stable are described in [`docs/versioning.md`](./docs/versioning.md).

### Help Wanted

Issues that are ready for development but have no owner are labeled `Help-Wanted`. If you're looking for a place to start, those are a good entry point.

---

## Development

### Contributor License Agreement

This project requires contributors to sign the [Microsoft Contributor License Agreement (CLA)](https://opensource.microsoft.com/cla/). You will be prompted by the CLA bot the first time you open a PR; once you have signed it, you do not need to do so again.

### Fork, Clone, Branch, and Create your PR

Once you've discussed your proposed change with a team member and agreed on an approach:

1. Fork the repository if you haven't already.
2. Clone your fork locally.
3. Create a feature branch.
4. Open a [Draft Pull Request](https://github.blog/2019-02-14-introducing-draft-pull-requests/) early.
5. Work on your changes and push them to the branch.
6. Build and validate locally (see below) before marking the PR ready for review.

### Project layout

```
src/                Rust workspace (wxc-exec, lxc-exec, mxc-exec-mac, wxc_common, etc.)
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

```bash
# Rust unit tests (from src/)
cargo test --workspace
cargo test -p wxc_common                    # Single crate
cargo test -p wxc_common -- config_parser   # Filter by test name

# SDK unit and integration tests (from sdk/node/)
npm test
npm run test:integration

# Rust end-to-end tests against the built binaries (from src/)
cargo test -p wxc_e2e_tests                 # Invokes MXC binaries directly
cargo test -p wxc_e2e_tests -- --ignored    # Include stress tests
```

PowerShell and shell helper scripts that drive the executor end-to-end live under `tests/scripts/` and require a local build. See the [README](./README.md) and the [SDK README](./sdk/node/README.md) for more.

### Code review

When the change is ready, mark the Draft PR as **Ready for Review**. The PR template asks you to confirm CLA acceptance and to update [`.github/copilot-instructions.md`](./.github/copilot-instructions.md) if your change affects build commands, project architecture, or key conventions.

PR builds don't run automatically — Microsoft ADO policy requires a Microsoft employee to comment `/azp run` to start the `MXC-PR-Build` pipeline. See [`docs/pull-requests.md`](./docs/pull-requests.md) for details.

Reviewers will look for:

* Correctness and security — MXC is a sandboxing system, so containment policy changes get extra scrutiny.
* Tests covering the new or changed behavior.
* Documentation updates when behavior covered by existing docs changes (e.g., `docs/schema.md` for schema changes, the relevant backend doc in `docs/` for runner changes, `sdk/node/README.md` for SDK API changes).
* Code style consistent with the rest of the repo.

It may take several review cycles. The result should be solid, testable, conformant code that is safe to merge.

### Merge

Once your PR has been reviewed and approved, a maintainer will merge it into `main`. Your PR will be automatically closed when the merge completes.

---

## Thank you

Thank you in advance for your contribution!
