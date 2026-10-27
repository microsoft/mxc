# How MXC is managed

> **Audience:** MXC consumers and developers

This guide describes how we run MXC, with shared expectations for maintainers
and community contributors. We track work in GitHub issues, implement changes
through pull requests (PRs), and publish release plans through milestones.

## Daily triage and ownership

Our developers and PMs share a daily triage rotation, coordinated by @mgudgin,
@bbonaby, @denelon, and @nadiauddin03. During triage, we check for duplicates,
ask clarifying questions, assess whether the issue is actionable and fits MXC,
apply labels, and respond with a decision and next step. That may mean further
investigation, keeping it in the backlog, or closing it with an explanation.
Understanding an issue does not mean we have estimated, prioritized, or
scheduled the work.

### Area ownership

We use `Area-*` labels for shared engineering responsibilities and `Backend-*`
and `OS-*` labels when relevant. Each area has a primary contact who coordinates
triage and review. Supporting contacts help with investigation and review.
The primary contact is not automatically the implementation assignee.

| Labels | Responsibility | Primary contact | Supporting contacts |
| --- | --- | --- | --- |
| No specific area | MXC in general and routing to the right area | @bbonaby | @mgudgin, @denelon, @nadiauddin03 |
| `Area-DotNet-SDK`, `Area-Node-SDK`, `Area-Rust-SDK` | SDK APIs and types | @bbonaby | @mgudgin, @jsidewhite |
| `Area-Schema`, `Area-Execution` | Schema, executor binaries, FFI, and core behavior | @mgudgin | @bbonaby, @jsidewhite |
| `Area-Build`, `Area-Test` | General MXC infrastructure and tests | @bbonaby | @theelliotm, @dhoehna |
| `Area-Telemetry` | Telemetry | @RamonArjona4 | @richiemsft |
| `Backend-Bubblewrap` | Bubblewrap | @sohamdas2021 | @dhoehna |
| `Backend-WSLC` | WSLC | @sohamdas2021 | - |
| `Backend-LXC` | LXC | @dhoehna | - |
| `OS-MacOS`, `Backend-Seatbelt` | macOS and Seatbelt | @theelliotm | @richiemsft |
| `Backend-ProcessContainer` | ProcessContainer: general | @jsidewhite | @mgudgin, @bbonaby |
| `Backend-ProcessContainer-UI` | ProcessContainer: UI | @mgudgin | - |
| `Backend-ProcessContainer-Networking` | ProcessContainer: networking | @bbonaby | - |
| `Backend-ProcessContainer-Filesystem` | ProcessContainer: filesystem | @daniedud-MSFT | - |
| `Backend-ProcessContainer-learningmode` | ProcessContainer: learning mode | @richiemsft | - |
| `Backend-IsolationSession` | IsolationSession | @adpa-ms | - |
| `Backend-VM` | VM | @mgudgin | - |
| `Backend-MicroVM` | MicroVM | @huzaifa-d | - |
| `Backend-Hyperlight` | Hyperlight | @danbugs | - |

For area routing, subarea ownership takes precedence over general backend
ownership. When an issue has a subarea label, that subarea's primary contact
coordinates triage and review, even if the general backend label is also
present. The general backend primary is the fallback for work without a subarea.

Apply labels for all areas affected by the issue. Use `Area-Schema` for schema
changes and `Area-Execution` for executor binaries, the foreign function
interface (FFI), and shared core behavior. Add backend or OS labels when the
issue concerns behavior specific to those backends or operating systems.
Do not add every backend label merely because shared code affects multiple
backends.

### Issue follow-up and assignment

We remove `Needs-Triage` once an area label is applied and a response records
the next step, even if that response asks for more information.
Completing triage does not require a completed investigation, an assignee, or
a release commitment.

We use `Needs-Author-Feedback` while awaiting the author's reply and
`Needs-Attention` when a maintainer or area owner owes a response or decision.
An author reply switches the issue from `Needs-Author-Feedback` to
`Needs-Attention`. We clear `Needs-Attention` once addressed, or switch back to
`Needs-Author-Feedback` when more information is requested.

Labels identify the responsible area; an assignee identifies someone who has
taken on the work. We assign work when its scope is clear and someone is ready
to take it, not simply because it falls within their area.
For cross-area work, maintainers and contributors agree on one coordinating
assignee. For areas not listed above, @mgudgin and @bbonaby help route the issue.
Maintainers handle triage when automation is unavailable.

## Contributions and pull request reviews

### Before a PR

We start proposed changes with an issue and get a maintainer's go-ahead before
opening a PR or writing a feature spec. Initial triage is not approval to
start work. Maintainers help agree on the approach and explain their decisions.

New-feature PRs opened without prior maintainer agreement in an issue may be
closed without review.

For features, maintainers record the agreed scope in the issue.
We first decide whether the feature belongs in MXC before asking contributors
to invest in a spec. Maintainers explain the next step when a PR arrives
before that discussion.
When a design or API spec is required, it must be approved and merged before
implementation begins, including draft implementation PRs.

### Review requirements

Our repository-wide [CODEOWNERS rule](../.github/CODEOWNERS) covers every file
and requests **Tessera Code Reviewers** (`@microsoft/tessera-code-reviewers`)
on every PR. At least one approval from this team is required.

PR rulesets request these teams as additional reviewers based on the files changed:

| Changed files affect | Additional reviewers |
| --- | --- |
| MXC APIs, policy, or schema | `@Mxc-Architect-Team` |
| MXC infrastructure | `@MXC-Infrastracture-Team` |

Both teams are requested when a PR spans both areas.

## Milestones and releases

Our release plans are on the [GitHub milestones page](https://github.com/microsoft/mxc/milestones).

We aim to release twice each month and plan milestones only one month ahead,
not as a longer-term roadmap. Milestones use names such as `November 2026 (2nd week)` and
`November 2026 (4th week)`. We target Friday of the release week; milestone
dates are planning targets, not guaranteed release dates.

Our **backlog** consists of all open issues without a milestone. They are
potential future work, not scheduled for a release. Ideas beyond our one-month
planning window remain in the backlog.

### Managing milestones

Contributors or assignees propose release targets. Maintainers confirm
readiness and capacity with the person taking on the work, update milestones,
and record the initial target or reason for a change in an issue comment.

| Action | Process |
| --- | --- |
| Add to a milestone | We require an assignee and a linked implementation PR, and confirm that the remaining implementation, review, and testing can realistically finish for the target release. Draft PRs may qualify; a link alone does not reserve a slot. |
| Move to another milestone | We reassess readiness and agree on a new target rather than automatically rolling unfinished work into the next release. |
| Return to the backlog | We remove the issue from the milestone when it is no longer planned for that release and no other release has been agreed. If its PR closes without merging, the issue returns to the backlog unless another linked implementation PR is still planned for that release. |
| Finish a release | We keep shipped issues in the milestone and move unfinished issues to another agreed milestone or back to the backlog. Then we close the milestone. |

Implementation PRs are linked through GitHub development links or closing
references so the relationship is visible on the issue.
We use `In-PR` while a linked implementation PR is open; this does not by
itself mean the issue is scheduled for a release or fully resolved.
An assignee, milestone, and implementation PR together are our clearest signal
of planned delivery, not a guarantee of a release date.

### Publishing releases and updates

Milestones are plans, not guarantees. We publish each release on the
[GitHub releases page](https://github.com/microsoft/mxc/releases), with information
on notable changes, SDK package links, and release binaries.

Urgent, backward-compatible fixes may ship as patch releases outside the
regular schedule.

We do not backport features or fixes to older release lines. They ship in new
releases on the current release line. Dependent projects must update to an SDK
version that includes the change to receive it.

## Prioritization and community input

We rank bugs, tasks, and features together by priority; issue type alone does
not determine priority or a release commitment.
We do not routinely use priority labels; they may be used for an urgent bug.
Backlog order can change as we learn more and capacity changes.

We use thumbs-up reactions on original bug reports and feature requests to
understand community demand. Reactions express support without "+1" or
"me too" comments; comments add new information or use cases.

We prioritize bugs and new requests using both community reactions and partner
asks, especially issues blocking current use or adoption of MXC.
We also consider the impact on users, security and reliability risks, the work
required, and dependencies. Critical issues can take priority regardless of
vote count. Votes and partner requests do not guarantee implementation or a
release date.

## SDK and schema versioning

We version SDK releases using [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html):

| SDK version change | When to use it |
| --- | --- |
| **Major** | Breaking public API or incompatible documented behavior changes |
| **Minor** | Compatible API additions, newly exposed schema capabilities, or new behavior; public API deprecations |
| **Patch** | Compatible bug fixes and internal refactoring; no new API, schema capability, or feature behavior |

A bug fix may correct behavior to match the documented contract. A new
incompatible contract is a major change, even when described as a fix.
We select the highest version change required by any change in the release.

SDK package and schema versions are independent: changing one does not
automatically change the other. We assess compatibility separately, and published
contracts remain immutable. Our
[versioning design](development/architecture/versioning.md) describes contract
selection and SDK compatibility.
