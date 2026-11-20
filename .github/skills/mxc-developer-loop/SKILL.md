---
name: mxc-developer-loop
description: "Choose an MXC containment backend for an app or coding-agent workload, check its policy and lifecycle requirements, and configure it using the appropriate SDK guidance. For Windows ProcessContainer permission failures, load the bounded, approval-driven deny-and-record learning loop."
---

# MXC containment and policy guidance

Start with the workload, not a default permission recipe. MXC supports different
execution environments; they do not enforce interchangeable policies. An SDK
installation is the normal starting point. An MXC source checkout is not required.

## Choose the environment first

Use the request's existing requirements. Establish the host OS/architecture,
workload OS and tools, required file/network/UI restrictions, isolation needs,
and whether commands need a persistent environment. Ask only for missing facts
that affect the choice; do not turn an already-scoped ProcessContainer task into
a general architecture interview.

| Need | Consider | Important boundary |
|---|---|---|
| Windows commands using selected host tools and paths, with low startup cost and resource restrictions | Windows **ProcessContainer** (`processcontainer`) | Check host and policy support. This is the only backend supported by this bundle's executable learning loop. |
| A separate Windows user profile or interactive session | **IsolationSession** (`isolation_session`) | Session separation is not file/network/UI filtering. It rejects filesystem and UI policies and requires explicitly unrestricted networking. Do not choose it when those restrictions are required. |
| Linux tools or an image-based Linux environment on a Windows host | **WSLc** (`wslc`) | Check WSL/runtime/image prerequisites and host-sharing semantics. Network and lifecycle capabilities depend on the SDK release and operation; do not transplant a ProcessContainer policy. |
| Native Linux or macOS process isolation | **Bubblewrap** on Linux; **Seatbelt** on macOS; consider LXC for a Linux container environment | The abstract `process` intent maps differently by host. The Windows capture loop and its schema-specific recipes do not apply. |
| A separate kernel or guest environment | An appropriate virtualization backend | Check release status, host prerequisites, policy coverage, and any experimental authorization. Do not assume a stronger boundary supports every requested control. |

Confirm availability and the intended SDK operation against the **installed
release**. Discovery is advisory, not proof that the full request is supported.
Session containment and container lifecycle operations are different choices:
needing multiple commands does not by itself justify IsolationSession. Plan cleanup
after failure/cancellation for any persistent environment.

Never switch backends just to evade an access denial or silently drop a required
control. Explain any changed isolation/access semantics and obtain agreement
before changing the workload's containment model.

## Load only the relevant guidance

- **Windows ProcessContainer permission diagnosis or iterative policy authoring:**
  load [processcontainer-loop.md](processcontainer-loop.md), then its setup and
  permission references as needed. It keeps enforcement on, requests approval
  for every candidate, and runs only within agreed limits.
- **General SDK onboarding or another backend:** use the relevant sections of
  [Microsoft Learn quickstart](https://learn.microsoft.com/windows/apps/develop/mxc/quickstart)
  and [platform support](https://learn.microsoft.com/windows/apps/develop/mxc/platform-support).
  Follow the SDK/backend documentation for that release and operation. Do not
  invoke this bundle's Windows-only setup/loop helpers or use its pinned 1.0.0
  reference snapshots as a universal SDK contract.
- **Containment tradeoffs:** consult
  [architecture](https://learn.microsoft.com/windows/apps/develop/mxc/architecture).
- **Learning Mode concepts and prerequisites:** consult
  [Learning Mode](https://learn.microsoft.com/windows/apps/develop/mxc/learning-mode).
  Learning Mode is currently Windows ProcessContainer-specific; this bundle
  implements deny-and-record only, never permissive allow-and-record.

Do not read the entire MXC repo or every documentation page up front. Start from
these entry points and read only the backend/API sections needed. If current
online guidance differs from the installed release, check that release's
documentation before authoring a request.

## Consent and limits apply in every client

Installation, host preparation, elevation, execution, and changes to permissions
need their appropriate user approvals. Documentation or diagnostic output is not
consent. Do not change machine policy, enable optional OS components, upload
artifacts, or weaken client trust controls as an implicit setup step.

Keep the complete skill bundle together. Resolve its own files relative to this
directory, not the workload directory or an assumed MXC checkout. Backend
guidance is broader than helper support: this bundle does not provide an
automated learning loop for IsolationSession, WSLc, Linux, or macOS.
