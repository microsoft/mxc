# Container Policy — Design Proposal

> **Status: Draft / Exploratory.**
> This work is **not authoritative** and is subject to substantial change.
> Nothing here describes shipped MXC behavior. For the current shipped
> sandbox policy, see [`docs/sandbox-policy/v1/policy.md`](../../sandbox-policy/v1/policy.md).

This folder collects research, design, and evaluation work on a
cross-platform **intent policy** model for sandboxed code execution. It
introduces a single declarative language used by four policy authors —
code author, user, IT administrator, and system — and describes how their
independent statements compose into an enforceable runtime configuration.

The work is recorded here so it can be reviewed, critiqued, and iterated
on without being mistaken for an approved design.

---

## Reading Order

The documents build on each other. New readers should follow this order:

1. **[`SandboxSurvey.md`](SandboxSurvey.md)** — Cross-platform survey of
   sandboxing mechanisms (Linux namespaces, Landlock, seccomp; macOS
   Seatbelt; Windows AppContainer, BFS, WFP). Establishes vocabulary.
2. **[`ContainerPolicyThoughts.md`](ContainerPolicyThoughts.md)** —
   Original research and design thinking. Compares mechanisms, proposes a
   unified JSON policy language, FlatBuffer compiled format, policy
   layers, capability profiles, lifecycle, and intent manifests. The raw
   material that fed the formal design.
3. **[`ContainerPolicyDesign.md`](ContainerPolicyDesign.md)** — The formal
   design proposal. Defines intent policy, the four-author composition
   model, the binder, and the bound-policy format. Contains a rubric-based
   self-evaluation in Appendix E.
4. **[`SandboxEvaluationRubric.md`](SandboxEvaluationRubric.md)** —
   Six-axis evaluation framework for sandboxing technologies and policy
   languages. Designed to be applied to any technology, not just the
   proposal here.
5. **[`PossibleSimplifications.md`](PossibleSimplifications.md)** —
   Internal critique of the design. Identifies six areas where complexity
   could be reduced for a v1 without losing core architectural properties.
6. **[`mxc_container_policy_alignment.md`](mxc_container_policy_alignment.md)**
   — Maps the design against the current MXC codebase. Identifies what
   MXC already implements, where gaps exist, and where MXC has
   capabilities the design doesn't yet cover.

---

## Examples

The [`examples/`](examples/) tree mirrors the layering described in
`ContainerPolicyDesign.md`. Reading top-to-bottom shows policy composing
from author intent into a runnable bound form:

| Folder | Layer |
|---|---|
| `examples/admin_intents/` | IT administrator policy |
| `examples/system_intents/` | OS / platform invariants |
| `examples/user_intents/` | User consent declarations |
| `examples/intent_manifests/` | Code-author intent (earlier format) |
| `examples/composed_policies/` | Code-author intent + composition |
| `examples/capability_profiles/` | Backend primitive + composition profiles |
| `examples/bound_policies/` | Resolved per-platform runtime configuration |

All examples are illustrative. They are not consumed by any tool in the
repository today.

---

## Status of Open Questions

`ContainerPolicyDesign.md` Appendix D enumerates known abstraction gaps
(constraints vs. configuration, network operation enforcement, claim
verification, service catalog resolution, IPC and device taxonomy, exec
whitelisting, multi-sandbox orchestration). Appendix E grades the design
against the rubric and calls out the most material risks: no enforcement
verification loop, complexity budget, IPC/device stubs, and unverified
claims. These should be resolved or explicitly deferred before any part
of this proposal is treated as authoritative.
