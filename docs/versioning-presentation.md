<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MXC Versioning

> Five-slide developer presentation
>
> September 22, 2026

---

## Slide 1 — Policy Needs a Durable Meaning

**Current architecture**

MXC policy comes from many producers:

```text
Humans     SDKs     Automation     Templates     LLMs and agents
   \        |           |              |                /
    └───────┴───────────┴──────────────┴───────────────┘
                            ↓
                    MXC configuration
                            ↓
               Stored, copied, and executed
                    by different releases
```

An **exact registered contract** gives every accepted field a precise,
machine-readable meaning.

- The version identifies the configuration language used by a document.
- Closed schemas define its fields, locations, types, defaults, and request
  roots.
- Published contracts preserve the meaning of stored policy.
- Development contracts provide the workspace for new capabilities.
- Schema-aware tools can guide humans, generators, LLMs, and agents.

**Key message:** Versioning preserves policy intent across producers, tools,
and releases.

---

## Slide 2 — Two Compatibility Promises

### Current: exact wire contracts

- Raw JSON declares one exact registered version.
- Each version owns its accepted shape and lifecycle roots.
- Published documents retain their established meaning.
- Current examples include published `0.9.0-alpha` and development
  `0.10.0-alpha`.

### Planned v1: SDK major lines

- High-level SDK APIs target a major line.
- Each SDK package release has a fixed, package-owned exact target.
- That target is the latest minor contract in its major line at release time.
- SDK 1.0 targets `1.0.0`; SDK 1.1 targets `1.1.0`.
- Compatible minor upgrades preserve existing source and policy intent.
- Optional API additions expose new minor-version capabilities.
- Raw configuration APIs continue to offer exact-version control.

```text
Exactness at the wire boundary
              +
Compatibility at the SDK boundary
```

**Example:** Existing SDK 1.0 code compiles against SDK 1.1 and expresses the
same intent. New code opts into an optional 1.1 capability.

**Key message:** The wire contract gives MXC precision; the SDK major line
gives application developers continuity.

---

## Slide 3 — One Boundary, One Runtime Model

```text
Exact external contract
          ↓
Version adapter
          ↓
One current runtime model
(CommonRequestIR → ExecutionRequest)
          ↓
Backend
```

### Lifecycle shapes

```text
One-shot:
policy + process ──→ run ──→ complete

State-aware:
provision policy ──→ start ──→ exec* ──→ stop ──→ deprovision
```

- One-shot carries policy and process together for one execution.
- State-aware provision establishes persistent policy for the sandbox.
- Start, exec, stop, and deprovision are separate closed operations against
  that provisioned sandbox.
- Version adapters translate every exact wire shape into the current model.

**Key message:** Version history ends at the contract boundary; execution uses
one current model.

---

## Slide 4 — How Developers Add a Feature

1. **Choose the contract and lifecycle.**
   - Identify the first exact contract and the applicable one-shot or
     state-aware roots.
2. **Define and adapt the shape.**
   - Add the exact Rust type and preserve field presence through adaptation
     and normalization.
3. **Validate and enforce the semantics.**
   - Each backend accepts and enforces the policy it supports.
4. **Prove and expose the feature.**
   - Add fixtures, generate artifacts, extend SDKs additively, and update the
     canonical documentation.

**Key message:** Every feature has an explicit contract owner, lifecycle
owner, runtime meaning, and SDK surface.

---

## Slide 5 — The v1 Path

**Planned v1 direction**

### Contract lineage

```text
published 0.9.0-alpha ── canonical v1 baseline ──→ published 1.0.0

development 0.10.0-alpha ─ development lineage ─→ development 1.1.0
```

- `1.0.0` establishes the canonical v1 names and published baseline.
- `1.0.0` includes WSLC, IsolationSession, directional networking, and common
  state-aware lifecycle roots.
- `1.1.0` carries the development lineage and features from v0.10.
- SDK 1.0 targets `1.0.0`; SDK 1.1 targets `1.1.0`.

### Gates protect v1 evolution

- Generated schemas and TypeScript oracles match the Rust contracts.
- Rust and AJV fixtures verify the same exact contract boundaries.
- Structural comparison classifies adjacent v1 contract changes.
- Semantic, source, and behavioral checks protect existing consumer intent.

**Question for every feature:**

> Which exact contract and request root own this feature, and what
> compatibility promise does it create?

### Three things to remember

1. Raw configurations use exact contracts.
2. High-level SDKs provide major-line compatibility.
3. Every feature has a contract owner and a lifecycle owner.
