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

### Exact wire contracts

- Raw JSON declares one exact registered version.
- Each version owns its accepted shape and lifecycle roots.
- Published documents retain their established meaning.
- Examples include `0.9.0-alpha`, `1.0.0`, and `1.1.0`.

### SDK major lines

- High-level SDK APIs target a major line.
- Each SDK release uses the latest minor contract in that line.
- SDK 1.0 targets `1.0.0`; SDK 1.1 targets `1.1.0`.
- Compatible minor upgrades preserve existing source and policy intent.
- Optional API additions expose new minor-version capabilities.
- Raw configuration APIs continue to offer exact-version control.

```text
Exactness at the wire boundary
              +
Compatibility at the SDK boundary
```

**Key message:** The wire contract gives MXC precision; the SDK major line
gives application developers continuity.

---

## Slide 3 — One Boundary, One Runtime Model

```text
Exact JSON contract
        ↓
Exact request root
        ↓
Version-specific adapter
        ↓
CommonRequestIR
        ↓
Shared normalization
        ↓
ExecutionRequest
        ↓
Selected backend
```

### Lifecycle shapes

```text
One-shot:
policy + process ──→ run ──→ complete

State-aware:
provision policy ──→ start ──→ exec* ──→ stop ──→ deprovision
```

- One-shot carries policy and process together for one execution.
- Provision establishes the sandbox and its persistent policy.
- Start, exec, stop, and deprovision each have a closed request root.
- Version adapters translate exact wire shapes into one normalization input.
- Backends consume the current normalized runtime model.

**Key message:** Version history ends at the contract boundary; execution uses
one current model.

---

## Slide 4 — How Developers Add a Feature

1. **Choose the first exact contract.**
   - The current development contract owns the new wire surface.
2. **Choose the lifecycle root.**
   - One-shot, provision, start, exec, stop, deprovision, or an intentional
     combination.
3. **Define the exact Rust shape.**
   - Preserve optional-field presence through parsing and adaptation.
4. **Adapt into the common runtime model.**
   - Shared normalization establishes common semantics.
5. **Implement backend validation and enforcement.**
   - Each backend accepts the policy it can enforce.
6. **Add fixtures and generate artifacts.**
   - Valid and invalid fixtures cover every applicable root.
   - Rust generates the schema and TypeScript wire oracle.
7. **Expose high-level SDK intent.**
   - Rust, Node, and .NET APIs express the feature additively.
8. **Update the canonical documentation.**

**Key message:** Every feature has an explicit contract owner, lifecycle
owner, runtime meaning, and SDK surface.

---

## Slide 5 — The v1 Path

### Contract lineage

```text
published 0.9.0-alpha ── canonical v1 baseline ──→ published 1.0.0

development 0.10.0-alpha ─ development lineage ─→ development 1.1.0
```

- `1.0.0` establishes the canonical v1 names and published baseline.
- `1.0.0` includes WSLC, IsolationSession, directional networking, and common
  state-aware lifecycle roots.
- `1.1.0` carries the features developed in v0.10, including Windows Sandbox,
  abstract VM intent, MicroVM, Hyperlight, and the test surface.
- SDK 1.0 targets `1.0.0`; SDK 1.1 targets `1.1.0`.

### Gates protect v1 evolution

- Generated schemas and TypeScript oracles match the Rust contracts.
- Rust and AJV fixtures verify the same exact contract boundaries.
- Structural comparison classifies adjacent v1 contract changes.
- Semantic manifests record the intended meaning of each addition.
- SDK source and behavioral fixtures protect existing consumer intent.

**Question for every feature:**

> Which exact contract and request root own this feature, and what
> compatibility promise does it create?
