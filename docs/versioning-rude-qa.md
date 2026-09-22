<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MXC Versioning — Rude Q&A

> Candid questions developers may ask during the versioning presentation
>
> September 22, 2026

## Why Version Policy?

### 1. “Isn’t this massively overengineered for parsing some JSON?”

The JSON carries execution and security policy. It is produced by humans,
SDKs, automation, templates, LLMs, and agents; it may be stored and executed
by another release. Exact contracts give that policy a durable meaning rather
than depending on the shape of whichever Rust type happens to exist today.

### 2. “Why can’t we keep adding optional fields to one struct forever?”

A rolling superset eventually accepts combinations that never belonged to any
released contract. It also spreads historical compatibility decisions through
the current runtime.

Exact contracts preserve the shape promised by each release. Version-specific
adapters then translate those shapes into one current runtime model.

### 3. “Why reject unknown fields? Isn’t ignoring them more
forward-compatible?”

An unknown field may represent security policy that the author believes MXC
will enforce. Silently discarding it would turn an invalid request into a
successful execution with weaker policy.

MXC fails closed: the selected exact contract must recognize the field in that
location.

### 4. “Why can’t a backend ignore policy it doesn’t support?”

A successful execution communicates that the requested policy was honored.
Backend validation therefore accepts the policy the backend can enforce and
returns an explicit error for the rest.

### 5. “Why JSON and JSON Schema instead of Protobuf or another format?”

MXC configurations serve human, SDK, automation, and agent workflows. JSON is
portable across all of them, and JSON Schema provides a machine-readable
contract for editors, generators, LLMs, agents, and preflight validation.

Another serialization format would still require exact message definitions,
evolution rules, adapters, and runtime normalization.

### 6. “Why are published `alpha` contracts immutable? They say alpha.”

`alpha` describes product maturity. Publication still creates documents that
people store, copy, and execute. A stored `0.9.0-alpha` request retains the
meaning it had when published.

The v1 line uses stable semantic versions such as `1.0.0` and `1.1.0`; registry
status identifies the mutable development contract.

## Exact Contracts and SDK Compatibility

### 7. “If SDKs target a major line, why does the wire need exact minor
versions?”

They provide two different compatibility promises:

- The **exact wire contract** gives MXC an unambiguous document shape.
- The **SDK major line** gives application developers source and behavioral
  continuity across compatible minor releases.

Exactness belongs at the native trust boundary. Compatibility belongs at the
high-level SDK boundary.

### 8. “Which exact contract does an SDK use?”

Each SDK release targets the latest minor contract in its major line:

- SDK 1.0 targets exact contract `1.0.0`.
- SDK 1.1 targets exact contract `1.1.0`.

Upgrading the SDK package advances the exact contract automatically. Existing
source must continue to compile and express the same intent; consumers use new
code when they opt into a new capability.

### 9. “Do raw JSON users rewrite their config for every minor release?”

No. A published exact document remains valid for runtimes that support that
contract. Authors change the version when they intentionally adopt another
exact contract.

Raw APIs retain exact-version control. High-level SDK APIs own their
package-selected exact target.

### 10. “What counts as a breaking change within a major line?”

Examples include:

- removing or renaming a field or request root;
- changing a field's type;
- making optional input required;
- narrowing an enum, range, or pattern;
- changing a default or presence rule in a way that changes existing intent;
- reinterpreting an existing value; or
- making an incompatible public SDK API change.

Compatible minor evolution uses additive optional fields, roots, APIs, and
capabilities while preserving established meaning.

### 11. “Can a minor version add a required field?”

It can introduce a new opt-in API or request root with its own requirements.
It cannot make existing consumers provide new input to continue expressing
the same policy.

### 12. “What happens if the SDK is newer than the native runtime?”

The SDK and runtime have an exact contract boundary. The runtime accepts
registered exact versions and reports an unsupported version explicitly.

The v1 release plan validates and releases paired SDK and runtime versions
together. Any future negotiation mechanism must be explicit and tested; exact
dispatch remains the source of truth.

### 13. “Is the entire v1 model implemented today?”

The current architecture already provides:

- exact registered contracts;
- closed version-specific request types;
- version-specific adapters;
- shared normalization;
- generated schemas and TypeScript wire oracles; and
- artifact and fixture gates.

Phase 14 adds the v1 SDK major-line behavior, `1.0.0` and `1.1.0` identities,
and the v1 compatibility gates.

## Architecture and Lifecycle

### 14. “Won’t one Rust type per version create endless maintenance?”

Published types are largely frozen. Shared adapters, normalization, fixtures,
and test support handle the reusable mechanics. Version-specific types remain
at the boundary where their differences are intentional and reviewable.

That gives MXC one current runtime model rather than permanent compatibility
branches throughout every backend.

### 15. “Are we going to have `if version >= ...` checks throughout the
runtime?”

Version selection and shape differences are resolved before normalization.
Backends receive `ExecutionRequest`, which represents current runtime
semantics.

A backend that needs to compare configuration-version strings signals that a
wire concern has escaped the contract boundary.

### 16. “If a field exists in one-shot, can I use it during state-aware
provision?”

Only when the provision request root explicitly includes it.

One-shot carries policy and process together for one execution. State-aware
provision establishes a persistent sandbox and its policy, and later phases
refer to that sandbox by ID. A feature author chooses whether a field applies
to one-shot, state-aware, or both.

### 17. “Why can’t every state-aware phase accept the full policy?”

Provision establishes the persistent policy. Start, exec, stop, and
deprovision perform different operations against that provisioned sandbox.

Each phase therefore has its own closed request root. The shape communicates
which input is meaningful at that point in the lifecycle.

## The v1 Path

### 18. “Why does `1.0.0` come from v0.9 instead of v0.10?”

Published `0.9.0-alpha` is the established baseline. It already contains WSLC,
IsolationSession, directional networking, and the common state-aware
lifecycle.

`1.0.0` uses that published baseline and establishes the canonical v1 names
and SDK boundary.

### 19. “Are we throwing away the v0.10 work?”

No. The complete v0.10 development lineage becomes development `1.1.0`.

The transition renames its contract identity, artifacts, fixtures, adapters,
tests, and documentation. It preserves the feature content rather than
deleting and reconstructing it.

### 20. “Why are Windows Sandbox, Hyperlight, and MicroVM in `1.1.0`?”

Those surfaces were developed in v0.10. Since `1.0.0` derives from the
published v0.9 baseline, the v0.10 additions naturally become the additive
`1.1.0` contract.

This lineage makes the compatibility comparison explicit:
`1.0.0` to `1.1.0`.

### 21. “Why not put experimental structures into `1.0.0`?”

Published v0.9 has no experimental structures, so the `1.0.0` baseline has
none to carry forward.

New capabilities enter `1.1.0` at their intended permanent JSON locations.
Publication eligibility and runtime authorization are separate decisions from
field placement.

### 22. “Why change the old aliases at the v1 boundary?”

The major-version boundary is the appropriate place to establish one
canonical vocabulary. `1.0.0` uses `processContainer` and `seatbelt`.

The immutable v0.x contracts continue to recognize the spellings they
published. Raw users retain access to those exact historical contracts.

## Gates and Developer Workflow

### 23. “Why do we need both Rust deserialization and JSON Schema tests?”

They protect two externally visible boundaries:

- Rust fixtures prove what the exact native request type accepts.
- AJV fixtures prove what the generated JSON Schema describes.

Running the same valid and invalid corpus through both detects drift between
tooling-time validation and runtime parsing.

### 24. “Why commit generated schemas and TypeScript wire files?”

They are reviewable compatibility artifacts and drift oracles. A pull request
shows the exact wire change, and CI proves that the committed artifacts were
generated from the authoritative Rust contracts.

The public SDK types remain high-level, hand-designed policy APIs.

### 25. “Can we fix bugs in a published contract?”

Implementation fixes may restore the contract's established meaning. Changes
to its accepted JSON shape or the intended meaning of existing fields require
a new compatible minor addition or a new major boundary, depending on the
change.

Ambiguous cases receive explicit compatibility and semantic review.

### 26. “What protects a published contract from accidental change?”

The protection is layered:

- stable-schema history checks;
- regenerated artifact comparison;
- exact Rust fixtures;
- AJV validation of the same fixture corpus;
- registry and request-root metadata checks;
- adjacent-contract structural classification;
- semantic review manifests; and
- SDK source and behavioral compatibility fixtures.

### 27. “What is the one question I should ask before opening a PR?”

Ask:

> **Which exact contract and request root own this feature, and what
> compatibility promise does it create?**

Then identify its normalized runtime meaning, backend enforcement, generated
artifacts, fixtures, and high-level SDK surface.
