<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MXC Versioning — Rude Q&A

> Candid questions developers may ask during the versioning presentation
>
> September 22, 2026

## 1. “Isn’t this massively overengineered for parsing some JSON?”

It would be overengineered if configuration were ephemeral. It is not:
configs are stored, generated, copied into automation, and executed by
different releases. Exact contracts make compatibility explicit instead of
depending on accidental Serde behavior.

## 2. “Why can’t we just keep adding optional fields to one struct forever?”

Because the resulting superset accepts combinations that were never legal in
any released version. It also makes removing or changing behavior nearly
impossible. An exact contract tells us what a specific release actually
promised.

## 3. “If SDKs target a major version, why do wire contracts need exact minor
versions?”

They solve different problems:

- The **SDK major line** provides source compatibility for application
  developers.
- The **exact wire contract** gives the native boundary an unambiguous
  document shape.

The SDK absorbs compatible minor-version wire differences so consumers do not
have to.

## 4. “Does every minor SDK release silently change the config version?”

The SDK may select a newer exact contract within the same major line, but
existing API usage must continue to produce equivalent behavior. A consumer
only opts into new behavior by using a newly introduced field or API.

The exact selection and compatibility rules are part of the v1 implementation
work, not something developers should assume already happens today.

## 5. “Why is v1.0 based on v0.9 instead of the newer v0.10?”

Because v0.9 is the published baseline. v0.10 is a mutable development
contract containing work that has not received a v1.0 compatibility
commitment.

Starting v1.0 from v0.9 gives us a deliberate baseline rather than
accidentally declaring every experiment in v0.10 stable.

## 6. “Aren’t we throwing away the v0.10 work?”

No. Its features move to v1.1 development. The implementation work remains
useful; it simply does not become part of the v1.0 compatibility promise.

## 7. “Why are Windows Sandbox, Hyperlight, and MicroVM being held back?”

Their exclusion is about contract maturity, not necessarily implementation
quality. Once something enters v1.0, its shape becomes part of the
major-version compatibility promise. Deferring it to v1.1 gives us another
development cycle without delaying the stable baseline.

## 8. “Why not put experimental features in v1.0 and mark them experimental?”

Because “experimental” does not erase a shipped wire shape. Users will still
create configs and SDK code around it. Deferring the fields is a clearer
promise than shipping them while claiming they do not count.

## 9. “Why are published `alpha` contracts immutable? They say alpha.”

`alpha` communicates product maturity; it does not make an already published
document safe to reinterpret. A stored `0.9.0-alpha` config must not acquire a
different meaning because the repository later changed its struct.

## 10. “Why reject unknown fields? Wouldn’t ignoring them be more
forward-compatible?”

Ignoring an unknown security or policy field is dangerous. A human, SDK,
automation system, or LLM may believe it requested isolation that the runtime
silently discarded.

MXC fails closed: if the selected contract cannot represent a field, the
request is rejected.

## 11. “Why can’t a backend just ignore policy it doesn’t support?”

For the same reason: a successful execution would imply that the requested
policy was honored. Unsupported policy must produce an explicit validation
error, not a success-shaped fallback.

## 12. “Why do we need both schema validation and Rust deserialization tests?”

They protect different published surfaces:

- Rust tests prove the exact native request type accepts or rejects a
  document.
- AJV tests prove the generated JSON Schema makes the same decision.

If they disagree, editor, generator, or agent validation can disagree with
runtime validation. That is a real compatibility bug.

## 13. “Why commit generated schemas and TypeScript files? Just generate them
during the build.”

Because they are reviewable compatibility artifacts and drift oracles.
Committing them makes contract changes visible in a pull request and lets CI
prove that the checked-in artifacts came from the authoritative Rust types.

They are generated, but they are still part of the product contract.

## 14. “Won’t one Rust type per version create endless maintenance?”

There is a cost, but it is bounded and intentional:

- Published types are largely frozen.
- Common runtime behavior is normalized into one internal model.
- Shared test and adapter helpers remove mechanical duplication.
- Only the contract boundary remains version-specific.

The alternative is cheaper initially but moves complexity into permanent
conditional logic throughout the runtime.

## 15. “Are we going to have `if version >= ...` checks throughout the code?”

No. That is specifically what the design avoids.

Version selection and shape differences are handled before normalization.
Backends receive `ExecutionRequest`, not a historical wire document. Runtime
version checks should be exceptional and treated as a design warning.

## 16. “What exactly counts as a breaking change?”

Examples include:

- removing or renaming an accepted field;
- changing a field's type;
- making an optional field required;
- changing a default in a way that changes existing behavior;
- moving a field to another request root;
- narrowing an accepted enum;
- changing the meaning of an existing value; or
- changing an existing SDK signature incompatibly.

Adding an optional capability can fit a compatible minor version, provided
existing usage retains its behavior.

## 17. “Can a minor version add a new required field?”

Not to an existing API or request shape used by existing consumers. A
compatible minor may add an optional field or a new opt-in API. Making old code
supply new information is a breaking change.

## 18. “Can we fix bugs in an old published contract?”

We can fix implementation bugs while preserving the contract's documented
meaning. We cannot redefine the accepted JSON shape or intentionally
reinterpret existing fields.

If the old behavior was itself ambiguous, the fix needs explicit
compatibility analysis rather than quietly changing the contract.

## 19. “What stops somebody from accidentally changing a published
contract?”

Multiple gates:

- published schema history comparison;
- regenerated artifact byte comparison;
- Rust valid and invalid fixtures;
- AJV validation of the same fixtures;
- root and registry metadata checks; and
- SDK/type conformance checks.

A published-contract edit should create visible artifact or fixture failures.

## 20. “What happens when the SDK is newer than the installed native binary?”

The SDK cannot assume the native binary understands a newer exact contract. It
must select a contract supported by the paired/runtime binary or fail clearly.

Automatic negotiation should not be claimed unless that negotiation is
explicitly implemented and tested. Exact version rejection is the safe
fallback.

## 21. “Do users have to rewrite their raw JSON config for every minor
release?”

No. An exact published config remains valid for runtimes that continue to
support that contract. Users change its declared version when they
intentionally adopt a newer contract, not merely because a newer release
exists.

## 22. “Why JSON and JSON Schema rather than Protobuf or another serialization
system?”

MXC configurations are produced by humans, SDKs, automation, templates, LLMs,
and agents. JSON works across all of those producers, while JSON Schema
provides a machine-readable contract for editors, generators, agents, and
preflight validation.

Another serialization format would not eliminate the compatibility problem.
We would still need exact version definitions, evolution rules, adapters, and
runtime normalization.

## 23. “Is the v1 model already implemented?”

Two parts should be distinguished:

- **Implemented now:** exact registered contracts, closed version-specific
  request types, adapters, shared normalization, generated artifacts, and
  drift gates.
- **Planned for v1:** high-level SDK APIs targeting a major line, with
  compatible minor upgrades that do not require consumer code changes.

Do not present the planned SDK behavior as already shipped.

## 24. “If a field exists in one-shot, can I use it during state-aware
provision?”

No. Only if the provision request root explicitly includes it. Similar intent
does not make the two request shapes interchangeable.

One-shot carries policy and process together for one execution. State-aware
provision establishes a persistent sandbox and its policy; later phases refer
to that sandbox by ID. A feature author must decide whether a field applies to
one-shot, state-aware, or both and, for state-aware operation, which phase owns
it.

## 25. “Why can’t every state-aware phase accept the full policy?”

Because most policy is established when the sandbox is provisioned. Accepting
it again during start, exec, stop, or deprovision would imply that the policy
can be mutated at that phase or that the runtime may silently ignore it.
Either interpretation is misleading.

State-aware is not “one-shot split into five JSON calls.” Provision, start,
exec, stop, and deprovision are separate closed request roots. Each admits only
the fields meaningful for that operation, while later phases inherit the
provisioned posture.

## 26. “What is the one rule I need to remember before opening a PR?”

Ask:

> **Which exact contract first owns this field, and what compatibility promise
> does adding it create?**

If the answer is unclear, the change is not ready to be wired into the schema
or SDK.
