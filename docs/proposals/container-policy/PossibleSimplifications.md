# Possible Simplifications

This document captures potential simplifications to the Container Policy
Design (`ContainerPolicyDesign.md`) that could reduce complexity
without losing the core architectural properties. These are recorded for
future consideration, not immediate action.

---

## Core Properties to Preserve

Any simplification must preserve these properties:

1. **Intent as universal format** — one schema for all policy authors
2. **Composition via intersection** — each layer restricts, never broadens
3. **Fail-closed on conflict** — if composed policy can't satisfy
   requirements, fail with attribution
4. **Binder produces bound policy** — bound policy is never hand-authored
5. **Abstract → concrete resolution** — storage classes, service names,
   tool names resolved by the binder
6. **Major version = hard fail** — the one versioning rule that really
   matters

---

## S.1 Merge System Intents into Binder / Capability Profiles

**Current design:** System intents are separate JSON files
(`examples/system_intents/*.jsonc`) expressing OS-level invariants like
"system binaries are read-only" and "no kernel memory access." These
participate in four-layer composition alongside developer, user, and
admin intents.

**Observation:** System intents describe properties of the platform, not
policies someone authors. The binder already consults capability profiles
to know what the platform enforces. System invariants (read-only system
paths, no privilege escalation) are intrinsic to the platform — they
don't change per-workload.

**Simplification:** Fold system invariants into the binder's platform
knowledge or into capability profiles. The binder always applies them
when producing a bound policy. No separate "system intent file" needed.

**Trade-off:** Loses the ability to express system policy in the same
format as other layers (less uniform). Makes it harder for an OS vendor
to ship updated system constraints independently of an MXC update.

**Risk:** Low. System invariants change rarely and are tightly coupled
to the platform the binder already understands.

---

## S.2 Simplify User Consent to Approval Annotations

**Current design:** User intents are full intent policy documents
(`examples/user_intents/*.jsonc`) with their own `manifest_version`,
`metadata`, `requires`, and `constraints` sections. They participate in
composition as a co-equal fourth layer.

**Observation:** In practice, user consent is narrowing — the user can
only restrict, never broaden. In most agentic scenarios the user either
approves or rejects what the developer requested. That's a boolean
per-resource, not a full intent policy document.

**Simplification:** User consent becomes a UI interaction that produces
approval annotations on the developer intent. For example:

```jsonc
{
  "consent": {
    "manifest_ref": "csv-data-analyzer/1.0.0",
    "approved": {
      "storage": ["input_data", "output_data", "workspace", "temp"],
      "network": [],
      "credentials": []
    },
    "overrides": {
      "max_wall_time_seconds": 90
    }
  }
}
```

This is simpler than a full intent document and directly expresses the
user's actual interaction: "I approve these capabilities and want to
lower this limit."

**Trade-off:** Loses the uniformity of "all four layers use the same
format." The consent annotation format is a different schema from intent
policy. However, it more accurately models what users actually do.

**Risk:** Medium. The full intent format for users enables power-user
scenarios (e.g., a security-conscious user writing detailed network
scope restrictions). The annotation model may not be expressive enough
for those cases.

---

## S.3 Drop Claims from v1

**Current design:** The `claims` section holds self-asserted behavioral
properties (`deterministic`, `idempotent`, `no_credential_exfiltration`,
etc.). They are explicitly not enforced and not verified. §2.7 and
Appendix D.3 both acknowledge there is no verification story.

**Observation:** Claims add schema surface area for no current benefit.
No consumer reads them. No enforcement mechanism exists. The document
defers their treatment to future work.

**Simplification:** Remove `claims` from the v1 intent schema entirely.
Add them back in a future version when there is a verification or
attestation mechanism.

**Trade-off:** Loses forward compatibility — policies written today
won't carry claims, so when verification arrives, all policies need
updating. However, this is a minor cost vs. carrying dead weight in
every policy document.

**Risk:** Low. Claims can be added as a minor version bump when needed.

---

## S.4 Inline Service Catalog into Admin Intent

**Current design:** §5.3 defines a service catalog — a separate
abstraction that maps logical service names to concrete endpoints. The
catalog has its own versioning, discovery, and conflict resolution
concerns (all flagged as underspecified in Appendix D.4).

**Observation:** The admin intent examples already contain endpoint
information directly. The catalog abstraction adds significant
complexity (versioning, discovery, conflict resolution) for a problem
that can be solved by the admin declaring allowed endpoints in their
intent policy.

**Simplification:** Admin intents declare allowed services with their
endpoints directly:

```jsonc
"requires": {
  "network": [
    { "service": "weather-api", "protocol": "https",
      "endpoints": ["api.weatherapi.com:443"] },
    { "service": "internal-api", "protocol": "https",
      "endpoints": ["gateway.corp.example.com:443"] }
  ]
}
```

The binder resolves developer-declared service names against the admin's
endpoint declarations. No separate catalog infrastructure needed for v1.

**Trade-off:** Loses the separation between "which services are
permitted" and "where services live." In large organizations, the
network team and the security team may be different groups. A catalog
lets the network team manage endpoints while the security team manages
permissions.

**Risk:** Medium. This simplification works well for small/medium
deployments but may not scale to enterprises with thousands of services
and separate operational concerns.

---

## S.5 Drop Blessed Compositions, Keep Primitive Profiles

**Current design:** Capability profiles have two layers — primitive
profiles (per-mechanism) and blessed compositions (validated stacks with
formal security guarantees). The binder matches intent claims against
composition guarantees.

**Observation:** Primitive profiles are clearly needed — the binder must
know what each mechanism can enforce. But blessed compositions with
formal guarantees add a layer of abstraction over the primitives. For
v1, the binder could simply check each intent requirement against the
set of primitives available on the platform.

**Simplification:** The binder consults primitive profiles directly. It
knows "on this Linux machine, I have Landlock v4 + seccomp + cgroups v2
+ namespaces" and checks each requirement against each primitive. No
blessed composition files needed.

**Trade-off:** Loses the pre-validated guarantee story. Without blessed
compositions, the binder can report "each individual requirement is
enforceable" but cannot assert composite properties like
"no-filesystem-escape" that depend on multiple primitives working
together correctly. The guarantee model is valuable for audit and
compliance.

**Risk:** Medium. Primitive-level checking is sufficient for
functionality. Composition-level guarantees are important for security
assurance, which matters most in enterprise/compliance contexts.

---

## S.6 Simplify Versioning: Defer Compatibility Matrix

**Current design:** §10.2 describes a binder compatibility matrix
mapping intent features to minimum config versions. §10.7 has five
detailed migration scenarios.

**Observation:** With one intent version and one config version today,
the compatibility matrix is speculative architecture. The five migration
scenarios illustrate situations that don't yet exist.

**Simplification:** Reduce versioning to three rules:

1. Major version ahead on any input → hard fail
2. Minor version ahead on any input → accept with reported gaps
3. Binder produces bound policy at the config version the runtime
   supports

Defer the compatibility matrix and detailed migration scenarios until
there are actually multiple versions in the wild.

**Trade-off:** Loses the forward-looking design guidance. When version 2
arrives, the compatibility model will need to be designed then. However,
designing it now without real usage patterns may produce the wrong
abstraction.

**Risk:** Low. The three rules are sufficient. The matrix can be
designed when there is empirical data on how versions actually diverge.

---

## Summary: What Would a Simplified v1 Look Like?

If all simplifications were adopted:

| Current Design | Simplified v1 |
|---|---|
| 4 policy layers (developer, user, admin, system) | 2 layers + annotations (developer intent, admin overlay, user approval annotations) |
| Full intent schema for all 4 authors | Full intent for developer + admin; approval annotations for user; platform knowledge in binder |
| `claims` section | Removed — added later with verification |
| Service catalog abstraction | Endpoints declared directly in admin intent |
| Primitive profiles + blessed compositions | Primitive profiles only |
| Compatibility matrix + 5 migration scenarios | 3 versioning rules |

**Composition becomes:** developer intent ∩ admin overlay ∩ user
approvals, with platform constraints applied by the binder.

**Core properties preserved:** Intent format, intersection composition,
fail-closed, binder-produced bound policy, abstract→concrete resolution,
major version fail.
