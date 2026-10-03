# Feature Spec: Known-tool Policy Floors

**Status:** Proposed public preview catalog. This is not an approved, shipped, or
implemented catalog.

**IMPORTANT NOTE:** This catalog and its repository are a temporary bridge to
Learning Mode, not a long-term supported product. Floors may broaden file
access to unblock tools, but guarantee neither success nor safety. Users and
clients must review that access; their settings and enterprise policies take
precedence.

---

## 1. Problem Statement

Developers frequently disable process isolation after enabling it breaks tools
needed for their workflow. This makes the first-run experience for process
containment poor and reduces adoption before developers can identify the
missing policy.

The near-term mitigation is a public, reviewable set of known per-tool policy
floors. Consumers can apply a candidate floor instead of starting from no tool
knowledge, and contributors can iterate on the data as failures are found. A
floor only describes a known minimum requirement. It does not prove that every
process, dependency, credential, service, or network interaction in an
end-to-end workflow is covered.

[#779](https://github.com/microsoft/mxc/pull/779) proposed the initial config
floor data model and SDK resolver. This document narrows that proposal into a
temporary catalog contract with explicit identity, platform, dependency,
revision, and inspection behavior. It reuses #779's model where possible and
calls out differences directly.

This document does not restate general MXC sandboxing concepts already covered
by [`docs/sandbox-policy/0.8.0/policy.md`](sandbox-policy/0.8.0/policy.md) or
[`docs/versioning.md`](versioning.md). It covers only what a policy store adds.

### Non-goals

- This does not change what the sandbox backend enforces, or `SandboxPolicy` /
  `ContainerConfig` schema semantics. A catalog entry embeds an existing
  `SandboxPolicy`; it does not define a parallel vocabulary.
- This is not a trust or attestation mechanism, and it does not authorize
  anything. See [§9](#9-trust-model).
- This is not a guarantee that a complete tool workflow will succeed under
  process containment.
- This does not define how any specific consumer stores, displays, or lets a
  user approve requirements. See [§2](#2-ownership-boundary).
- This does not define Learning Mode's candidate-generation or review UX. See
  [§8](#8-relationship-to-learning-mode).

### MXC feature impact and defaults

This is a standalone catalog and library proposal. Following the feature-impact
checklist in [`docs/authoring-a-new-feature.md`](authoring-a-new-feature.md):

- **Policy changes:** None. Catalog entries embed an existing, registered
  `SandboxPolicy`.
- **ContainerConfig changes:** None. The catalog does not add configuration
  fields or change omission behavior in an existing contract.
- **OS and backend changes:** None. Backends continue to validate whether they
  can enforce the resolved policy.
- **MXC SDK changes:** None. This proposal does not add catalog lookup, types,
  or resolver code to the MXC SDKs.
- **Standalone libraries:** The dedicated catalog repository provides its own
  library API for TypeScript/JavaScript, Rust, and C#/.NET, each depending on
  the corresponding MXC SDK and returning its existing `SandboxPolicy` type.
  MXC does not depend on the catalog. See
  [§6](#6-intended-repository-and-packaging-boundary).

The proposed **public preview** designation describes the catalog's support
status. It does not add an MXC schema feature, activate the
`--experimental` runtime gate, or change executor behavior.

Defaults and omission behavior are:

- Existing callers do not perform catalog lookup automatically. A consumer
  must explicitly enable or invoke it.
- Omitted `ResolveContext.platform` uses the current host platform.
- Omitted `ResolveContext.architecture` uses the device's native system
  architecture, not the architecture of the library's process or a detected
  tool build. Explicit caller selection takes precedence. See the selection
  rules and emulation risk in [§4.4](#44-platform-variants).
- Omitted `ResolveContext.catalogRevision` uses the currently installed
  catalog revision.
- Omitted `ResolveContext.allowWeakIdentityFallback` is `false`.
- Omitted `projectRoot` and `symbols` provide no caller overrides. The resolver
  uses supported local discovery and shared documented defaults for required
  symbols as specified in [§4.2](#42-entry-shape). It does not invent a project
  root or an installation path. A selected entry with an unresolved required
  symbol is not resolvable.
- Omitted `packageUrl` or `detectedVersion` supplies no matching evidence. The
  resolver does not fabricate either value.
- If no policy can be resolved, `resolveSandboxPolicy` returns `undefined`.
  `resolveSandboxPolicyWithDiagnostics` instead returns a result whose `policy` is
  `undefined`, preserving the diagnostics. The consumer's restrictive baseline
  remains unchanged.

## 2. Ownership boundary

The proposed dedicated catalog project owns an integrity-validated, versioned,
read-only data set of known-tool sandbox requirements, its resolver libraries,
and their public APIs. MXC continues to own the existing `SandboxPolicy`
contract, but not the catalog entries, libraries, repository, or publication
lifecycle.

The catalog states a candidate minimum that a tool needs. It does not grant
access, modify caller state, create a sandbox, or guarantee workflow success.
Filesystem composition combines lower-bound requirements using the least
restrictive access needed by the selected tools. This is distinct from the
consumer's restrictive composition with its own security ceilings.

Everything else is a consumer decision:

- Whether automatic catalog lookup is enabled at all.
- Access-profile mapping, elevation preference, and per-tool authorization.
- Persistence of accepted requirements (which tools, which catalog/entry
  revision, when).
- Composition with the consumer's own user, learned, and invocation-specific
  policy layers, and with non-overridable OS/enterprise/device ceilings.
- Approval UX, audit, and the final call into `createConfigFromPolicy()` /
  sandbox creation.

A catalog lookup can only ever narrow what a consumer still has to decide for
itself. `resolveSandboxPolicy` returns a candidate composed requirement or
`undefined`; its diagnostics counterpart also reports how that result was
obtained. The consumer decides whether and how to act on it. This mirrors
#779's floor/policy distinction, discussed further in
[§3](#3-relationship-to-the-config-floors-proposal): a resolved entry is a
lower bound asserted by the tool ecosystem, never an upper bound the host is
required to grant.

## 3. Relationship to the config-floors proposal

| #779 (config floors) | This document (policy store) |
|---|---|
| One `schemaVersion` for the whole table | Four separate version dimensions: `catalogSchemaVersion`, `catalogRevision`, per-entry `entryRevision`, and per-variant `sandboxPolicy.version` ([§4.1](#41-versions)) |
| Strongest satisfied identity predicate describes a match | All eligible matching entries contribute; identity evidence is retained without stronger matches suppressing weaker ones ([§4.3](#43-identity)) |
| One `sandboxPolicy` per entry; `when.platform` only conditions dependencies | One complete `SandboxPolicy` per platform variant; a variant cannot name a containment backend ([§4.4](#44-platform-variants)) |
| `requires` composition unspecified beyond "union" | Composition limited to a small, explicit, field-by-field set for the first contract version; everything else is rejected until a rule exists ([§4.5](#45-dependencies-and-composition)) |
| `getSandboxConfigForTool(tools: string[])` returns one composed policy | Replaced by `resolveSandboxPolicy`, accepting one tool or an array and returning one policy; `resolveSandboxPolicyWithDiagnostics` adds attribution, with catalog inspection kept separate ([§5](#5-api-surface)) |
| No revision/publication model | Immutable published catalog revisions; corrections publish a new revision ([§10](#10-immutable-revisions)) |

The data model, the floor/policy direction argument, multi-tool composition,
and the identity layering problem (invocation name vs. launcher artifact vs.
executing image) build on #779. The matching, composition, and trust refinements
are stated here rather than implied by that reference.

## 4. Data model

### 4.1 Versions

| Field | Meaning |
|---|---|
| `catalogSchemaVersion` | Version of the catalog JSON shape itself. |
| `catalogRevision` | Immutable identifier for one published, fully reviewed catalog. |
| `entryRevision` | Monotonic revision of a single entry, for cache invalidation and audit comparison. |
| `sandboxPolicy.version` | The exact registered `SandboxPolicy` contract version used by one platform variant. |

These identifiers serve separate purposes and do not advance in lockstep.
Registering a new `SandboxPolicy` contract does not change existing catalog
data and therefore does not require a new catalog revision. Migrating a
platform variant to that contract changes the entry's content, so publication
of that migration must increment both `entryRevision` and `catalogRevision`.
A catalog revision may still change without incrementing unaffected entries.
Tool version constraints (`versionRange`, below) are a fifth, orthogonal axis.
They describe which builds of a tool an entry was observed against, not
anything about the catalog.

### 4.2 Entry shape

```json
{
  "entryId": "tool:npm",
  "entryRevision": 3,
  "displayName": "npm / npx",
  "identity": [
    { "kind": "purl", "value": "pkg:npm/npm", "versionRange": ">=10 <12" },
    { "kind": "invocation-name", "names": ["npm", "npm.cmd", "npx", "npx.cmd"] }
  ],
  "platformVariants": [
    {
      "when": { "platform": "windows" },
      "dependencies": [{ "entryId": "tool:node", "versionRange": ">=22" }],
      "sandboxPolicy": {
        "version": "0.9.0-alpha",
        "filesystem": {
          "readonlyPaths": ["${npm_prefix}"],
          "readwritePaths": ["${project_root}", "${npm_cache}"]
        }
      }
    }
  ],
  "provenance": { "method": "reviewed-observation", "sourceRevision": "opaque-review-reference" }
}
```

Invariants:

- `entryId` is stable, unique, namespaced, and is the only key `requires`/
  dependency edges may reference.
- `entryRevision` increases on every semantic change to the entry.
- Variant selection follows the deterministic rules in
  [§4.4](#44-platform-variants). No selected variant means the tool is
  unsupported on that platform, not that it needs an empty policy, and not
  `undefined` conflated with "requires nothing" (see [#779, "Defaults and
  omission"](https://github.com/microsoft/mxc/pull/779)).
- Symbols (`${project_root}`, `${npm_cache}`, OS well-known folders) are
  resolved by the resolver before a policy is returned; catalog data never
  ships a literal, machine-specific path. This is unchanged from #779.
- An embedded `sandboxPolicy` is validated against the real `SandboxPolicy`
  schema for its declared `version`. The catalog schema does not duplicate
  that validation.

Symbol definitions are shared across entries and versioned with the selected
catalog revision. Each definition describes the symbol's permitted sources
and may include a `defaults` map from platform to path template. This extends
the catalog contract, not `SandboxPolicy`. Entries continue to reference
symbols rather than repeat defaults. For example, default metadata in the
shared symbol registry can include:

```json
{
  "symbols": {
    "npm_cache": {
      "defaults": {
        "linux": "${user_home}/.npm",
        "macos": "${user_home}/.npm"
      }
    }
  }
}
```

This is a metadata fragment, not a complete symbol definition. Default
templates may reference approved host-known symbols; they cannot contain
commands or executable discovery logic. Shared definitions and defaults are
covered by the catalog revision's integrity validation and cannot change
behind a pinned revision.

For symbols required by selected entries and dependencies, precedence is:

1. Explicit caller values from `projectRoot` or `symbols`, as applicable.
2. Supported local discovery, including `PATH`, known host locations, and
   relevant tool configuration overrides.
3. A documented default for the selected platform, if applicable.
4. Unresolved, with diagnostics and no partial policy.

Tool-specific discovery runs in the library, not in catalog-supplied code.
It does not execute candidate tools, install software, or contact the network.
Automatic discovery and host-derived values describe the current host and
environment; callers targeting another execution environment supply overrides.
A failed configuration read is an explicit library error, not evidence that
no override exists and a default should be used. Discovery does not verify
tool identity. The diagnostics operation reports the source and resolved value
of each discovered or defaulted symbol through `diagnostics.warnings`.

### 4.3 Identity

`identity` describes the predicates a candidate can satisfy for an entry,
using the layering #779 §3.1 establishes (invocation name vs. launcher artifact
vs. executing image; falsifiable-against-a-local-artifact as the admission test
for a new kind).

Caller-supplied identity is not verified identity. A `packageUrl` match does
not prove that the installed tool belongs to that package; the caller is
responsible for verifying that association. The library does not inspect the
tool to verify it.

Invocation-name matching is locale-independent and case-insensitive on every
platform. This affects catalog lookup only: it does not change the caller's
command, the OS's executable lookup rules, or package-identity matching.

Matching is additive across entries. For each input tool, the resolver collects
every entry with a satisfied, eligible identity predicate and an applicable
platform/architecture variant. It does not choose a single winning entry:

- A package-identity match does not suppress another entry's eligible
  invocation-name match. Equal-strength matches to different entries also
  contribute; they are not ambiguity errors.
- Identity strength describes the matching evidence, not precedence between
  entries. Diagnostics retain all satisfied identity predicates for each
  contributing entry.
- Multiple predicates matching the same entry do not add its policy multiple
  times. Entries shared across input tools or dependency chains likewise
  contribute once, while diagnostics preserve the per-input matches.
- Multiple matching entries for one input produce a diagnostic warning, not
  a refusal. Their policies must still satisfy the composition rules in
  [§4.5](#45-dependencies-and-composition).
- Diagnostic tool records follow input order, matches are ordered by
  `entryId`, and matched predicates follow their declaration order within the
  entry. Catalog file order does not select or exclude a match.

The existing matching qualifications remain:

- A version range on an identity predicate is advisory matching evidence, not
  a gate. A detected mismatch returns a diagnostic alongside the resolved
  policy rather than silently degrading precision, and the consumer decides
  what to do with the mismatch.
- Invocation-name-only identity is the always-available fallback, not the
  default outcome. Whether a consumer accepts an invocation-name-only match
  automatically, or requires opt-in, is unresolved. See
  [§13](#13-open-questions). Under the current proposed default, an entry
  matched only by invocation name participates when
  `allowWeakIdentityFallback` is `true`. Compose-all-matches does not bypass
  that option.

### 4.4 Platform variants

Supported platforms are `windows`, `linux`, and `macos`. Supported architecture
selectors are `x64` and `arm64`. A variant selector has this closed shape:

```ts
interface PlatformVariantSelector {
  platform: "windows" | "linux" | "macos";
  architecture?: "x64" | "arm64";
}
```

A platform variant is a complete requirement statement: one full
`SandboxPolicy`, not a patch applied to a base policy, plus any
platform-specific dependencies. Variants are never merged. Architecture is a
catalog selector, not a field added to the embedded `SandboxPolicy`. Omitting
`when.architecture` makes a catalog variant architecture-neutral; omitting the
caller's `ResolveContext.architecture` instead requests the host default.

Selection first filters by platform, then uses the following precedence:

| Caller context | Preferred variant | Fallback |
|---|---|---|
| Explicit `architecture: "x64"` | x64 for the selected platform | Architecture-neutral for that platform |
| Explicit `architecture: "arm64"` | ARM64 for the selected platform | Architecture-neutral for that platform |
| Architecture omitted | Device's native system architecture for the selected platform | Architecture-neutral for that platform |

The native system architecture is the architecture reported by the host OS,
not the architecture of the process hosting the library. For example, on an
ARM64 device with both x64 and ARM64 catalog variants and no neutral variant,
omitting architecture selects ARM64. An explicit `architecture: "x64"` selects
x64 on that same device. The resolver does not require a neutral variant to
return a result when the effective architecture has an exact match.

Catalog validation rejects duplicate exact selectors and more than one
architecture-neutral variant for the same platform. If neither an exact nor
architecture-neutral variant exists, that entry contributes no match, not an
empty policy or a variant for a different architecture. A failure to determine
the native system architecture when it is needed is a library error, not a
guessed selection.

**Emulation risk:** A host-derived default does not establish the architecture
of the installed tool. An x64 tool running under emulation on an ARM64 device
may need the x64 variant rather than the default ARM64 variant. The resolver
does not inspect or run the tool to discover its architecture. Callers that
know the relevant tool and runtime requirements should select architecture
explicitly and remain responsible for deciding whether the result applies.
Neither explicit selection nor a host default guarantees that the returned
policy is sufficient or minimal. Host-derived selection and neutral fallback
are surfaced through `diagnostics.warnings` by the diagnostics API
([§5.1](#51-runtime-lookup)).

A platform variant must not name a specific MXC containment backend. Policies
stay backend-neutral; the selected backend still decides whether a stated
requirement can be realized on that host.

### 4.5 Dependencies and composition

Dependencies reference another entry's `entryId` and live inside the platform
variant when platform-specific. An optional `versionRange` records which
dependency versions supplied the reviewed evidence. The v1 resolver has no
dependency inventory, so it does not evaluate that range or use it for
matching. It returns the range as unevaluated metadata for consumer inspection.
Catalog validation checks only that the range is syntactically valid.
Resolution is otherwise transitive, cycle-rejecting, and deterministic, and
the diagnostics API returns the resolved dependency metadata alongside the
policy.

The same composition rules apply to all entries matched by one tool, entries
matched by different tools in an array, and their transitive dependencies.
Each selected entry contributes its policy once, even when reached through
multiple inputs or dependency edges. Repeated contribution is de-duplicated
by entry ID within the selected catalog revision, not by discarding match
attribution. A shared `ResolveContext` applies to the whole lookup.

Following #779's floor semantics, filesystem composition preserves the access
required by all selected tools rather than intersecting their requirements.
An overlapping read-only requirement must not suppress another tool's needed
write access, and a catalog-provided deny must not block a required read or
write path. This is not a rule for merging consumer authorization policy.
For the first contract version, cross-entry composition is limited to the exact
`filesystem.deniedPaths`, `filesystem.readonlyPaths`, and
`filesystem.readwritePaths` fields:

1. Every policy in the selected entries and their dependency closure must
   declare the same `sandboxPolicy.version`.
2. At lookup time, resolve all required symbols and normalize paths using the
   selected platform's path rules before comparing equal or
   ancestor/descendant paths. Combine the selected entries and dependencies,
   de-duplicating paths within each access class.
3. Preserve every required read-write subtree. Remove read-only entries equal
   to or contained within a read-write subtree, since read-write already
   satisfies their read requirement. Retain a read-only ancestor of a
   read-write subtree without promoting the whole ancestor to read-write.
4. Remove each catalog-provided deny that overlaps any required read-only or
   read-write path, whether equal, an ancestor, or a descendant. Remove the
   entire deny entry, not an invented exception beneath it. Retain
   non-overlapping denies.
5. Return the composed policy and make the access changes available through
   diagnostics. The same rules apply to overlaps within one selected entry
   and across multiple entries; matching or traversal order must not change
   the effective access.

Filesystem comparison is separate from invocation-name matching. Equality,
de-duplication, and ancestor checks honor the applicable filesystem and
directory case-sensitivity, not a blanket OS assumption. When that information
cannot be determined, compare case-sensitively, preserve differently cased
paths as distinct, and report the assumption in diagnostics. Returned paths
retain their casing; comparison must not lowercase the policy paths. Another
target environment must not inherit this host's filesystem case rules.

| Resolved requirements | Composed filesystem policy |
|---|---|
| Read-only `/work` and read-write `/work` | Read-write `/work`; omit read-only `/work` |
| Read-write `/work` and read-only `/work/tools` | Read-write `/work`; omit read-only `/work/tools` |
| Read-only `/work` and read-write `/work/cache` | Retain read-only `/work` and read-write `/work/cache`; do not make all of `/work` writable |
| Denied `/data` and read-write `/data/cache` | Remove denied `/data`; retain read-write `/data/cache` and report that the entire `/data` deny was removed |
| Denied `/secrets` and read-write `/work` | Retain both non-overlapping entries |

These are composition rules for the returned MXC `SandboxPolicy`, not changes
to MXC's enforcement precedence. Simply concatenating a conflicting deny or
read-only entry with a grant is insufficient: the restrictive entry could
still prevent the access the composed floor is intended to request.

Removing a parent deny removes its protection for the entire subtree, not
just the overlapping required path. It does not itself add a grant to that
subtree, but other grants can now apply there. Diagnostics must identify the
removed deny and this broader effect. Caller-owned denies and other user,
enterprise, device, or backend restrictions are never inputs to this
least-restrictive catalog composition and must not be removed by it.

Publication checks validate policy shapes, symbols, and supported composition
fields and exercise the rules with known paths and fixtures. Equal or nested
filesystem requirements are not by themselves invalid catalog data. Caller
symbol values can introduce additional overlaps, so the resolver must always
apply these rules after substitution and normalization at lookup time.
An overlap covered by these rules is not a composition error; missing required
symbols or unsupported composed fields retain their existing failure behavior.

The v1 contract does not compose `network`. In particular, it defines no merge
for `network.egress.default`, `network.egress.allow`,
`network.egress.deny`, `network.ingress.default`, or
`network.ingress.hostLoopback`. Composition rejects a selected set of entries
where policies from more than one entry would require composing any `network`
field. The same rejection applies to timeout, clipboard, lifecycle, UI, proxy,
and every other policy field without an explicit cross-entry rule. A lookup
resolving to only one entry without dependencies may still use
catalog-supported policy fields because no cross-entry merge occurs.

## 5. API surface

The standalone libraries separate runtime resolution from catalog inspection.
Resolution accepts one tool or an array and composes all applicable matching
entries and dependencies into one `SandboxPolicy`. Callers choose a policy-only
operation or a diagnostic operation over the same resolution logic. Neither
implicitly returns the whole catalog. These are in-process library calls, not
a hosted service or additions to the MXC SDKs.

The signatures below use TypeScript to describe the shared contract. Rust and
C# expose the same operations and metadata with idiomatic names and types.
TypeScript and C# expose single-tool and array overloads; Rust uses an idiomatic
one-or-many input type because it does not support function overloading. An
absent policy is `undefined` in TypeScript/JavaScript, `None` in Rust, and
`null` in C#. Library failures remain distinct from policy absence.

### 5.1 Runtime lookup

Failures reuse existing MXC error codes, which are sufficient for normal
programmatic handling. An optional `details.reason` may provide a stable,
catalog-specific distinction for logging, investigation, or finer handling
when the code alone is too broad. Callers need not branch on it; an absent or
unrecognized reason retains the same handling as the primary code. A reason
must not duplicate a distinction already expressed by an existing MXC code.

The following primary-code mappings apply across all language bindings.
When `details.reason` is supplied for these failures, it uses the listed value;
callers may ignore it.

| Failure | MXC error code | Optional `details.reason` |
|---|---|---|
| Invalid tool input or resolution context | `malformed_request` | `invalid_context` |
| Invalid catalog data, including invalid dependency references or cycles | `policy_validation` | `invalid_catalog` |
| Unsupported composition, including mixed policy versions or fields without a composition rule | `policy_validation` | `composition_conflict` |
| Unsupported or undetectable host platform or architecture | `unsupported_containment` | `unsupported_host` |
| Catalog content cannot be read or fails its integrity check | `backend_error` | `integrity` |
| Explicitly requested catalog revision is not installed | `backend_error` | `revision_unavailable` |

Filesystem overlaps handled by [§4.5](#45-dependencies-and-composition) are not
composition failures. Ordinary no-match results remain policy absence, not an
error from this table.

```ts
import type { SandboxPolicy } from "@microsoft/mxc-sdk";

interface ToolCandidate {
  invocationName: string;
  packageUrl?: string;
  detectedVersion?: string;
}

type ToolInput = string | ToolCandidate;

interface ResolveContext {
  projectRoot?: string;
  symbols?: Record<string, string>;
  platform?: "windows" | "linux" | "macos";
  architecture?: "x64" | "arm64";
  catalogRevision?: string;
  allowWeakIdentityFallback?: boolean;
}

interface SandboxConfigResolution {
  policy: SandboxPolicy | undefined;
  diagnostics: {
    catalogRevision: string;
    tools: Array<{
      inputIndex: number;
      matches: Array<{
        entryId: string;
        entryRevision: number;
        matchedIdentities: Array<{
          kind: string;
          strength: "strong" | "weak";
        }>;
      }>;
    }>;
    resolvedDependencies: Array<{
      entryId: string;
      entryRevision: number;
      requiredVersionRange?: string;
    }>;
    warnings: string[];
  };
}

export declare function resolveSandboxPolicy(
  tool: ToolInput,
  ctx?: ResolveContext
): SandboxPolicy | undefined;

export declare function resolveSandboxPolicy(
  tools: readonly ToolInput[],
  ctx?: ResolveContext
): SandboxPolicy | undefined;

export declare function resolveSandboxPolicyWithDiagnostics(
  tool: ToolInput,
  ctx?: ResolveContext
): SandboxConfigResolution;

export declare function resolveSandboxPolicyWithDiagnostics(
  tools: readonly ToolInput[],
  ctx?: ResolveContext
): SandboxConfigResolution;
```

A string input is shorthand for `{ invocationName: tool }`; it supplies no
package or version evidence and follows the same weak-identity option as an
object input. For example, name-only lookup under the current proposed opt-in
rule is:

```ts
const ctx = { allowWeakIdentityFallback: true };
const policy = resolveSandboxPolicy("npm", ctx);
const combinedPolicy = resolveSandboxPolicy(["git", "npm"], ctx);
const result = resolveSandboxPolicyWithDiagnostics("npm", ctx);
const combinedResult =
  resolveSandboxPolicyWithDiagnostics(["git", "npm"], ctx);
```

Single-tool lookup is equivalent to a one-element array; its diagnostic
`inputIndex` is `0`. A caller retaining separate policies per tool can use
single-tool calls. A caller wanting one sandbox for several tools passes an
array. Both forms compose every eligible matching entry, not just the
strongest match, and the selected dependencies.

`resolveSandboxPolicy` returns the composed `SandboxPolicy` directly, not a wrapper
or a `ContainerConfig`. It is the exact type provided by the corresponding MXC
SDK, not a catalog-owned lookalike. Callers can pass an accepted policy directly
to that SDK without conversion or serialization. The `policy` field returned
by `resolveSandboxPolicyWithDiagnostics` uses that same SDK type, with attribution
and warnings from the same resolution pass. Callers choose one operation;
retrieving diagnostics does not require a second lookup or process-global
"last result" state.

Following #779, an unmatched input contributes no requirements while matched
inputs still contribute. Each input has a diagnostic record; an unmatched
input has an empty `matches` list and a warning. An empty input array or an
all-unmatched lookup produces no policy, not an empty policy:
`resolveSandboxPolicy` returns `undefined`, while the diagnostics operation returns
a `SandboxConfigResolution` with `policy: undefined`. An empty array has no
per-input records. Unresolved required symbols in selected entries prevent a
policy from being returned and produce diagnostics; they are not grounds for
silently omitting a selected requirement to produce a partial policy.

Multiple matching entries for one input are listed in `matches`, with a
warning identifying that input and the contributing entry IDs. Shared entries
remain attributed to every matching input even though their policy is
composed once. Dependency diagnostics retain each distinct
entry/revision/required-version-range combination, ordered by those fields;
repeated metadata does not mean repeated policy contribution.

When architecture is omitted, diagnostics include a warning naming the
effective native system architecture and stating that the tool's architecture
was not verified. Architecture-neutral fallback is also identified. These
diagnostics describe selection; they do not attest to the installed tool's
architecture. The policy-only operation does not expose warnings or
attribution; consumers needing them use `resolveSandboxPolicyWithDiagnostics`.

Filesystem composition diagnostics report read-only requirements superseded
by read-write requirements and catalog denies removed to satisfy required
access. Each warning identifies the resolved paths, access classes, and
contributing entry IDs. A removed deny warning names the full removed scope
and explains that other grants may now apply throughout it, not only at the
overlap. Both APIs return the same composed policy; callers needing to review
these adjustments use `resolveSandboxPolicyWithDiagnostics`.

### 5.2 Setup and inspection

```ts
type CatalogPlatform = "windows" | "linux" | "macos";
type CatalogArchitecture = "x64" | "arm64";

type CatalogIdentityMetadata =
  | { kind: "purl"; value: string; versionRange?: string }
  | { kind: "invocation-name"; names: string[] };

interface CatalogEntryMetadata {
  catalogRevision: string;
  entryId: string;
  entryRevision: number;
  displayName: string;
  identity: CatalogIdentityMetadata[];
  platformVariants: Array<{
    platform: CatalogPlatform;
    architecture?: CatalogArchitecture;
    dependencyEntryIds: string[];
    sandboxPolicyVersion: string;
  }>;
  provenance: {
    method: string;
    sourceRevision: string;
  };
}

export declare function listCatalogEntries(): CatalogEntryMetadata[];
export declare function getCatalogInfo(): { catalogSchemaVersion: string; catalogRevision: string };
```

This supports setup UI, catalog browsing, and update decisions without paying
the cost of policy resolution, and keeps "give me everything" out of the
runtime lookup path entirely. Metadata exposes selectors, dependency IDs, and
provenance, but not an unresolved or resolved policy body.

### 5.3 Consumer obligations

A consumer that uses this API:

1. Decides whether automatic lookup is enabled at all.
2. When persisting an accepted policy, retains its `catalogRevision` and
   contributing entry IDs/revisions from diagnostics, whether the policy
   covers one tool or several.
3. Keeps catalog-derived requirements in a layer separate from its own user,
   learned, and invocation-specific policy.
4. Applies its own authorization, elevation, and restrictive-composition
   rules on top.
5. Enforces its OS, enterprise, device, and backend ceilings regardless of
   what the catalog returned.
6. Fails closed when a required entry cannot be realized on the current
   host/backend. It falls back to its own restrictive baseline and does not
   run uncontained.
7. Uses the diagnostics operation when attribution or audit is needed, and
   records matched identities, catalog/entry revisions, warnings, and approval
   state in its own audit trail.

The catalog libraries never write a consumer's policy store. A consumer's own
capability observation (see [§8](#8-relationship-to-learning-mode)) can produce
candidate evidence for a future contribution to this catalog; it is not a
mechanism for mutating the catalog at request time.

## 6. Intended repository and packaging boundary

The catalog is intended to live in a new public repository outside
`microsoft/mxc`. Its schema, entries, resolver libraries, contribution history,
validation, and publication workflow belong there. This specification remains
in MXC while the proposed contract is reviewed. No catalog repository or
package is created by this proposal.

MXC retains the existing `SandboxPolicy` contract and SDK types. Each catalog
library has a required dependency on its language's MXC SDK and constructs
that SDK's policy type. The dependency runs only from the catalog to MXC:
MXC neither references the catalog nor performs catalog lookup. A consumer
passes its final, authorized policy directly to the existing MXC SDK.
Standalone means separate repository, API, and release ownership, not absence
of SDK dependencies. SDK dependencies may bring native build or package
assets; catalog lookup itself does not invoke MXC sandbox execution.
Catalog and library releases using supported SDK contracts do not require
an MXC SDK release or changes to MXC repository governance.

### 6.1 Library distribution and consumption

The initial library language coverage matches MXC's current first-party SDK
languages, but the packages are owned and released by the catalog project:

| Language | Distribution | MXC SDK dependency and policy type |
|---|---|---|
| TypeScript / JavaScript | npm package | `SandboxPolicy` from `@microsoft/mxc-sdk` |
| Rust | Cargo crate | `mxc_sdk::SandboxPolicy` from `mxc-sdk` |
| C# / .NET | NuGet package | `Microsoft.Mxc.Sdk.SandboxPolicy` from `Microsoft.Mxc.Sdk` |

Repository and package names remain to be selected. This language match does
not require copying MXC's native-binding architecture or exposing sandbox
execution operations.

Each library declares compatible MXC SDK versions. The catalog and caller must
resolve compatible SDK dependencies with the same policy type identity,
including crate source/version in Rust. Returned policies must use fields and
contract versions supported by that SDK; unsupported data must not be silently
dropped to fit its types.

A consumer:

1. Installs and pins the standalone library package for its language. Each
   package includes a reviewed default catalog revision for local use.
2. Calls `getCatalogInfo()` or `listCatalogEntries()` for inspection.
   `resolveSandboxPolicy()` returns a policy for one tool or an array;
   `resolveSandboxPolicyWithDiagnostics()` adds match attribution and warnings.
3. Handles policy absence without widening its restrictive baseline. It
   reviews the composed policy and uses the diagnostics operation when it
   needs contributing identities, revisions, and warnings, applying the
   consumer obligations in [§5.3](#53-consumer-obligations).
4. Supplies its final policy to its chosen execution integration. The catalog
   library does not launch a sandbox.

The library API reference and repository/package READMEs must state:

> Returns a candidate MXC `SandboxPolicy` combining the access requirements of
> all matching tools and their dependencies. Overlapping filesystem
> requirements use the least restrictive access needed to satisfy the combined
> requirements, including removal of conflicting catalog-provided denies.
> This is not authorization or a guarantee of workflow success. The caller
> decides whether to accept the requested access and must preserve its own
> user, enterprise, and device restrictions. Use
> `resolveSandboxPolicyWithDiagnostics` to review contributing entries and access
> changes, including the full scope of any removed deny.

Lookup is local and does not download updates, contact a hosted service, or
run the candidate tool. `ResolveContext.catalogRevision` selects an available
local revision, not a network lookup; an explicitly requested revision that
is unavailable is an error, not a substitution with a different revision.
An omitted revision uses the library's installed default.

Catalog revisions are also published as immutable, language-neutral data
artifacts. A library package version identifies the library release, not the
catalog revision or embedded `SandboxPolicy.version`; it declares the catalog
schema and policy versions it supports and reports its bundled
`catalogRevision`. Publishing newer data can update the packages' bundled
revision without changing resolver behavior. Installing an update does not
rewrite a consumer's previously accepted per-tool policies.

### 6.2 Cross-language consistency and support

All three libraries use the same catalog format and shared conformance
fixtures. Given the same catalog revision, tool inputs, explicit resolution
context, and relevant host/filesystem observations, they must agree on matching,
variant selection, dependency metadata, effective policy, diagnostic meaning,
and failure categories. This is semantic consistency, not byte-identical
output or reproduction of another language's runtime behavior.

Each binding uses consistent, idiomatic result and error handling for its
language. Equivalent failures map to the corresponding existing MXC error
codes, while error types, message wording, and language-specific representations
may differ. Callers need not understand another binding or parse message text.
Shared fixtures compare policy semantics and required diagnostic information,
including prescribed ordering, rather than identical warning prose or
incidental serialization. The catalog digest format remains shared as
specified in [§10](#10-immutable-revisions).

Shared fixtures cover platform path semantics as well as ordinary lookup;
matching function names alone is not compatibility. Package CI must also
exercise installation, public API usage, and host-derived defaults on the
supported platforms. Implementation sharing between languages is a separate
engineering decision; catalog resolution does not move into MXC's engine.

Supporting three languages includes maintaining parity, dependencies,
documentation, and releases, not only writing the initial implementations.
The libraries and catalog have the same limited public-preview horizon and
are intended to retire together when Learning Mode replaces this workflow.

## 7. Contribution and review

- Catalog contributions are pull requests against the dedicated catalog
  repository. No client or SDK can write a catalog entry at runtime.
- Every entry change includes identity evidence, supported tool version
  range(s), platform evidence, a minimized requirement set, test fixtures,
  and provenance.
- CI validates schema conformance, exact `SandboxPolicy` version registration,
  entry-ID uniqueness, dependency closure and cycle-freedom, symbol validity,
  absence of unsafe user-specific literal paths, unsupported-field rejection,
  deterministic resolution, and package inclusion.
- A new entry or a requirement expansion requires one catalog-owner approval
  and one security/policy-reviewer approval, plus tool- or scenario-owner
  evidence where available.
- A requirement reduction requires regression evidence that every supported
  tool version still functions under the narrower requirement.
- Library API and implementation contributions are reviewed in the dedicated
  catalog repository. These contribution requirements do not require
  applications to seek maintainer approval to use the public catalog or
  libraries.

## 8. Relationship to Learning Mode

Learning Mode is the intended long-term solution. The known-tool catalog only
reduces immediate first-run failures while that workflow is completed. It is
not a parallel long-term policy platform.

MXC's learning-mode capabilities (`learningModeLogging`,
`permissiveLearningMode`, `captureDenials`; see
[`docs/learning-mode/capabilities.md`](learning-mode/capabilities.md)) are the
substrate a contributor can use to observe what a tool actually touches, the
same way [#779 §5.1](https://github.com/microsoft/mxc/pull/779) describes for
config floors. That observation workflow is unchanged by this document and
remains **a contributor step that happens before a pull request**, not
consumer runtime behavior and not a catalog-mutation path.

Whether and how a consumer turns its own runtime capability observations into
a candidate catalog contribution or a locally scoped policy suggestion is
that consumer's design. No runtime submission hook is proposed here. When
Learning Mode can provide the required observation and policy-authoring
experience directly, this catalog should be retired rather than promoted into
a durable platform.

## 9. Trust model

This document tightens #779's trust framing rather than replacing it. Entries
assert *need*, not authorization, but incorrect data has two different
outcomes:

- An understated floor omits a requirement and can cause the tool or its
  end-to-end workflow to fail under the resulting policy.
- An overstated floor can fail against a narrower consumer ceiling. If a
  consumer instead approves or adopts it and its ceiling permits the request,
  the effective policy contains unnecessary capability.

Even correct entries can yield a broader combined request than any one tool
needs. Read-write requirements supersede overlapping catalog read-only
requirements, and a conflicting parent deny is removed in full under
[§4.5](#45-dependencies-and-composition). These changes are intentional and
reported by the diagnostics API; they are not permission to remove a
consumer's own restrictions.

What changes from #779 is the review bar. #779 described community-contributed,
unsigned, unwarranted data. This contract requires named-role approval
([§7](#7-contribution-and-review)) before an entry publishes, and publishes
under an immutable, integrity-validated revision ([§10](#10-immutable-revisions)).
That raises confidence in the data; it does not change what the data *is*. The
catalog still carries no security guarantee or independent authority. A
consumer must review the requirement and intersect it with its own policy
rather than adopt it outright. The catalog can influence a consumer's
decision, so consumer approval and restrictive ceilings remain required even
though the catalog cannot grant capability by itself. See
[#779 §2.1](https://github.com/microsoft/mxc/pull/779) for why that layering is
honest about what such a choice costs.

## 10. Immutable revisions

Published catalog revisions are immutable. A correction, including a security
fix to an over-broad entry, publishes a new `catalogRevision` and bumps the
affected `entryRevision`; it never rewrites a revision a consumer may already
have cached or recorded in an audit trail.

In addition to schema validation, verify the stored revision content,
including shared symbol definitions, against its packaged expected digest
when loading it. A mismatch is an explicit library failure, not a no-match
result. Validated immutable data may be cached; each lookup need not rehash it.
The packaging format defines the digest input consistently across languages,
without requiring a custom JSON parser or canonicalization implementation.

This lightweight check detects content that no longer matches the packaged
revision metadata. It does not independently authenticate the publisher or
protect against replacing both content and digest; authenticity remains a
property of the trusted package or artifact distribution channel.

## 11. Backward compatibility

- No change to `SandboxPolicy` or `ContainerConfig` schema.
- No change to executor behavior.
- No change to the MXC SDK APIs and no catalog dependency added to MXC.
  The catalog libraries depend on MXC SDKs, not the reverse. Catalog lookup
  requires an explicit call; existing MXC callers see no behavior change.
- Catalog schema and API compatibility are limited to the stopgap's support
  horizon. Retirement in favor of Learning Mode is an expected outcome, not a
  normal promotion milestone.

## 12. Test plan

**Resolver libraries (TypeScript/JavaScript, Rust, and C#/.NET)**

- shared conformance fixtures produce equivalent results and failure
  categories in all three languages without requiring identical message text
  or language-specific representations; each binding's error handling is
  consistent and uses the corresponding MXC error codes
- failure cases use the primary-code mappings in [§5.1](#51-runtime-lookup);
  any supplied reason uses its listed value, and callers can handle the code alone
- one-tool and one-element-array overloads produce equivalent policies and
  diagnostics; the simple API returns the same policy as the diagnostic API
- multiple input tools compose all matching entries and dependencies into one
  policy; repeated inputs or shared dependencies do not duplicate contributions
- known and unknown inputs compose the known requirements and report each
  unmatched input; empty and all-unmatched arrays return no policy, never an
  empty policy, while the diagnostic API preserves the resolution metadata
- omitted context uses host platform and native system architecture, the
  installed catalog revision, no caller symbol overrides, and no weak-identity
  fallback
- an unresolved required symbol prevents policy output, with diagnostics,
  rather than silently omitting selected requirements
- caller symbol overrides precede discovery, which precedes documented
  defaults; only required symbols are resolved, with source/value diagnostics
- failed configuration reads are errors, not default selection; another
  target environment does not inherit this host's discovered paths
- pinned catalog revisions retain their shared symbol definitions and defaults;
  unsupported default templates and executable discovery data are rejected
- one input matching several entries composes all eligible matches, including
  equal-strength matches; a stronger match does not suppress a weaker eligible
  match, and diagnostics preserve all matching entries and identity evidence
- multiple predicates matching the same entry contribute that policy once;
  file order does not change matching or composition
- string shorthand and object inputs obey the same weak-identity fallback
  option; additive matching does not bypass it
- invocation-name case variants match identically on all platforms without
  changing command spelling or package-identity matching
- filesystem equality, de-duplication, and ancestor checks follow the actual
  case rules, including case-sensitive macOS volumes and Windows directories;
  unknown sensitivity preserves differently cased paths with a diagnostic
- version-range mismatch produces a warning, not a refusal
- exact-architecture variant precedes the platform-only variant; duplicate
  selectors are rejected; no matching variant produces `undefined`
- on an ARM64 host with both architecture-specific variants and no neutral
  variant, omitted architecture selects ARM64; explicit x64 selects x64
- a library process running as x64 under emulation on an ARM64 host still
  defaults to the native ARM64 system architecture, not its process
  architecture
- a missing exact variant falls back to the platform's neutral variant;
  a different architecture's variant is never used as a fallback
- successful host-derived selection and neutral fallback produce the
  diagnostics specified in [§5.1](#51-runtime-lookup); host-architecture
  detection failure produces a library error, not a guessed match
- dependency chain resolution, including cycles (terminate, no duplication)
- dependency `versionRange` is returned as unevaluated metadata and never used
  for v1 resolver matching
- filesystem floor composition ([§4.5](#45-dependencies-and-composition)):
  same-class de-duplication; equal read-only/read-write paths become read-write;
  read-write ancestors subsume read-only descendants, while read-only
  ancestors remain read-only outside required writable subtrees
- literal paths and distinct symbols that resolve to equal or nested paths
  follow the same lookup-time composition rules; catalog publication checks
  do not substitute for this runtime pass
- catalog denies equal to, above, or below required read/write paths are
  removed; non-overlapping denies remain; warnings identify source entries,
  paths, access changes, and the full scope of removed parent denies
- overlaps within one entry, across matched inputs, and through dependencies
  behave identically; both APIs return equivalent composed policies, and
  entry/input traversal order does not change effective access
- mixed policy versions, network fields, and other unsupported composed fields
  remain rejected, including incompatible entries selected together only at
  lookup time
- symbol resolution on Windows, Linux, and macOS

**Data (CI)**

- every entry and platform variant validates against the catalog schema and
  the `SandboxPolicy` schema for its declared version
- `dependencies[].entryId` references resolve within the same catalog revision
- no literal absolute user-specific paths; no wildcard filesystem/network grants
- catalog/entry revision monotonicity across a proposed change

**Integration**

- each package installs with its declared MXC SDK dependency and performs
  lookup without invoking sandbox execution; lookup requires no network access
- compiled consumer examples in all three languages pass both the direct
  result and the diagnostic result's policy to existing MXC SDK APIs without
  casts, adapters, or serialization; the same SDK policy type is used throughout
- the bundled catalog revision matches `getCatalogInfo()`; selecting an
  unavailable revision fails explicitly, without falling back to another
  revision
- changing stored catalog content without updating its expected digest fails
  on load even when the changed content still passes schema validation
- a package update leaves previously accepted consumer policies unchanged
- a representative tool that fails under a minimal consumer policy succeeds
  once its resolved entry is composed in
- the composed MXC policy realizes the documented read-only/read-write
  nesting without unnecessarily promoting a read-only parent to read-write;
  retained backend precedence does not reintroduce removed catalog conflicts
- the same tool still fails when the consumer's policy forbids what the entry
  requests (the floor never widens the consumer's ceiling)
- a caller-owned deny still prevents access even when an overlapping
  catalog-provided deny was removed during floor composition

## 13. Open questions

Recommended answers are proposals for review, not decisions.

| Question | Recommended answer |
|---|---|
| What is the dedicated repository name and owning team? | Use a public repository outside `microsoft/mxc`; publish a separately versioned artifact so catalog updates are not coupled to SDK releases. |
| Is invocation-name-only identity accepted automatically, or does it require explicit consumer opt-in? | Treat it as a fallback requiring explicit opt-in (`allowWeakIdentityFallback`), not the default. |
| What happens on a detected tool-version mismatch: `undefined`, or a warning-bearing result the consumer may still use? | Return the resolved result with a warning; refusing outright removes information the consumer needs to decide for itself. |
| Are private or enterprise catalog overlays in scope, and if so with what precedence? | Defer until the shared catalog contract and its API are stable; define precedence explicitly before any library implementation adds overlay support. |
| Should the first contract version's composition vocabulary expand beyond [§4.5](#45-dependencies-and-composition) before implementation? | No. Start with least-restrictive filesystem floor composition and expand only with an explicit, reviewed rule per field. |
| Who owns catalog schema, data, and library API review? | Assign catalog, library, and security reviewers in the dedicated repository; MXC SDKs remain unaware of the catalog. |
| Should the libraries share a resolver implementation or implement the contract independently? | Choose based on dependency footprint and maintenance cost, with shared conformance fixtures required either way. |

## 14. Related work

- [`microsoft/mxc#779`](https://github.com/microsoft/mxc/pull/779) - Sandbox
  Config Floors feature spec. This document's data model, floor/policy
  direction argument, and identity-layering analysis build directly on it.
- [`ChazGo/mxc#1`](https://github.com/ChazGo/mxc/pull/1) - draft SDK resolver
  and catalog prototype exercising lookup, dependency closure, and symbol
  resolution against an earlier version of this shape.
- [`docs/sandbox-policy/0.8.0/policy.md`](sandbox-policy/0.8.0/policy.md) -
  the `SandboxPolicy` contract every catalog entry embeds.
- [`docs/versioning.md`](versioning.md) - the versioning model
  [§4.1](#41-versions) builds on.
