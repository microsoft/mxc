# Feature Spec: Known-tool Policy Floors

**Status:** Under review. Pending API sign-off from the designated MXC SDK
reviewers before merge and implementation. Not part of MXC 1.0; no later release
is committed.

**IMPORTANT NOTE:** The Policy Store provides best-effort baseline requirements
believed necessary for representative tool workflows. Floors may broaden file
access to unblock tools, but guarantee neither success nor safety. Users and
clients must review that access; their settings and enterprise policies can
further constrain or override the recommendation.

---

## 1. Problem Statement

When users first enable sandboxing without known-good configurations, tools
can break and users spend time debugging or disable containment. The catalog
supplies a suggested starting policy intended to make requested tools work
out of the box when the user has not configured the sandbox and no enterprise
policy overrides it.

Clients can configure the sandbox and override these defaults; user and
enterprise policy can further restrict them, including later changes. The
catalog is a best-effort suggestion, not authorization or a guarantee of
success or safety.

[#779](https://github.com/microsoft/mxc/pull/779) proposed the initial config
floor data model and SDK resolver. This document develops that proposal into
an SDK catalog contract with identity, platform, dependency, revision, and
inspection behavior. It reuses #779's model where possible and calls out
differences directly.

For caller-facing review, start with the [API spec](mxc-policy-store-api.md).

This document does not restate general MXC sandboxing concepts already covered
by the [v1 SDK reference](https://github.com/microsoft/mxc/blob/894f4c159705f5f470727e4fa1e363a2abec88f1/docs/reference/node/v1/README.md) or
[versioning design](development/architecture/versioning.md). It covers only what a policy store adds.

### Non-goals

- This does not change backend enforcement or the MXC 1.x request contract.
  Catalog data uses a supported subset of `ContainerRequest`; it does not
  define a parallel policy vocabulary or supply commands.
- This is not a trust or attestation mechanism, and it does not authorize
  anything. See [§9](#9-trust-model).
- This is not a guarantee that a complete tool workflow will succeed under
  process containment.
- This does not define how any specific consumer stores, displays, or lets a
  user approve requirements. See [§2](#2-ownership-boundary).
- This does not define Learning Mode's candidate-generation or review UX. See
  [§8](#8-relationship-to-learning-mode).

### MXC feature impact and defaults

**MXC 1.0 alignment:** Command-free lookup and composition are unchanged.
`ContainerRequirements` reuses the filesystem, network, UI, and timeout types
from the [v1 request](https://github.com/microsoft/mxc/blob/894f4c159705f5f470727e4fa1e363a2abec88f1/sdk/node/src/v1/types.ts#L549-L597);
the caller supplies the command and final execution settings later. The SDK owns
wire version selection.

| Earlier spec | MXC 1.x alignment |
|---|---|
| `SandboxPolicy`, `resolveSandboxPolicy` | `ContainerRequirements`, `resolveToolRequirements` |
| `SandboxConfigResolution.policy` | `ToolRequirementsResolution.requirements` |
| `default.sandboxPolicy` and its `version` | `default.requirements` subset; catalog `sdkContractVersion` records validation target |
| `ui.allowWindows` | `ui.disable` with inverse meaning; `clipboard` and `allowInputInjection` retain their meanings |
| Synchronous Node resolution | Promise-returning plain verbs, with no `Async` suffix |

This is an MXC SDK API, not a command-line utility. Following the feature-impact
checklist in
[authoring a new feature](development/guides/authoring-a-new-feature.md):

- **Policy changes:** None. Entries use the existing v1 request access fields.
- **ContainerConfig changes:** None. The catalog does not add configuration
  fields or change omission behavior in an existing contract.
- **OS and backend changes:** None. Backends continue to validate whether they
  can enforce the resolved policy.
- **MXC SDK changes:** Add policy-resolution and inspection APIs to the existing
  TypeScript/JavaScript, Rust, and C#/.NET SDKs, returning `ContainerRequirements`.
- **Delivery:** V1 policy data is embedded in the MXC native library at build
  time and ships in the existing MXC SDK packages. See
  [§6](#6-intended-repository-and-packaging-boundary).


Caller defaults and omission behavior are defined in the
[API spec](mxc-policy-store-api.md#context-defaults-and-symbol-resolution).
Lookup is command-free and opt-in; unresolved requirements never authorize a
less restrictive execution fallback.

## 2. Ownership boundary

MXC owns the reviewed, versioned, read-only catalog, its resolution and
inspection APIs, and their SDK publication lifecycle in `microsoft/mxc`.
The requirements type and its underlying request field types remain MXC-owned as well.

The catalog states a best-effort baseline for a tool. It does not grant
access, modify caller state, create a sandbox, or guarantee workflow success.
Filesystem and network composition combine lower-bound requirements using the
least restrictive access needed by the selected tools. This is distinct from
the consumer's restrictive composition with its own security ceilings.

Everything else is a consumer decision:

- Whether automatic catalog lookup is enabled at all.
- Access-profile mapping, elevation preference, and per-tool authorization.
- Persistence of accepted requirements (which tools, which catalog/entry
  revision, when).
- Composition with the consumer's own user, learned, and invocation-specific
  policy layers, and with non-overridable OS/enterprise/device ceilings.
- Approval UX, audit, and the final call to the v1 `run` / `spawn` operations
  (or their language equivalents).

A catalog lookup can only ever narrow what a consumer still has to decide for
itself. `resolveToolRequirements` yields candidate requirements or
`undefined`; its diagnostics counterpart also reports how that result was
obtained. The consumer decides whether and how to act on it. This mirrors
#779's floor/policy distinction, discussed further in
[§3](#3-relationship-to-the-config-floors-proposal): a resolved entry is a
lower bound asserted by the tool ecosystem, never an upper bound the host is
required to grant.

## 3. Relationship to the config-floors proposal

| #779 (config floors) | This document (policy store) |
|---|---|
| One `schemaVersion` for the whole table | Separate catalog shape, catalog/entry revisions, and SDK-owned validation target ([§4.1](#41-versions)) |
| Strongest satisfied identity predicate describes a match | Select the most specific identity/intent/architecture match per tool; tied matches are errors ([§4.3](#43-identity)) |
| One `sandboxPolicy` per entry; `when.platform` only conditions dependencies | One unversioned default per entry, with platform/intent data and optional additive version overlays ([§4.2](#42-entry-shape)) |
| `requires` composition unspecified beyond "union" | Composition limited to a small, explicit, field-by-field set for the first contract version; everything else is rejected until a rule exists ([§4.5](#45-dependencies-and-composition)) |
| `getSandboxConfigForTool(tools: string[])` returns one composed policy | Replaced by `resolveToolRequirements`, accepting one tool or an array and optional lookup context; `resolveToolRequirementsWithDiagnostics` adds attribution ([§5](#5-api-surface)) |
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
| `sdkContractVersion` | Catalog-revision metadata recording its published validation target (`1.0.0` initially), not a caller-selected wire version. |

These identifiers serve separate purposes and do not advance in lockstep.
Registering a new exact request contract does not change existing catalog
data. A semantic entry change increments its `entryRevision` and the containing
`catalogRevision`; changing only catalog metadata, including its published
validation target, increments only `catalogRevision`. Revalidating unchanged
data does not rewrite its published metadata or either revision.
Tool versions and `versionRange` values are distinct from catalog revisions.

Entries use MXC's v1 request access fields; breaking changes require a new
major surface. No entry or caller chooses a wire version. At SDK build time,
every bundled revision is revalidated against that SDK's exact
`SDK_CONTRACT_VERSION` and its matching schema, not automatically accepted by
semver range. An older published validation target remains selectable when
it is an exact registered stable target in the same major and the current
build has revalidated its data successfully. Other revisions are not bundled.
At lookup, select only those build-validated revisions; never dispatch their
historical target or substitute another revision. The SDK owns wire version
selection as described in the [versioning design](development/architecture/versioning.md).

### 4.2 Entry shape

```json
{
  "entryId": "tool:git",
  "entryRevision": 3,
  "displayName": "Git",
  "versionScheme": "intdot",
  "identity": [
    { "kind": "purl", "value": "pkg:generic/git" },
    { "kind": "invocation-name", "names": ["git", "git.exe"] }
  ],
  "default": {
    "requirements": {
      "filesystem": {
        "readonlyPaths": ["${git_prefix}"],
        "readwritePaths": ["${project_root}"]
      }
    },
    "intents": {
      "local": {
        "exampleSubcommands": ["status", "diff"],
        "policyAdditions": {}
      },
      "fetch": {
        "exampleSubcommands": ["fetch", "pull"],
        "policyAdditions": {
          "network": {
            "egress": {
              "allow": [
                { "to": [{ "cidr": "192.0.2.10/32" }], "ports": [{ "protocol": "tcp", "port": 443 }] }
              ]
            }
          }
        }
      },
      "push": {
        "exampleSubcommands": ["push"],
        "policyAdditions": {
          "network": {
            "egress": {
              "allow": [
                { "to": [{ "cidr": "192.0.2.10/32" }], "ports": [{ "protocol": "tcp", "port": 22 }] }
              ]
            }
          }
        }
      }
    }
  },
  "platformVariants": [
    {
      "when": { "platform": "windows" },
      "policyAdditions": {
        "filesystem": { "readonlyPaths": ["${programData}/Git"] }
      }
    }
  ],
  "versionVariants": [
    {
      "versionRange": "vers:intdot/>=2.40|<2.50",
      "intentAdditions": {
        "push": { "dependencies": [{ "entryId": "tool:ssh" }] }
      }
    },
    {
      "versionRange": "vers:intdot/>=2.50|<3",
      "newIntents": {
        "bundle-fetch": {
          "exampleSubcommands": ["clone --bundle-uri=<uri>"],
          "policyAdditions": {
            "filesystem": { "readwritePaths": ["${temp_dir}/git-bundles"] },
            "network": {
              "egress": {
                "allow": [
                  { "to": [{ "cidr": "198.51.100.20/32" }], "ports": [{ "protocol": "tcp", "port": 443 }] }
                ]
              }
            }
          }
        }
      }
    }
  ],
  "provenance": { "method": "reviewed-observation", "sourceRevision": "opaque-review-reference" }
}
```

Each entry has exactly one unversioned `default`, containing the conservative
subset common to all tool versions and platforms, not the newest version's
behavior. It contains base access fields and an optional timeout suggestion in
`requirements`, plus intent additions. The timeout is advisory, not an access
grant; the caller supplies the command and final execution settings when
constructing a `ContainerRequest`.
Unversioned means no tool-version selector, not a caller-selectable wire version.

`versionVariants` is an optional list of non-overlapping VERS ranges using the
entry's `versionScheme`. Effective policy data is `default` plus the selected
platform/architecture overlay and at most one selected version overlay.
Neither dimension cascades across multiple variants. In either overlay,
`policyAdditions` and `dependencies` add to the base, `intentAdditions` adds to
intents the default declares, and `newIntents` defines intents the default
does not declare. Additions use only fields
with defined monotone composition: no replacements, deletions, narrowing,
negative operations, or removal/renaming of inherited intents.
In v1, access additions are read-only/read-write paths and outbound allow
rules. Overlay deny rules, scalar replacements, and delete/rename operations
are invalid.

To narrow requirements for newer versions, remove the access from the default
and add it only to the older version ranges that need it. Each effective
variant must retain all default access and intents. Intent bodies themselves
remain additions to their effective base, not full policy copies.

The Git example illustrates the structure, not a verified Git compatibility
matrix. `local` adds nothing; default fetch and push add their network needs.
The first range adds an SSH dependency to push through `intentAdditions`. The
second defines `bundle-fetch` through `newIntents`, without inheriting the
first range's SSH dependency. The endpoints are
documentation addresses. The Windows overlay adds `${programData}/Git`;
`programData` is the Windows common application-data directory and is resolved
only when that overlay is selected.

Intent names are exact identifiers scoped to the tool: Git's `local`, `fetch`,
and `push` are supplied as `intent: "local"`, `"fetch"`, or `"push"`.
`exampleSubcommands` contains non-normative hints for callers. The caller maps
command lines to intents; the catalog does not parse or execute command lines.

Invariants:

- `entryId` is stable, unique, namespaced, and is the only key `dependencies`
  edges may reference.
- `entryRevision` increases on every semantic change to the entry.
- Exactly one `default` is required, including when no version variants exist.
  Entries with only versioned variants, multiple defaults, or a variant tagged
  as default are invalid.
- Each entry declares a supported `versionScheme`. Version ranges are valid,
  non-overlapping, and use that scheme. Overlap is a catalog error, not a
  precedence choice.
- Intent names are unique in each materialized default-plus-overlays result.
  `intentAdditions` may name only intents the default declares. `newIntents`
  cannot reuse a default intent name or a name the other selected overlay
  defines. All additions and dependencies are versioned with the containing
  entry.
- Variant selection follows the deterministic rules in
  [§4.4](#44-platform-variants). No matching platform overlay leaves the common
  default unchanged; it does not produce an empty policy or a no-match result.
- Symbols (`${project_root}`, `${npm_cache}`, OS well-known folders) are
  resolved by the resolver before a policy is returned; catalog data never
  ships a literal, machine-specific path. This is unchanged from #779.
- Embedded request access fields use the v1 SDK contract and the validation
  pipeline below; there is no standalone `SandboxPolicy` schema.

`default.requirements` is closed to the three filesystem path lists,
directional network policy, v1 UI fields, and unsigned 32-bit `timeoutMs`.
Commands, wire versions, backend configuration, runtime proxy values,
lifecycle/cleanup settings, environment data, and unknown fields are rejected,
including inside overlays. `policyAdditions` retains its access-only meaning.
When UI is present, `disable` is required; `clipboard` and `allowInputInjection`
are optional. UI/timeout composition and overlay limits remain those of §4.5.

Build validation materializes every platform/architecture/version/intent
combination, enforcing the closed field set, selectors, and additive rules.
Bind fixture symbols and a validation-only command, then expose the SDK's exact
[`OneShotRequest` before normalization](https://github.com/microsoft/mxc/blob/894f4c159705f5f470727e4fa1e363a2abec88f1/src/mxc-sdk/src/policy/exact/v1_0.rs#L184).
This hook must be implemented: `prepare_request` returns normalized data.
Validate the exact serialization against the SDK target's schema, initially
[`mxc-config.schema.1.0.0.json`](https://github.com/microsoft/mxc/blob/894f4c159705f5f470727e4fa1e363a2abec88f1/schemas/stable/mxc-config.schema.1.0.0.json),
mapping `allowInputInjection` to wire `injection` and supplying the SDK-owned
wire version. Check CIDR/exclusion containment, protocol/port relationships,
numeric bounds, and unknown fields. Run semantic normalization on a disposable
copy; its restrictive path precedence must not alter the original floors.
The fixture command is never executed or returned. Lookup repeats validation
with real symbols and the object-identity checks in §4.5. Neither stage probes
or launches a backend; enforcement and capability checks still occur at execution.

Symbol definitions are shared across entries and versioned with the selected
catalog revision. Each definition describes the symbol's permitted sources
and may include a `defaults` map from platform to path template. This extends
the catalog contract, not `ContainerRequest`. Entries continue to reference
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
    },
    "programData": {
      "source": "host",
      "description": "Windows common application-data directory."
    }
  }
}
```

This is a metadata fragment, not a complete symbol definition. Default
templates may reference approved host-known symbols; they cannot contain
commands or executable discovery logic. Shared definitions and defaults are
embedded with the entries and cannot change behind a pinned catalog revision.

Symbol discovery implementations follow the
[API precedence and failure rules](mxc-policy-store-api.md#context-defaults-and-symbol-resolution).
Tool-specific discovery is library code, never executable catalog data.

### 4.3 Identity

Entries declare package-identity predicates and invocation-name fallbacks,
with tool-defined intents and version overlays. The
[API matching contract](mxc-policy-store-api.md#identity-and-match-precedence)
defines equality, precedence, and malformed-input behavior; the
[version/intent contract](mxc-policy-store-api.md#version-intent-and-platform-selection)
defines selection and diagnostic outcomes. Catalog indexing and validation
must use those same rules, not introduce a second comparison policy.

Validate complete catalog PURLs and reject invalid predicates, including any
version, qualifiers, or subpath; only type, optional namespace, and name are
catalog identity predicates. Do not silently strip unsupported predicate
components. Validate VERS syntax, supported schemes, and non-overlapping
ranges during authoring/build.
Neither predicate ordering nor file order may resolve an ambiguous match.

### 4.4 Platform variants

Each platform variant's `when` selector contains `platform` (`windows`,
`linux`, or `macos`) and optional `architecture` (`x64` or `arm64`).
It adds `policyAdditions`, `dependencies`, `intentAdditions`, and
`newIntents` to the common default; it never removes, narrows, or replaces
default requirements. Catalog validation rejects duplicate exact selectors
and more than one architecture-neutral variant for a platform.

The [API selection rules](mxc-policy-store-api.md#version-intent-and-platform-selection)
define precedence, host defaults, and emulation diagnostics. Architecture is
catalog context, not a new `ContainerRequest` field. Variants remain
backend-neutral; execution still validates backend capabilities.

### 4.5 Dependencies and composition

The [API composition contract](mxc-policy-store-api.md#dependencies-and-composition)
defines selected dependencies, effective access, conflicts, and failures.
Implement the same rules within entries, across requested tools, and through
dependency closures. Caller restrictions are never inputs to floor composition.

Dependency references use `entryId` and may name intents, for example
`{ "entryId": "tool:ssh", "intents": ["connect"] }`. Validate that those
intents exist in every materialized platform combination where referenced.
A dependency range is validated VERS metadata, not detected version evidence.
Traverse transitively, rejecting cycles.

De-duplicate each source layer independently within an entry/catalog revision:
default base once; platform base by selector; default intent by name; platform
intent by selector/name; version base by range; version intent by range/name.
New intents belong to their defining overlay. Do not attach a requesting
pair's version or intent to a shared base key. Preserve all requesting input
indexes for direct and transitive attribution.

Resolve symbols and validate bound values before floor composition. Lexical
normalization respects platform path syntax and actual case rules; retain
original casing. It does not establish filesystem-object identity.
Use MXC's [object comparison primitives](https://github.com/microsoft/mxc/blob/894f4c159705f5f470727e4fa1e363a2abec88f1/src/mxc-sdk/src/core/mxc_common/filesystem_object.rs#L100-L265):
Windows volume serial/file ID via `CreateFileW`/`FileIdInfo`, Unix device/inode
via `stat`. Resolve existing ancestors for subtree comparison. A cleanly
missing suffix is relative to its deepest established ancestor, not an existing
alias; unreadable components and unresolvable broken links are unknown.

Preserve required alias locations, including bind mounts, symlinks, junctions,
hard links, and 8.3 names, even when object identity is shared. Reconcile access
without deleting a needed pathname. For unknown relationships, exclude every
affected pair, not just the restrictive side; remove solely owned layers and
retain shared layers for remaining contributors. Recompose complete surviving
pairs. This resolver observation does not replace enforcement-time checks.

Catalog validation exercises composition with fixtures, but caller symbols and
filesystem observations require lookup-time validation too. Materialization
must not invoke the runner's restrictive normalization as the floor merge
algorithm. Unsupported composition fails explicitly.

## 5. API surface

The [Policy Store API spec](mxc-policy-store-api.md) is the authoritative
caller-facing contract: public types, signatures, defaults, behavior, errors,
diagnostics, and usage examples. This document owns catalog authoring and
implementation. API review comes first; implementation follows the approved
contract.

### 5.1 Runtime lookup

`resolveToolRequirements` resolves one tool or an array into command-free
`ContainerRequirements`; `resolveToolRequirementsWithDiagnostics` also
reports coverage, selections, dependencies, and warnings.
See [operation signatures](mxc-policy-store-api.md#6-language-bindings),
[types](mxc-policy-store-api.md#3-types-and-fields), and
[results/coverage](mxc-policy-store-api.md#results-coverage-and-attribution).

### 5.2 Setup and inspection

`listCatalogEntries` and `getCatalogInfo` expose metadata without resolving
policy bodies. Their signatures and
[metadata types](mxc-policy-store-api.md#inspection-metadata) live in the API spec.

### 5.3 Consumer obligations

Consumers own authorization, their policy layers, accepted-policy persistence,
and execution. The [API responsibilities](mxc-policy-store-api.md#5-errors-and-consumer-responsibilities)
define the contract; the [trust model](#9-trust-model) explains its rationale.
Catalog APIs never write a consumer's store or mutate reviewed data at lookup.

## 6. Intended repository and packaging boundary

The Policy Store lives in `microsoft/mxc` and ships through the existing MXC
SDK packages, not a separate repository, package, or command-line utility.
Catalog data and resolver APIs follow the MXC contribution and release process.

One internal `policy_store` module in `mxc-sdk` uses the SDK's v1 types and
common identity helpers. Rust calls it directly; Node/.NET use panic-contained
`mxc_ffi` library exports, not launch/probe APIs. V1 data is embedded at build
time, with no dynamic fetching; that is a possible V2 capability.


### 6.1 Library distribution and consumption

Resolution and inspection ship through the existing TypeScript/JavaScript,
Rust, and .NET SDKs. The [API spec](mxc-policy-store-api.md#6-language-bindings) owns
entry-point names, return types, and language conventions. SDK reference pages
and package READMEs should link that contract rather than duplicate it.

V1 data updates ship with MXC releases; catalog revision metadata does not
imply an independent download channel. A package update never rewrites a
consumer's previously accepted requirements.

### 6.2 Cross-language consistency and support

All three SDKs use the same catalog format and shared conformance
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
incidental serialization.

Shared fixtures cover platform path semantics as well as ordinary lookup;
matching function names alone is not compatibility. Package CI must also
exercise installation, public API usage, and host-derived defaults on the
supported platforms. Binding tests exercise the shared native resolver rather
than independent implementations of the resolution rules.

Every .NET Policy Store DTO crossing the JSON FFI boundary must be registered
as a `[JsonSerializable]` root in `MxcJsonContext` and use the `MxcJson` helpers.
Its serialize/deserialize paths must be covered by
`Microsoft.Mxc.Sdk.AotSmokeTest`; reflection fallback is not permitted.

Policy Store is an ongoing SDK capability. Language parity,
documentation, and maintenance belong to the MXC SDK release process.

### 6.3 Catalog source layout and embedded data

Catalog authors edit one JSON file per tool under
`src/mxc-sdk/policy_store/catalog/entries/`. Each file contains that tool's full
entry: identity, common default, intents, all platform/version variants,
dependencies, and provenance. Do not split variants or intents into separate files.

```text
src/mxc-sdk/policy_store/
  catalog/
    contract.v1.json
    manifest.json
    entries/
      git.json
      node.json
      npm.json
    revisions/
      <catalogRevision>.json       # generated release snapshot
    views/
      <catalogRevision>.md         # generated reviewer view
      <catalogRevision>.requests.json  # generated validation requests
  schema/
    catalog.v1.schema.json
    manifest.v1.schema.json
  conformance/
```

Build tooling collects entry files recursively, validates globally unique
`entryId` values and dependency references, and assembles the complete candidate
revision in stable entry-ID order. CI checks generated snapshots/views against
their editable inputs; authors do not maintain a second policy copy by hand.
Optional category subdirectories are organizational only: paths and file order
never affect identity, lookup, or composition.

`manifest.json` selects the default revision and maps bundled revisions to
generated snapshots. Published snapshots remain immutable; changing tool data
produces a new catalog revision and the required entry revision changes.
Generating a new revision never overwrites a published one. Moving an entry
between category directories alone is not a semantic policy change.

The build embeds validated snapshots into the native library. These are source
and generated-artifact paths, not runtime lookup directories or files consumers
edit. Consumer persistence remains separate from the read-only MXC catalog.

## 7. Contribution and review

- Catalog and API contributions are pull requests in `microsoft/mxc`.
  No client or SDK can write a catalog entry at runtime.
- Every entry change includes identity evidence, supported tool version
  range(s), platform evidence, a minimized requirement set, test fixtures,
  and provenance.
- Entry and dependency `versionRange` values pass VERS syntax and supported-type
  validation during authoring/build validation. An entry's version ranges must
  use its declared scheme and must not overlap.
- Keep one unversioned default common to all versions and platforms. Define an
  intent only when its additions materially differ in network access,
  credentials, or writes outside the
  workspace. Do not create one intent per subcommand. An empty `local` intent
  identifies base-only use separately from omitted-intent aggregation.
- Intent dependencies and access additions must be justified by that intent.
  Example subcommands are caller guidance, not executable matching rules.
- CI must validate the agreed policy contract and version mapping,
  entry-ID uniqueness, dependency closure and cycle-freedom, symbol validity,
  absence of unsafe user-specific literal paths, unsupported-field rejection,
  deterministic resolution, and package inclusion.
- Build validation rejects missing/multiple defaults, version-only entries,
  variants tagged as default, and non-additive platform/version operations.
  Materialize and schema-validate every platform x architecture x version
  variant x intent combination, including omitted-intent aggregation.
- Verify default base requirements are a subset of each effective base, and
  each inherited default intent's policy/dependencies are a subset of the same
  effective intent. Overlays may add names through `newIntents`, never delete,
  rename, or redefine inherited intents. Validate dependency closures
  introduced by additions too.
- Generate rendered effective-policy views and diffs from the default for
  catalog reviewers; do not require reviewers to mentally expand overlays.
- A new entry or a requirement expansion requires one catalog-owner approval
  and one security/policy-reviewer approval, plus tool- or scenario-owner
  evidence where available.
- A requirement reduction needs regression evidence for the representative
  scenarios used to justify the entry, not a universal workflow guarantee.
- Catalog data and SDK changes follow MXC's contribution and release review.
  These requirements do not require applications to seek maintainer approval
  to use the SDK APIs.

## 8. Relationship to Learning Mode

Learning Mode complements Policy Store; it does not replace it. Policy Store
is a long-lived source of best-effort baseline requirements.
Learning Mode is developer tooling for discovering requirements and
productizing them as reviewed policy data.

MXC's learning-mode capabilities (`learningModeLogging`,
`permissiveLearningMode`, `captureDenials`; see
[logging access denied](logging-access-denied.md)) are the
substrate a contributor can use to observe what a tool actually touches, the
same way [#779 §5.1](https://github.com/microsoft/mxc/pull/779) describes for
config floors. That observation workflow is unchanged by this document and
remains **a contributor step that happens before a pull request**, not
consumer runtime behavior and not a catalog-mutation path.

Whether and how a consumer turns its own runtime capability observations into
a candidate catalog contribution or a locally scoped policy suggestion is
that consumer's design. The SDK provides no runtime submission hook or
automatic mutation of the release-bundled catalog.

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
requirements, and a conflicting catalog filesystem or egress deny is removed
in full under
[§4.5](#45-dependencies-and-composition). These changes are intentional and
reported by the diagnostics API; they are not permission to remove a
consumer's own restrictions.

What changes from #779 is the review bar. #779 described community-contributed,
unsigned, unwarranted data. This contract requires named-role approval
([§7](#7-contribution-and-review)) before an entry publishes, and publishes
under an immutable revision through MXC's package distribution
([§10](#10-immutable-revisions)).
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

V1 embeds entries and shared symbol definitions in the native library at build
time and inherits MXC package signing and distribution integrity. It has no
separate catalog digest or runtime checksum. Schema validation still applies.

## 11. Backward compatibility

- No change to the v1 `ContainerRequest` or exact `ContainerConfig` schema.
- No change to executor behavior.
- New opt-in APIs in existing MXC SDKs; callers that do not use policy lookup
  see no behavior change from this feature.
- No breaking policy-schema changes within MXC 1.x; breaking changes require
  2.x. Bundled entries follow the containing SDK's compatible policy contract.

## 12. Test plan

**SDK resolver APIs (TypeScript/JavaScript, Rust, and C#/.NET)**

- shared conformance fixtures produce equivalent results and failure
  categories in all three languages without requiring identical message text
  or language-specific representations; each binding's error handling is
  consistent and uses the corresponding MXC error codes
- failure cases use the [API error mappings](mxc-policy-store-api.md#5-errors-and-consumer-responsibilities);
  any supplied reason uses its listed value, and callers can handle the code alone
- one-tool and one-element-array overloads produce equivalent requirements and
  diagnostics; the simple API yields the same requirements as the diagnostic API
- a separate TypeScript consumer imports every public function and named type
  from the v1 package entry point; same-file snippet checks are not sufficient
- Rust borrowed-slice calls and .NET single/list sync/async calls compile with
  the documented context and cancellation parameters; name-only conversions
  set only the invocation name and do not alter weak-matching opt-in or validation
- converted and directly constructed candidates have identical matching and
  invalid-input outcomes; .NET null-name construction rejects rather than
  fabricating a default, and `string[]` is not a candidate-list overload
- per-input records use optional `selection` and required boolean `contributes`
  in all bindings; selected identity metadata survives version/intent failures
  without implying contribution
- validated output is defined exactly when at least one input contributes;
  no output means all flags are false, including symbol-resolution failures;
  a sole failed input leaves no dependency-only output
- duplicate inputs and inputs sharing dependencies may both contribute;
  flags report inclusion, not unique grants, authorization, or execution success
- single-input callers use the requirements-presence check, including when a
  validated result has an unfamiliar descriptive status; multi-input callers
  can report flags without rejecting an available partial combined result
- malformed result shapes and missing/non-boolean contribution flags fail at
  the SDK boundary rather than becoming valid partial results
- every .NET Policy Store JSON DTO is a `MxcJsonContext` source-generation root
  and uses `MxcJson`; `Microsoft.Mxc.Sdk.AotSmokeTest` exercises serialization
  and deserialization, including absent selection, retained failed selection,
  true and false contribution flags, and rejected missing/non-boolean flags
- lookup is command-free and returns only §4.2's allowed fields; reject old
  UI names and execution fields other than the optional timeout suggestion;
  leave `filesystem.clearPolicyOnExit` and `network.runtimeConfig` unset
  (`undefined`/`None`/`null`), despite their presence in the reused SDK types;
  reject those keys in catalog data even when their values are null
- Node resolution does not block the event loop; Rust/.NET preserve their
  corresponding idiomatic result/error types
- multiple input tools select one match each and compose their bases, selected
  intent additions, and dependencies; repeated inputs and shared components
  do not duplicate contributions
- two versions or intents of one entry share the default/platform base layers
  once, preserving distinct additions and per-input attribution; identical
  base fields do not create false unsupported-composition conflicts
- a known intent selects only its effective base and additions; omitted intent
  combines all effective intents, while unsupported intent contributes nothing
  with `intent_unsupported`
- omitted version selects default with `matched_default` and no version warning;
  a version in one range adds only that overlay with `matched_version`
- a valid version outside all ranges uses default with `version_out_of_range`;
  never select the nearest, highest, or broadest variant
- an unparseable version contributes nothing with `version_unparseable`;
  an out-of-range version plus a newer-only intent emits both warnings
- unparseable versions, unsupported intents, and unmatched tools skip that
  pair's dependencies and symbols while other pairs still resolve
- every input has an ordered status record; `tool_unmatched` never falls back
  to a wildcard entry; mixed requests return only contributing policies
- requirements-only and diagnostic APIs retain the same partial-result behavior;
  only the diagnostic API reports coverage, without a `requireAllMatches` option
- different tools in one request carry independent intents; two intents of
  the same tool share the base without losing either set of additions
- unselected intent dependencies and symbols are not resolved; selected
  intent dependencies participate in cycle detection and attribution
- shared and transitive dependency records retain the union of requesting
  `inputIndexes`, including successful resolutions that emit no warnings
- a dependency contributes only its default and applicable platform base
  additions, never a version overlay or intents, unless its reference names
  dependency intents; named intents are added with their platform additions
- known and unknown inputs compose the known requirements and report each
  unmatched input; empty and all-unmatched arrays return no policy, never an
  empty policy, while the diagnostic API preserves the resolution metadata
- omitted optional context fields use host platform and native system architecture, the
  installed catalog revision, no caller symbol overrides, and no weak-identity
  fallback
- `projectRoot` alone and `symbols.project_root` alone bind the same symbol;
  identical dual values are accepted and diagnosed as caller-supplied when used;
  differing strings fail with `malformed_request`/`invalid_context` before
  lookup, even with empty inputs or paths that refer to the same object
- an unresolved required symbol prevents policy output, with diagnostics,
  rather than silently omitting selected requirements
- caller symbol overrides precede discovery, which precedes documented
  defaults; only required symbols are resolved, with source/value diagnostics
- failed configuration reads are errors, not default selection; another
  target environment does not inherit this host's discovered paths
- context overrides do not provide remote/guest filesystem identity; only
  locally inspectable host-side sources can satisfy the required identity checks,
  and unavailable identity follows the existing per-input failure rules
- pinned catalog revisions retain their shared symbol definitions and defaults;
  unsupported default templates and executable discovery data are rejected
- package identity precedes invocation name, then declared intent specificity,
  then exact architecture over platform-only or common default;
  distinct matches tied at the highest rank produce `ambiguous_match`
- intent declaration may identify an entry before version selection, but a
  version lacking that intent still contributes nothing, not another entry
- multiple predicates matching the same entry contribute that policy once;
  file order does not change matching or composition
- string shorthand and object inputs obey the same weak-identity fallback
  option; intent selection does not bypass it
- invocation names compare case-insensitively on Windows/macOS and exactly on
  Linux, without changing command spelling or package-identity matching
- PURL type compares case-insensitively; namespace and name follow type-specific
  rules, independent of host OS; case-distinct Maven coordinates remain distinct
  and equivalent percent-encodings compare after parsing
- candidate PURL version/qualifiers/subpath are ignored with structured
  warnings; malformed components leave only that pair unmatched, with no
  invocation-name retry even when weak matching is enabled
- filesystem equality, de-duplication, and ancestor checks follow the actual
  case rules, including case-sensitive macOS volumes and Windows directories;
  unknown sensitivity preserves differently cased paths with a diagnostic
- exact-architecture additions precede platform-only additions; duplicate
  selectors are rejected; no matching overlay retains the common default
- on an ARM64 host with both architecture-specific variants and no neutral
  variant, omitted architecture selects ARM64; explicit x64 selects x64
- a library process running as x64 under emulation on an ARM64 host still
  defaults to the native ARM64 system architecture, not its process
  architecture
- a missing exact overlay falls back to the platform's neutral additions,
  otherwise to the common default; never use another architecture's overlay
- successful host-derived selection and neutral fallback produce the
  [API diagnostics](mxc-policy-store-api.md#warnings); host-architecture
  detection failure produces a library error, not a guessed match
- dependency chain resolution, including cycles (terminate, no duplication)
- filesystem floor composition ([§4.5](#45-dependencies-and-composition)):
  same-class de-duplication; equal read-only/read-write paths become read-write;
  read-write ancestors subsume read-only descendants, while read-only
  ancestors remain read-only outside required writable subtrees
- literal paths and distinct symbols that resolve to equal or nested paths
  follow the same lookup-time composition rules; catalog publication checks
  do not substitute for this runtime pass
- symlink, junction, hard-link, bind-mount, and 8.3 aliases use established
  target object identity in floor composition; the returned policy must not
  silently lose required writes to a more restrictive catalog alias
- same-object aliases preserve every required pathname; a read-write `/data`
  and read-only bind-mount alias `/alias` remain accessible through both names
  with the composed access, and same-class aliases are not collapsed
- unestablished necessary target identity fails closed for affected pairs,
  including dependency aliases, with structured diagnostics; unrelated
  resolved pairs still contribute and MXC enforcement is not weakened
- warnings for architecture, symbols, composition, removed denies, versions,
  intents, identity, and unmatched pairs have discriminated codes and required
  data fields; consumers read paths/rules and source entries without parsing
  messages
- catalog denies equal to, above, or below required read/write paths are
  removed; non-overlapping denies remain; warnings identify source entries,
  paths, access changes, and the full scope of removed parent denies
- overlaps within one entry, across matched inputs, and through dependencies
  behave identically; both APIs return equivalent composed policies, and
  entry/input traversal order does not change effective access
- a no-network tool does not veto another selected tool's network requirement;
  unselected version/platform/intent additions add no access; omitted intent
  selects all effective intents, while unsupported intent contributes nothing
- composed outbound rules retain destination/port pairings and exclusions;
  no network requirement means no grants, not unrestricted access
- a catalog egress deny rule overlapping another selected tool/intent's
  required allow rule is removed in full, within one entry or across entries,
  without failing the request; non-overlapping deny rules remain; warnings
  identify the rule, its full scope, and source entries
- a single network-requiring component retains its supported egress and ingress
  settings; components requiring no network do not introduce a network merge
- incompatible SDK target metadata and undefined cross-source composition,
  including unsupported non-default ingress merges, remain rejected rather
  than broadly approximated; this is not a blanket rejection of ingress
- a UI or timeout field from one deduplicated source is retained; omission in
  another source adds no value; distinct sources supplying that field fail with
  `policy_validation`/`composition_conflict`, for equal and unequal values alike
- clients may omit or override the suggested timeout in their final request;
  lookup does not start an execution timer or promise a minimum runtime
- symbol resolution on Windows, Linux, and macOS

**Data (CI)**

- every default and materialized platform/architecture/version/intent
  combination passes the closed catalog checks, typed v1 builder, semantic
  validation, and exact schema validation; no backend/probe is needed
- per-tool sources assemble deterministically across directories; duplicate
  entry IDs, dangling dependencies, and generated-source drift fail validation
- validation captures the exact request before normalization and never feeds
  the normalized restrictive copy back into floor composition
- a newer SDK exact target revalidates all bundled catalog revisions using
  its own schema; unchanged older-major-line revisions retain their IDs when
  revalidation passes, while unvalidated or cross-major data is not bundled
- catalog PURLs pass complete syntax/type validation before identity indexing;
  version, qualifiers, and subpath are rejected rather than silently ignored,
  including `pkg:npm/foo@1`, `pkg:npm/foo?arch=x64`, and `pkg:npm/foo#bin/cli.js`;
  `pkg:npm/foo` is an accepted predicate when otherwise valid
- exactly one unversioned default is required; missing/multiple defaults,
  version-only entries, and a version variant tagged as default are rejected
- version ranges use the entry's scheme and do not overlap, including at
  inclusive boundaries; adjacent non-overlapping ranges are accepted
- platform, version, and intent additions share the SDK target and cannot
  remove, narrow, or replace inherited requirements; defaults remain subsets
  of effective variants and inherited intent names are never deleted or renamed
- rendered effective policies and default-relative diffs include base/intent
  access and dependencies for reviewer inspection
- malformed VERS syntax, invalid constraints, and unsupported version types
  fail catalog validation; valid examples cover npm, semver, pypi, nuget, and
  intdot, including their scheme-specific version syntax
- metadata distinguishes default, platform, and version additions and lists
  intent names, subcommand hints, and dependencies without resolving policy bodies
- `dependencies[].entryId` references resolve within the same catalog revision;
  named dependency intents exist in every applicable platform combination
- no literal absolute user-specific paths; no wildcard filesystem/network grants
- catalog/entry revision monotonicity across a change

**Integration**

- each MXC SDK resolves through the shared Rust implementation with build-time
  embedded data; lookup performs no dynamic fetching or sandbox execution
- compiled consumer examples in all three languages pass both the direct
  result's fields and the diagnostic result's requirements fields into
  `ContainerRequest` with a caller-supplied command, without nested-type
  conversion, casts, or serialization
- the bundled catalog revision matches `getCatalogInfo()`; selecting an
  unavailable revision fails explicitly, without falling back to another
  revision
- an MXC SDK update leaves previously accepted consumer policies unchanged
- a representative tool that fails under a minimal consumer policy succeeds
  once its resolved entry is composed in
- the composed MXC policy realizes the documented read-only/read-write
  nesting without unnecessarily promoting a read-only parent to read-write;
  retained backend precedence does not reintroduce removed catalog conflicts
- the same tool still fails when the consumer's policy forbids what the entry
  requests (the floor never widens the consumer's ceiling)
- a caller-owned filesystem or egress deny still prevents access even when an
  overlapping catalog-provided deny was removed during floor composition
- floor alias reconciliation and MXC's final object-based normalization agree
  on required access; a resolver check never replaces enforcement-time checks

## 13. Open questions

| Maintainer sign-off | Recommended answer |
|---|---|
| Approve the command-free requirements API surface? | Review the [API spec](mxc-policy-store-api.md) before implementation, including inputs, results, errors, and partial-result behavior. |

## 14. Related work

- [`microsoft/mxc#779`](https://github.com/microsoft/mxc/pull/779) - Sandbox
  Config Floors feature spec. This document's data model, floor/policy
  direction argument, and identity-layering analysis build directly on it.
- [`ChazGo/mxc#1`](https://github.com/ChazGo/mxc/pull/1) - draft SDK resolver
  and catalog prototype exercising lookup, dependency closure, and symbol
  resolution against an earlier version of this shape.
- [Node v1 types](https://github.com/microsoft/mxc/blob/894f4c159705f5f470727e4fa1e363a2abec88f1/docs/reference/node/v1/types.md) -
  `ContainerRequest` and its access sections. Rust and .NET use their
  corresponding v1 SDK types.
- [Versioning design](development/architecture/versioning.md) - the versioning model
  [§4.1](#41-versions) builds on.
- [Package-URL VERS specification](https://github.com/package-url/vers-spec) -
  version-range syntax and supported version-type comparison references.
