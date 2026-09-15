# Feature Spec: Sandbox Config Floors

**Status:** Proposed — design only, no implementation

---

## 1. Problem Statement

When an agent runs a tool inside a sandbox, it must know the minimum set of
filesystem paths, network endpoints, and child processes that tool requires in
order to function. Get it wrong and the tool fails — usually with an error that
does not name the missing permission.

The agent is the case that makes this unsolvable by enumeration: an LLM-driven
caller selects tools at runtime, so its requirements cannot be listed in advance.
The same gap exists for any embedder — a CI runner or an IDE hits it identically —
but only the agent case makes it structural rather than merely tedious.

This spec says **agent** where the agent is the point, and **host** for the
general process that configures and launches the sandbox. Where a statement holds
for both, it says host.

Today every host discovers this independently, by hand, through trial and error.
The knowledge ends up hardcoded in each host's source tree. It is duplicated,
drifts out of sync, and does not scale past a small hardcoded set of well-known
tools. A user who wants to run a tool nobody has profiled yet is on their own.

Two illustrative cases:

- A Node-based MCP server fails to launch under containment. The cause is that
  the global npm prefix directory is not mapped into the sandbox. Nothing in the
  failure output says so.
- A build invokes a package manager that shells out to a compiler toolchain. The
  compiler's own requirements are invisible at the point where the sandbox is
  configured, because only the top-level command was known.

Both are the same underlying gap: **there is no machine-readable description of
what a given tool minimally needs.**

This spec proposes that MXC carry that description as data, plus an API to
resolve it.

### Prior work in this repo

[#673 — *feat(policy): discover default-location dev-tool caches in
available_tools_policy*](https://github.com/microsoft/mxc/pull/673) proposed a
curated table of default-location developer-tool caches (cargo/rustup, go,
npm/pnpm/yarn/bun/deno and Node version managers, pyenv/pipx, Maven/Gradle,
.NET/NuGet, Ruby, Conan, node-gyp), merged into `available_tools_policy`
alongside the existing env-var and `PATH` discovery.

That PR established several things this spec adopts directly:

- **Credential-safe scoping** — grant build-input subdirectories, never tool-home
  roots, so `~/.cargo/credentials.toml`, `~/.npmrc`, `~/.m2/settings.xml`,
  `~/.gradle/gradle.properties`, and similar stay unreadable.
- **Read-only by default**, read-write only for scratch caches a build rewrites
  on every run.
- **Trusted home by construction** — resolve against the process's own home,
  never a caller- or command-env-controlled value, closing a symlink-redirect
  vector.
- **Pure discovery** — the discovery function performs no filesystem writes, so
  callers can inspect or serialize the result; materialization is a separate,
  explicit step.

It was not merged. This spec is a generalization of the same idea along three
axes: the table becomes standalone data rather than curated code, entries gain a
dependency graph so requirements compose transitively, and the data is
cross-platform rather than Unix-only (#673 deferred Windows to existing
`%LOCALAPPDATA%` env-var discovery).

The security properties above are not re-litigated here — they are treated as
settled and carried forward.

### Non-goals

- This does not change what the agent or the OS *enforces*. Enforcement semantics are
  unchanged, and enforcement remains the OS's job — a floor is an input to the
  request, never a step in the decision.
- This is not a trust or attestation mechanism. See §7.
- This does not attempt to describe what a tool is *permitted* to do. Floor data
  states need, not permission — but see §2.1, which covers what happens when a
  host chooses to answer the second question with the first.
- **This spec covers only floors distributed by this repository.** A floor is
  reviewed data with a known provenance and a version. Anything a host or agent
  derives at runtime for itself is a different object with a different warranty,
  and is out of scope. §5 describes how repository floors get *authored*; it does
  not describe host or agent behavior.

---

## 2. Concept: the config floor

**A config floor is a Policy.** Same type, same schema, same vocabulary — and
`getSandboxConfigForTool` returns one. It is not a new kind of object, and this
spec does not introduce one.

What distinguishes a floor is the **direction of the bound it expresses**.

A policy, as the term is normally used here, is an *upper* bound: it states the
most a tool is permitted to do, and the host is the authority. A floor is a
*lower* bound on the same axes, stated by the tool ecosystem rather than the
host. Read as a sentence from the tool:

> This is roughly the minimum I need. Run me with at least this and I will
> probably work. Run me with less and I will probably fail. You may give me more.

Both are claims about the same set of capabilities. They differ in who asserts
them and which way the inequality points:

|                       | Floor (lower bound)                 | Policy (upper bound)               |
| --------------------- | ----------------------------------- | ---------------------------------- |
| Asserts               | "less than this and I fail"          | "more than this is not permitted"  |
| Asserted by           | tool ecosystem                      | the host and its administrator     |
| Source                | observed/declared tool behavior     | operator, org, product decision    |
| Failure mode if wrong | tool breaks, or asks for too much   | security boundary is wrong         |

The two compose in the obvious way. Given a host policy `P` and a floor `F`, the
tool is expected to work when `F ⊆ P`. If `F ⊄ P`, the host learns *before
running* that the tool will probably fail, and on which capabilities — which is
strictly better than an opaque runtime error, and is most of the practical value
here.

What the host does with that knowledge is the host's decision: widen `P`, refuse
to run the tool, or run it anyway and accept the failure. **The resolver never
makes that decision and never modifies `P`.** It states a requirement; it does
not apply one.

This is what lets floors be community-authored data without weakening the
security model. A floor is an *assertion about need*, and a wrong or malicious
one can only overstate need — which surfaces as a tool that will not run under a
policy the host already chose. §2.1 covers the deployment where that separation
thins.

### 2.1 When a host uses a floor as its policy

Because a floor is a Policy, a host can simply *use* it as one — skip authoring
`P` and run the tool with `F`. Nothing prevents this, and the spec should say so
plainly rather than pretend the layering forbids it.

It is worth being precise about what that costs, because the intuitive answer is
wrong. Adopting `F` as `P` does not produce an over-permissive sandbox in the
usual sense: `F` is a *minimum*, so it is typically tighter than what a host would
hand-author, and far tighter than the common real-world alternative of no sandbox
at all. The failure mode is not excess capability. It is **misplaced authorship** —
the host has adopted a community contributor's estimate of need as its own
statement of permission, and those are different questions decided by different
people.

The practical consequence is that a wrong or malicious floor can only ever
*overstate* need, and a host that adopts floors wholesale inherits that overstatement
as granted authority. Two properties bound it:

- **A floor is only ever compared against, or intersected with, a host policy.**
  There is deliberately no `createConfigFromFloor()` convenience path. Adopting a
  floor as a policy requires the host to say so in its own code, which keeps the
  decision visible at review time rather than implied by an API shape.
- **A floor cannot exceed a policy the host actually authored.** Where `P` exists,
  composition is intersection, and no floor — including a hostile one — widens it.

So the honest claim is not "a floor is not a policy." It is:

> A floor states what a tool needs. A policy states what a host permits. They are
> the same type of object because they describe the same capabilities, and a host
> may choose to answer the second question with the first — but that is a choice
> the host makes and owns, not something the floor does.

§7 restates this as a documentation requirement.

---

## 3. Data Model

One entry per tool. An entry is an **envelope** that identifies the tool, wrapping
a verbatim `sandboxPolicy` that *is* an MXC `SandboxPolicy` — not a parallel
vocabulary that resembles one. Illustrative shape, not final schema:

```json
{
  "tool": "npm",
  "identity": [
    { "kind": "invocation-name", "names": ["npm", "npm.cmd", "npx", "npx.cmd"] }
  ],
  "requires": ["node"],
  "sandboxPolicy": {
    "version": "0.7.0-alpha",
    "filesystem": {
      "readonlyPaths": ["~/.npmrc", "${npm_prefix}", "./package.json"],
      "readwritePaths": ["./node_modules", "${npm_cache}"]
    },
    "network": {
      "allowOutbound": true,
      "allowedHosts": ["registry.npmjs.org"]
    }
  }
}
```

**Note what the example does not say.** `npm.cmd` is a batch script, so running it
spawns `cmd.exe`, which spawns `node.exe`. (Every shim in the list has this shape:
`npx` is `npx.cmd` on Windows too — which is why both spellings appear, and why
the Windows `cmd` dependency below is attributed to the launcher layer rather
than to `npm` itself.) None of that appears in the entry, for two different
reasons worth separating:

- **Child processes are not the inner Policy's vocabulary.** `SandboxPolicy` has
  no `process` or `spawn` field, and this spec does not propose adding one.
  Spawn requirements are a fact about *the tool*, not about the permissions a
  host grants it — so they belong in the envelope, alongside the other identity
  and dependency facts, and are expressed through `requires` (below).
- **The parts that *are* permissions belong to the tools that own them.** `npm`
  needs Node's paths — reached via `"requires": ["node"]` and the dependency
  closure, not restated inline.

The general rule: **spawn requirements live in the envelope, never in the inner
Policy.** The envelope describes what the tool *is* and what it *reaches for*;
the inner Policy describes what a host *permits*. Keeping them apart is what lets
the inner object stay a verbatim `SandboxPolicy`.

**Enterprise feed substitution.** `registry.npmjs.org` above is the default, and in
many enterprises it is blocked and replaced by an internal mirror. A floor that
hardcodes the public host is wrong for those hosts in the most damaging direction:
the tool fails, and it fails with a network denial that looks like the sandbox is
broken.

This is the same problem symbolic paths solve on the filesystem axis, and it wants
the same treatment — the floor should state *"the configured package registry"*,
with resolution to a concrete host happening at request time from local
configuration (`npm config get registry`, `NPM_CONFIG_REGISTRY`, `.npmrc`). The
floor asserts that npm needs to reach its registry; which registry that is, is a
property of the machine, not of npm.

The seed data should therefore prefer symbolic network endpoints wherever a tool
has a configurable one, and treat a literal host as a fallback for tools that
genuinely have a fixed endpoint. §9 tracks the open question of who owns that
symbol table and whether it extends to network endpoints as well as paths.

Notable properties:

**The inner object is not a new type.** It is whatever `SandboxPolicy` currently
is, embedded verbatim, carrying its own `version` field. When Policy gains a
field, floors can express it the day it ships — no change to this schema, no
re-specification, no lag. When Policy deprecates a field, floors inherit that
deprecation. A floor cannot express a capability MXC has no vocabulary for, which
is a feature: anything unrepresentable in Policy is unenforceable by the executor
anyway.

**Per-entry policy versioning.** Because the embedded object carries its own
`version`, entries authored against different Policy versions coexist in one
table. An entry pinned to `0.6.0-alpha` stays valid when the current version moves
on. This is the existing versioning design (`docs/versioning.md`) doing its job,
not a new mechanism.

**Validation is inherited.** Entries validate against the existing Policy schema.
CI needs no floor-specific validation logic for the inner object, and a malformed
floor fails the same way a malformed policy does.

**Composition.** A command line that invokes several tools resolves to the union
of their policies. `npm install && npm test` composes cleanly. Union is over
Policy objects using the SDK's existing merge semantics — not a floor-specific
rule.

**Dependency closure.** `requires` names other tools this one invokes — the
envelope's way of expressing spawn requirements. The effective floor is the
transitive union over that graph. This is what makes the compiler-toolchain case
above tractable: the caller does not need to know what the callee needs.

Entries in `requires` are *tool names*, resolved against the same table, not
image paths. `"node"` means "npm invokes the tool this table calls `node`," and
resolution to `node.exe` or `/usr/bin/node` happens per-machine at request time —
the same indirection symbolic paths provide on the filesystem axis. This is what
keeps the field portable: it is true on every platform, while the concrete
process tree is not.

A bare string is shorthand. The general form is an object, because a dependency
carries facts beyond its name — which **version** satisfies it, and **when** it
applies:

```json
{
  "tool": "npm",
  "requires": [
    { "tool": "node", "version": ">=22" },
    { "tool": "cmd", "when": { "platform": "windows", "via": ["npm.cmd", "npx.cmd"] } }
  ]
}
```

**Version constraints** matter because a floor is only accurate for the versions
it was observed against. Tool requirements move: a dependency that needed one
path in v18 may need two in v22, and an entry that silently applies to both is
wrong for one of them. Stating the range makes the entry's scope checkable
instead of assumed, and gives the resolver something to log when the installed
version falls outside it.

Semantics are deliberately weak. A version constraint is an **assertion about
need**, like everything else in a floor — not an installation requirement and not
a gate. If the installed `node` is v20 and the entry says `>=22`, the correct
behavior is to resolve the floor anyway and log that the entry may not
match. The tool might work fine. Refusing to run it would be the resolver making
a decision that belongs to the host, and floors do not make decisions.

The version question here and the one §9 raises about the symbolic table are
independent, but this one has an answer: a dependency's `version` is an assertion
about what the floor was observed against, on the same footing as every other
field in the entry.

**Platform-conditional dependencies** are where the `cmd.exe` case finally
becomes expressible. The shim is a real spawn requirement on Windows and
genuinely absent elsewhere, so the entry says exactly that rather than pretending
the tool is uniform across platforms or omitting the fact. The `via` field
records *why* the dependency exists — it is the `.cmd` launchers, not `npm`
itself, that pull in `cmd` — which ties the dependency back to the launcher layer
in §3.1. It lists every launcher that triggers it, since a tool may ship several.

Whether the resolver needs either form on day one is a seed-data question, not a
schema question — but the envelope has to be able to hold them.

What `requires` does **not** do is grant permission to spawn. It is an assertion
about need: it tells the resolver which other floors to union in, and tells a
host reading the entry which processes to expect. Whether spawning is permitted,
and how containment applies to children, remains the host's policy and the
executor's job — unchanged by this feature.

**Symbolic paths.** Floors reference well-known locations symbolically
(`${npm_prefix}`, `${npm_cache}`) rather than as literal absolute paths.
Resolution to concrete paths is done at request time, per-platform and
per-machine. This keeps entries portable across Windows and Linux and avoids
baking one user's layout into shared data. This is the one place the inner object
is not yet a literal `SandboxPolicy`: it is a `SandboxPolicy` whose path fields
may contain symbols, resolved to a plain one before use. §9 asks whether symbolic
paths belong in Policy itself.

**The symbol table is owned by this repository and extended by pull request.**
It starts from two sources, neither of which requires inventing a namespace:

- **The well-known folders the OS already defines** — `${localappdata}`,
  `${appdata}`, `${programdata}`, `${userprofile}`, `${temp}` and their platform
  equivalents. These are not this spec's invention; they are named by the
  platform and resolved through its folder API.
- **Per-ecosystem roots**, one per tool family — `${npm_prefix}`, `${npm_cache}`,
  `${cargo_home}`, and so on. #673 already curated most of this set for
  cargo/rustup, go, the Node package managers, pyenv/pipx, Maven/Gradle, NuGet,
  Ruby, and Conan; those entries carry over.

A symbol is admissible when it names a location a *tool ecosystem* defines and
resolves, rather than one a particular machine happens to use. Adding one is a PR
against the table, reviewed like any other entry. Naming an owner is deliberate:
"who decides what is well-known" is the question that otherwise stalls the
design, and the answer that keeps the data reviewable is the same repository that
reviews the floors.

**Backend neutrality.** The floor describes requirements in MXC's existing
Policy vocabulary. It does not mention any specific containment backend.
Translation to a backend is the executor's existing job and is unchanged by this
feature.

### 3.1 Identifying a tool

The entry above keys on an `identity` list whose only member is an
`invocation-name` predicate. That is the weakest form of identity, and it is the
form that is always available — this section explains why it is the default and
what can strengthen it. §3.2 then states the whole model as JSON Schema.

**Three things get called "the tool," and they are rarely the same object:**

| | Example (`npm` on Windows) | What it is |
| --- | --- | --- |
| **Invocation name** | `npm` | what the agent writes in a command line |
| **Launcher artifact** | `npm.cmd` on `PATH` | a shim script, resolved from the name |
| **Executing image** | `cmd.exe`, then `node.exe` | the process that actually runs |

`npm.cmd` is not an executable. It is a batch shim that invokes `node` against
`npm-cli.js`. On Linux the same name resolves to a symlink to a JavaScript file
with a shebang. In neither case does an image called "npm" ever exist.

This matters because the three layers want *different* predicates. Matching
signature or hash against the executing image identifies `node`, not npm — every
Node-based tool on the machine collides on one floor, and their union approaches
unrestricted. Matching the launcher artifact is precise but is a script, so
signature and package identity mostly do not apply to it.

This layering is already handled in a shipping schema.
[MCPB](https://github.com/modelcontextprotocol/mcpb/blob/main/MANIFEST.md)
(`manifest.json`, spec v0.3) never names an executable: it declares the runtime as
an enum, keeps the script (`entry_point`) separate from the launching image
(`mcp_config.command`), and attaches stronger identity additively in a namespaced
`_meta` block. Floors adopt that shape, with one divergence in scope — MCPB
describes tools shipping *as bundles*, where an author declares the runtime, while
floors must also cover a `winget` package, a distro package, or a tarball on
`PATH`, where nothing has been declared and the invocation name is all the agent
has. Floors therefore cannot require the declaration. The closing table below maps
the correspondence field by field.

So a floor entry keys on the **invocation name** — that is the only layer the
agent actually knows at request time — and treats stronger predicates as optional
refinements *on whichever layer can carry them*:

| Kind | Applies to | Example | Strength | Availability |
| --- | --- | --- | --- | --- |
| Invocation name | name as written | `npm` | weak — anything on `PATH` matches | always |
| Launcher path shape | resolved artifact | `<npm_prefix>/npm.cmd` | weak-to-moderate | when resolution is observable |
| Package identity | installed package | npm registry package, PackageFamilyName | strong | packaged installs only |
| Signature | executing image | publisher / cert thumbprint | strong | signed images only |
| Content hash | executing image or script | SHA-256 | strongest | always, brittle across versions |

An entry may carry several. The resolver matches on the strongest predicate the
candidate satisfies and logs which one — the first thing a maintainer needs when a
floor turns out to have matched the wrong tool. Name-only entries remain legal:
the long tail of dev tools is unsigned and unpackaged, and refusing them means
shipping a table that covers almost nothing.

**How lookup works.** The agent knows one thing at request time: the string it is
about to run. So resolution is always *name-first*, and stronger predicates are
checked afterward against the candidate the name produced:

1. **Index by invocation name.** The table is indexed on
   `identity[].kind == "invocation-name"` entries only. `npm` → candidate entry.
   This is the sole entry point, and it is why `invocation-name` must be present
   for any name-invocable tool.
2. **Resolve the name to an artifact.** `PATH` lookup yields
   `C:\Users\…\npm.cmd`. Now there is a file on disk to interrogate.
3. **Check the entry's remaining predicates against that artifact.** Hash the
   bytes, check the certificate, ask the package manager what owns the path. Each
   can fail, and a failure is informative.
4. **Log what matched.** Which predicate confirmed the tool, and on which layer.

The direction constrains what can be an identity kind at all: **a predicate must
be falsifiable against a local artifact.** Signatures, hashes, and package
identity all satisfy this. An identifier that names a *product* in an external
registry — with no record of it on disk and no local mapping from file to
identifier — does not, because confirming it would require the name-to-product
judgment the resolver cannot make.

Note what the layering does to the spoofing objection. A hostile `npm` earlier on
`PATH` matches the invocation name and receives npm's *requirements* — never npm's
authority, since floors are only intersected with a real policy (§2.1). The
stronger predicates do not fix this and are not claimed to; they reduce the chance
of applying the wrong floor to the wrong tool. This is a **precision** mechanism,
not a security boundary, and nothing about enforcement depends on it.

**Interpreted tools are the general case, not the exception.** Once the shim is
visible, `npm` is revealed to be the same shape as any Node or Python entry point:
a script plus an interpreter. The unit has to be the *script*, identified by its
package coordinates or path, with the interpreter as a `requires` edge:

```json
{
  "tool": "some-mcp-server",
  "identity": [
    { "kind": "npm-package", "name": "@vendor/some-mcp-server" }
  ],
  "requires": [
    { "tool": "node", "version": ">=16" }
  ]
}
```

A tool's runtime is stated once, as a `requires` entry. That entry carries a
version constraint, platform conditions, and a resolvable edge into the dependency
closure, and it describes a tool needing two runtimes by having two entries.

The script path is absent. What identifies the tool is its `identity` predicates;
where the entry point happens to live is a property of the install, resolved
per-machine like any other path, and not a fact a shared table should carry.

The borrowing from MCPB is therefore by *shape*, not field-for-field:

| MCPB | Floor equivalent |
| --- | --- |
| `server.type` (`node` \| `python` \| `binary`) | a `requires` entry naming that tool |
| `compatibility.runtimes` (`{"node": ">=16.0.0"}`) | that entry's `version` constraint |
| `server.entry_point` | not carried — `identity` identifies the tool |
| `_meta[...].package_family_name` | an `identity` predicate |

The principle worth borrowing is that runtime is **declared, never inferred** from
a file extension or a shim's name. A floor for an MCPB-packaged tool stays
derivable from its manifest mechanically: `type` plus `compatibility.runtimes`
becomes one `requires` entry with a version, and `_meta` package identity becomes
an `identity` predicate.

This composes with the dependency closure already described above: the script's
floor unions with the interpreter's, which is the correct answer — a Node-based
MCP server genuinely needs both Node's paths and its own. It is also exactly how
`npm` already resolves in the seed data (`npm` requires `node`), which is
reassuring: the shim case and the MCP-server case are one mechanism, not two.

It also means the agent must identify the tool it *intends* to run, not merely the
process it is about to spawn. `node dist/index.js` and `python -m foo` carry the
real identity in the arguments, not in the image name — and per the layer table
above, `npm` carries it in neither.

Open sub-questions, deliberately not resolved here:

- Whether ecosystem coordinates (npm package, PyPI distribution, cargo crate) are
  a distinct identity kind or a naming convention layered over `npm-package`.
- Whether a floor should ever bind to a *resolved* absolute path — precise on one
  machine, meaningless in shared data.
- Whether hash-based identity earns its version churn for anything beyond a small
  set of high-value tools.

What this spec commits to is that identity is **extensible**, so strengthening it
later does not require reissuing the table.

---

### 3.2 Full proposed schema

The complete proposal, as JSON Schema. Everything above is a reading of this.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://mxc.dev/schemas/config-floor/v1",
  "title": "MXC Config Floor Table",
  "type": "object",
  "required": ["schemaVersion", "entries"],
  "additionalProperties": false,
  "properties": {
    "schemaVersion": {
      "type": "string",
      "const": "1",
      "description": "Version of this floor-table schema. Distinct from the SandboxPolicy version carried per entry."
    },
    "entries": {
      "type": "array",
      "items": { "$ref": "#/$defs/entry" }
    }
  },
  "$defs": {
    "entry": {
      "type": "object",
      "required": ["tool", "identity", "sandboxPolicy"],
      "additionalProperties": false,
      "properties": {
        "tool": {
          "type": "string",
          "description": "Stable key for this entry. Referenced by other entries' requires[].tool. Not itself an identity claim."
        },
        "description": { "type": "string" },
        "identity": {
          "type": "array",
          "minItems": 1,
          "items": { "$ref": "#/$defs/identityPredicate" },
          "description": "How a candidate is recognized as this tool. An entry may carry several; the resolver matches on the strongest satisfied."
        },
        "requires": {
          "type": "array",
          "items": { "$ref": "#/$defs/dependency" },
          "default": [],
          "description": "Other tools this one invokes. Assertion of need, not a grant of permission to spawn."
        },
        "sandboxPolicy": { "$ref": "#/$defs/symbolicSandboxPolicy" }
      }
    },

    "identityPredicate": {
      "oneOf": [
        {
          "type": "object",
          "required": ["kind", "names"],
          "additionalProperties": false,
          "properties": {
            "kind": { "const": "invocation-name" },
            "names": {
              "type": "array",
              "minItems": 1,
              "items": { "type": "string" },
              "description": "Names as written on a command line, including platform launcher spellings (npm, npm.cmd)."
            }
          }
        },
        {
          "type": "object",
          "required": ["kind", "name"],
          "additionalProperties": false,
          "properties": {
            "kind": { "enum": ["npm-package", "pypi-distribution", "cargo-crate", "package-family-name"] },
            "name": { "type": "string" }
          }
        },

        {
          "type": "object",
          "required": ["kind"],
          "additionalProperties": false,
          "properties": {
            "kind": { "const": "signature" },
            "publisher": { "type": "string" },
            "thumbprint": { "type": "string" }
          },
          "anyOf": [
            { "required": ["publisher"] },
            { "required": ["thumbprint"] }
          ]
        },
        {
          "type": "object",
          "required": ["kind", "algorithm", "value"],
          "additionalProperties": false,
          "properties": {
            "kind": { "const": "content-hash" },
            "algorithm": { "const": "sha256" },
            "value": { "type": "string", "pattern": "^[a-f0-9]{64}$" }
          }
        }
      ]
    },

    "dependency": {
      "oneOf": [
        {
          "type": "string",
          "description": "Shorthand for { tool: <name> } with no constraints."
        },
        {
          "type": "object",
          "required": ["tool"],
          "additionalProperties": false,
          "properties": {
            "tool": {
              "type": "string",
              "description": "Another entry's tool key. Resolved against this table, never an image path."
            },
            "version": {
              "type": "string",
              "description": "Semver range the floor was observed against. Advisory: a mismatch is logged, never enforced."
            },
            "when": {
              "type": "object",
              "additionalProperties": false,
              "properties": {
                "platform": { "enum": ["windows", "linux", "macos"] },
                "via": {
                  "type": "array",
                  "items": { "type": "string" },
                  "description": "Launcher spellings that trigger this dependency, e.g. the .cmd shims that spawn cmd.exe."
                }
              }
            }
          }
        }
      ]
    },

    "symbolicSandboxPolicy": {
      "type": "object",
      "required": ["version"],
      "description": "An MXC SandboxPolicy whose path and host fields may contain ${symbols}, resolved per-machine before use. Field names and semantics are inherited from docs/sandbox-policy/v1/policy.md and are not redefined here; this spec adds only the symbol allowance. Validation is the Policy schema's job.",
      "properties": {
        "version": {
          "type": "string",
          "description": "SandboxPolicy schema version this entry was authored against. Per-entry, so entries pinned to different versions coexist."
        },
        "filesystem": {
          "type": "object",
          "properties": {
            "readonlyPaths": { "type": "array", "items": { "type": "string" } },
            "readwritePaths": { "type": "array", "items": { "type": "string" } },
            "deniedPaths": { "type": "array", "items": { "type": "string" } },
            "tempDir": { "enum": ["shared", "isolated"] }
          }
        },
        "network": {
          "type": "object",
          "properties": {
            "allowOutbound": { "type": "boolean" },
            "allowLocalNetwork": { "type": "boolean" },
            "allowedHosts": { "type": "array", "items": { "type": "string" } },
            "blockedHosts": { "type": "array", "items": { "type": "string" } }
          }
        },
        "ui": {
          "type": "object",
          "properties": {
            "allowWindows": { "type": "boolean" },
            "clipboard": { "enum": ["none", "read", "write", "readwrite"] },
            "allowInputInjection": { "type": "boolean" }
          }
        },
        "timeoutMs": { "type": "integer", "minimum": 0 }
      }
    }
  }
}
```

Four things in the schema are load-bearing and worth calling out, because each
encodes an argument made above rather than a formatting choice.

**`tool` is a key, not an identity claim.** It exists so `requires` has something
to reference. Recognition is entirely `identity`'s job, which is why `identity` is
required with `minItems: 1` — an entry that cannot be matched to anything is not
a usable entry.

**`sandboxPolicy` is described, not redefined.** The `$defs` entry restates
Policy's fields for readability, but the authority is
`docs/sandbox-policy/v1/policy.md`. An implementation should validate that object
against the real Policy schema for the `version` it declares, not against this
copy. Notably absent: `proxy`, which Policy supports but which is a deployment
decision rather than a tool requirement. Equally absent: any `process` or `spawn`
field — spawn requirements live in `requires`, in the envelope.

**`additionalProperties: false` everywhere except `symbolicSandboxPolicy`.** The
envelope is this spec's to close; the inner object must stay open so Policy can
gain fields without this schema blocking them. That asymmetry is the embedding
working as intended.

**Two independent version fields.** `schemaVersion` at the table level versions
the envelope; `sandboxPolicy.version` is per-entry and versions the Policy
dialect. They move on different clocks — conflating them would force a table
reissue every time Policy revved.

One deliberate omission: there is no `platform` field on the entry itself, only
inside `when`. A tool that needs genuinely different *policies* per platform — not
just different dependencies — has no way to say so here. Symbolic paths cover most
of that gap by resolving differently per platform. §9 tracks the remainder.

Platform variation belongs in a structured field rather than in the `tool` key.
`tool` is the referent for `requires`, so one key per tool keeps the dependency
graph single-rooted: an entry depending on `node` names it once, whatever the
platform. Variation expressed in structure also stays validatable, which a
convention encoded inside a string cannot be.

## 4. API Surface

The consumer-facing surface is a resolver in the TypeScript SDK
(`@microsoft/mxc-sdk`) and the Rust SDK, sitting *above* Policy:

```ts
getSandboxConfigForTool(
  tools: string[],
  ctx?: ResolveContext
): SandboxPolicy | undefined
```

The name says what it returns rather than naming the concept: callers reach for
"sandbox config for a tool," not for a "floor." *Floor* stays as the term for the
data and its semantics (§2), where the lower-bound meaning is load-bearing.

**Types.** Only one is new:

| Type | Origin | What it is |
| --- | --- | --- |
| `SandboxPolicy` | existing, `docs/sandbox-policy/v1/policy.md` | the return type. The same Policy object a caller already authors and already passes to `createConfigFromPolicy()`. Literal on return: symbols are resolved by the resolver. |
| `ContainerConfig` | existing | the backend-facing output of `createConfigFromPolicy()`. Never produced or consumed by this API — named only to state that it is unchanged. |
| `ResolveContext` | **new** | caller-known inputs and overrides. Optional. |

```ts
interface ResolveContext {
  /** Project root for `./`-relative paths. Defaults to cwd. */
  projectRoot?: string;
  /** Override individual symbols. Unset symbols are detected. */
  symbols?: Record<string, string>;
}
```

**There is no diagnostic channel in the API.** Identity strength and version
mismatch are worth *logging* — they are how a maintainer debugs a floor that
matched the wrong tool — but they are not worth a parameter, because nothing a
caller could do with them is safe. Refusing a floor on weak identity denies the
tool its requirements while leaving the host's policy untouched, so the tool
simply fails; and per §3.1 identity is a **precision** mechanism, not a security
boundary, so a stricter caller gains no containment by refusing. The resolver logs
what it observed. The return value is the answer.

**Resolution is the resolver's job, not the caller's.** Platform is not a
parameter: the SDK already knows what it is running on, and a caller passing a
platform it does not run on would select `when.platform` branches for a machine
whose paths cannot be resolved anyway. Symbols are likewise resolved internally,
because resolving them is not a lookup the caller can be expected to perform.

Symbols come from three different places, and only the first is an environment
variable:

| Symbol source | Example | How it resolves |
| --- | --- | --- |
| OS well-known folders | `${localappdata}` | environment variable, or the platform's folder API |
| Tool configuration | `${npm_prefix}`, `${npm_cache}`, the configured registry | the tool's own config chain — `npm config get`, `.npmrc`, `NPM_CONFIG_*` — where an environment variable is only one of several layers, and not the one that usually wins |
| Request-relative | `./package.json` | `projectRoot`, defaulting to cwd |

The middle row is why symbols cannot be reduced to environment variables. A user
who ran `npm config set prefix` has a prefix in `.npmrc` and no corresponding
variable in the environment; reading only the environment yields a default that
is wrong on exactly the machines that were configured deliberately. The
enterprise-registry case in §3 is the same shape: `NPM_CONFIG_REGISTRY` may be
absent while `.npmrc` names a mirror.

So `ResolveContext` carries only what the SDK genuinely cannot determine — which
directory counts as the project — plus an escape hatch for a caller that has
already resolved a symbol and wants that value used rather than re-derived.

"Policy" throughout this spec means `SandboxPolicy`; there is no separate
`SandboxConfig` type. The floor entry's inner `sandboxPolicy` is the same type
with symbols still unresolved (§3.2's `symbolicSandboxPolicy`), so the resolver's
job is: select entries, union them, resolve symbols, return a literal
`SandboxPolicy`.

The caller compares that against, or intersects it with, its own policy, and
passes the result to the existing `createConfigFromPolicy()`. No new path into
config generation, and no change to `SandboxPolicy` or `ContainerConfig` schema.

Both SDKs expose the same function. The Rust side matters more than parity: the
Rust SDK is where `SandboxPolicy` and the denial-capture input path (§5.1) live,
so floor authoring and floor consumption share a language.

Per the repo's feature flowchart this is therefore **SDK-library-only**: it adds
neither a cross-platform security restriction nor backend-specific
configuration. It is a helper that produces existing types.

### Defaults and omission

**When no tool has an entry, the function returns `undefined`, not an empty
Policy.** The two are not interchangeable. An empty `SandboxPolicy` is a
well-formed statement — *this tool requires nothing* — and a caller that
intersects with it, or adopts it as its policy per §2.1, gets a sandbox that
permits nothing. `undefined` says something different and correct: *this table has
nothing to say about this tool*. Absence of data and a claim of zero requirement
are distinct facts, and collapsing them puts the more dangerous reading one
misuse away.

The distinction is enforced by the type. A caller cannot accidentally intersect
with a floor that does not exist, because there is no object to intersect with;
the language makes them handle the case. That is the same reasoning §3.2 applies
to `additionalProperties: false` — make the wrong thing unrepresentable rather
than documented against.

When *some* tools match and others do not, the function returns the union of the
floors that did match. A tool with no entry contributes nothing, which is the same
result as a tool whose floor is empty — correctly, since neither asserts a
requirement. Only the all-unmatched case is distinguishable, and it is the one
that matters: `undefined` rather than a policy.

In every case the bound in §2 holds. The caller's policy is unchanged, and a tool
with no floor works or fails exactly as it does today. Adopting this feature can
make a previously-failing tool succeed; it can never make a previously-contained
tool less contained.

---

## 5. Authoring Pipeline

Hand-authoring floors for the long tail does not scale, and a manually curated
list will rot. The proposal is that floors be **produced by observation**, with
humans reviewing rather than writing.

**Scope note.** Everything in this section is a *contributor* workflow that runs
before a pull request. None of it is agent runtime behavior.

### 5.1 Denial capture (already exists)

This spec does **not** need to propose a discovery mechanism. Windows denial
capture already exists end to end in this repo:
`wxc_common::wire::CaptureDenials`, the `config_parser` mapping with its
`learningModeLogging` / `permissiveLearningMode` capability injection, the
BaseContainer runner, the ETL → JSON decode path, and `CaptureDenialsOutput` on
the SDK output side. [#748](https://github.com/microsoft/mxc/pull/748) adds the
remaining typed input path, exposing `captureDenials` on the Rust
`SandboxPolicy`.

When a sandboxed process is denied access, the runtime therefore already knows
precisely what was denied — and can already emit it as structured,
machine-readable output rather than an opaque process failure.

That is exactly the substrate floor authoring needs, and it means the authoring
pipeline is **a consumer of existing capability, not a new requirement.**

Two gaps remain, both out of scope here:

- **Windows only.** Seatbelt and Bubblewrap have no learning-mode API, so denial
  capture silently drops on Linux and macOS. Floors authored this way will be
  Windows-observed until those backends grow an equivalent; entries still need
  cross-platform review before they are treated as portable.
- **Denials are raw.** Capture reports the paths and endpoints a specific run
  touched. A floor is the *minimal generalized* requirement. Going from one to
  the other is a human judgement, made by the contributor before submission.

How a contributor gets from captured denials to a proposed entry is left to them.
The artifact this spec cares about is the result: a candidate floor, submitted as
a PR, reviewed by a human like any other change.

What the spec does commit to is the bound: **nothing widens a sandbox without a
human in the loop.** `getSandboxConfigForTool` reads reviewed, versioned data and
nothing else. A sandbox never widens itself in response to its own failures. Any
runtime inference a host may perform is outside this spec and composes with a
floor at the host's own discretion and risk.

### 5.2 Choosing the seed set

The initial table should be defined by a **selection rule, not a hand-picked
list**, so that what belongs in it stays answerable after the first release and
by people other than its authors.

The rule: **seed with the tools whose observed sandbox failures are
config-fixable, ranked by frequency × task-failure impact.**

Each clause does work:

- **Observed** — drawn from failures that actually happened, not from a guess
  about which tools matter. Any existing corpus of sandbox-related bug reports
  supplies this at no instrumentation cost.
- **Config-fixable** — the failure must be one a floor could have prevented. A
  tool that fails because the sandbox lacked a path it needed qualifies; a tool
  that fails because of a defect in the tool, or in the harness invoking it, does
  not. This judgement has to be made per report, and it is the step that keeps
  the table from accumulating entries that would not have helped.
- **Frequency × task-failure impact** — a tool that fails often but is trivially
  worked around ranks below one that fails rarely and blocks the task outright.

The same rule keeps the table current after seeding: denial capture (§5.1) is the
renewal mechanism, and self-declaration (§5.3) eventually removes the need to
rank at all, since a tool that ships its own floor is not competing for a slot.

### 5.3 Long-term: self-declaration

Eventually the tool itself is the right author of its own floor — declared in
installation metadata (package manifest, registry, install manifest) and
discovered rather than looked up in a central table. The repository-hosted table
is the bootstrap that makes the concept concrete and demonstrates value before
asking an ecosystem to adopt a declaration format. It is not the end state, and
the schema should be designed so entries can later be sourced from the tool
instead of the table.

---

## 6. Backward Compatibility

- No change to Policy.
- No change to ContainerConfig schema.
- No change to executor behavior.
- New SDK export; existing callers unaffected.
- Hosts that never call `getSandboxConfigForTool` see no behavioral difference.

Denial capture (§5.1) is pre-existing and separately gated; this spec does not
change it.

Given the schema is expected to move (§5.3), the resolver and floor data should
land under the experimental surface and be promoted per the repo's normal
promotion process once the shape has settled.

---

## 7. Trust Model

Floor data is **community-contributed, unsigned, and unwarranted.** It carries
no security guarantee and must not be treated as one.

This is safe because of §2: a floor is a hint used to construct a request, not a
grant of authority. A malicious or wrong floor can ask for anything; policy
still decides, and the enforcement boundary is untouched. The worst outcome from
bad floor data is a tool that fails to run, or a host that constructs a request
policy then rejects.

The documentation and the resolver's API docs should state this plainly:

> Config floors are community-contributed descriptions of what tools need in
> order to function. They are not security policy. They are not signed,
> reviewed, or warranted by Microsoft or by any contributor. Hosts must
> intersect floors with their own policy and must not treat a floor as an
> authorization decision.

Practical consequences:

- Contribution is open; review is for accuracy and minimality, not for security
  sign-off, because no security decision is delegated.
- No one is on the hook to maintain correctness for the long tail — a wrong or
  missing entry degrades to today's behavior.
- Hosts with stricter needs can ignore the table entirely, or pin/vendor a
  reviewed subset.

---

## 8. Test Plan

**Resolver (SDK unit tests)**

- single tool → expected Policy
- multiple tools → correct union of requirements
- `requires` chains → correct transitive closure
- cycles in `requires` → terminate, no duplication
- unknown tool → `undefined`, not an empty Policy
- known and unknown tools together → union of the known, no error
- symbolic path resolution on Windows and Linux
- floor ∩ restrictive policy → restrictive result (floor never widens)
- floor ⊄ host policy → host policy unmodified, tool fails as it does today

**Data (CI)**

- every entry validates against the schema
- `requires` references resolve
- no literal absolute user-specific paths
- no wildcard filesystem or network grants

**Integration**

- a representative tool that fails under a minimal policy succeeds when its
  resolved floor is composed in
- the same tool still fails when policy forbids what the floor requests

---

## 9. Open Questions

1. **Symbol expansion location.** Symbol resolution currently happens in the
   resolver, which means a floor's embedded object is a `SandboxPolicy` with
   symbols in its path fields rather than a literal one. Should symbolic paths
   move into Policy itself, so the embedding is exact? §3 settles *who owns the
   symbol table*; this is the separate question of *where symbols are expanded*.
2. **Per-platform policies.** `when` covers platform-conditional *dependencies*,
   but an entry carries exactly one `sandboxPolicy`. Symbolic paths absorb most
   per-platform variation by resolving differently per machine. Is that sufficient,
   or do some tools need genuinely different policies per platform?
3. **Standard identity vocabularies.** Should `identity` accept
   [purl](https://github.com/package-url/purl-spec) (`pkg:npm/npm`,
   `pkg:pypi/black`), which would subsume the `npm-package` / `pypi-distribution`
   / `cargo-crate` kinds into one standard scheme? purl satisfies the
   locally-checkable requirement — the package manager can be asked what owns a
   path.
