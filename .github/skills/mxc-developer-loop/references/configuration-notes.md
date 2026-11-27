# MXC configuration rules

This file owns **loop-specific permission boundaries, configuration semantics,
and supporting evidence**. The execution/approval procedure is in
[processcontainer-loop.md](..\processcontainer-loop.md); setup and reference maintenance are in
[README.md](..\README.md). Consult the immutable [policy guide](policy-1.0.0.md)
and [schema](mxc-config.schema.1.0.0.json) for the full MXC contract and exact fields.

## Reviewer boundary versus MXC's full contract

This loop accepts 1.0.0 Windows ProcessContainer configurations. MXC supports
more settings than the helper can review; native acceptance does not authorize
a change outside the boundaries below.

| Candidate addition | Review boundary | `allowedChanges` field |
|---|---|---|
| Read-only/read-write paths | Additions within approved content scopes; covered generated children may be removed under the rules below | `readonlyPaths`, `readwritePaths` |
| Enumeration paths | Exact normalized scope matching, not recursive content roots; runtime support required | `enumeratePaths` |
| Named capability | Explicit non-reserved name with documented effects; no unresolved SID | `capabilities` |
| UI controls | Supported stable fields; preserve explicit initial restrictions and account for latent permissions | `ui` |
| Network egress rule | Canonical exact numeric `/32` or `/128` destination, exact TCP/UDP port or ICMP protocol | `networkEgress` |

Read-only additions may use approved read-only or read-write scopes; writes
require a read-write scope. Content-scope expansion requires a newly agreed
session. The other fields record agreed review scopes; a supported permission
outside those scopes must be explicit in the candidate approval. The review's
`withinScope` flag reports scope membership, **not authorization**. Every candidate
requires exact approval before activation, including in-scope grants and
removal-only consolidation. No field preapproves future candidates.

Execution settings, environment, backend, fallback, capture, learning mode,
least-privilege posture, network defaults/denies/exclusions, ingress, proxy,
lifecycle, and all other fields are immutable during the loop. Registry writes,
arbitrary COM/IPC policy, and unknown permission effects are not supported.
Extending the reviewer's supported fields requires deliberate implementation work,
not merely a new interpretation of a denial.

The supplied baseline is retained unchanged; its prepared copy binds the agreed
command/cwd and capture settings. The prepared baseline refuses DACL mutation
and permissive/legacy learning modes.
Without a supplied baseline, it starts with empty explicit content/capability
grants, default-deny network, and no `leastPrivilege` flag; ambient Windows/runtime
access still exists. A supplied `leastPrivilege` is preserved and may be unsupported
on the host. Content grants/scopes must not overlap results, and write grants/scopes
must not overlap the helper or native runtime.

## Permission reasoning

Correlate the failure location and relevant PID when available. A denial may be
incidental, handled by the application, or caused by another process. Distinguish
attempted access from required access, account for dependencies, and explain what
a proposed permission exposes beyond the failing operation. Report uncertainty
instead of assuming that a parsed setting or a passing probe proves necessity.

## Enumeration and filesystem scope

`processContainer.filesystem.enumeratePaths` permits path queries/directory
enumeration without file-content reads. It needs Windows BaseContainer PSEC
1.1 support, confirmed by `baseContainerSupportsEnumeratePaths: true` in the
probe, and cannot combine with `processContainer.leastPrivilege`.
Metadata queries are different from reading contents. An actionable `read`
label alone does not distinguish them: inspect the error and surrounding
execution context before choosing a permission.

Enumeration can expose names and metadata beyond approved content-read paths.
Do not describe it as permission for only one query. Do not assume identical
recursive behavior across filesystem backends or permission types. The upstream
Windows BaseContainer documentation explicitly says a volume-root
`readwritePaths` grant does not cascade to child folders. The enumeration
experiment below did not test volume-root read-only or read/write grants.
The helper refuses new drive-root content grants of either kind as a
conservative POC boundary, not as a claim about their runtime inheritance.

## Filesystem authoring rules

Apply these rules before submitting a candidate, not by rewriting saved
configuration or approval files. A smaller list is not necessarily a narrower
permission: removing children already covered by a broad parent does not
reduce that parent's reach.

Consider the complete candidate, including grants generated on earlier retries;
denial/log order must not determine which redundant entries survive. In a new
candidate, remove covered generated children using the bounded exception below.
Keep every initial-baseline entry, all explicit restrictions, and all historical
snapshots unchanged. The immutable prepared baseline (`baseline.json`), not the
most recent active policy, identifies which entries predate generated additions.

The basis column separates **runtime-tested** observations from **documented**
behavior, current **implementation** checks, and recommended **guidance**.
Implementation references identify the native writer, native parser, or helper;
they are not interchangeable descriptions of OS enforcement. Source locations
and the bounded runtime observation are recorded below.

| Rule | Expected behavior | Basis |
|---|---|---|
| Normalize comparisons | For accepted local Windows paths, compare case and trailing separators consistently. Require a directory boundary: `C:\data` does not cover `C:\database`. Do not normalize unsupported spellings into apparently safe grants. | Helper/native writer implementation |
| Remove equivalent duplicates | Include a normalized path/access entry only once. The helper rejects duplicates; it does not clean the candidate for the agent. | Helper/native writer implementation |
| Remove covered new children regardless of order | Where directory inheritance is established, a read-only parent covers child reads and a read/write parent covers child reads and writes. Remove redundant newly proposed children even when the independently justified parent appears later in the log. Check access type, volume-root exceptions, and explicit restrictions. Previously active children follow the narrower rule below. | Guidance; native writer only skips children when the parent is already present |
| Consolidate generated children across retries | A generated child absent from the initial baseline may be omitted from a new candidate when a retained or independently justified added parent is in the **same content-access list**. The helper requires a confirmed BaseContainer host, an existing ordinary non-root directory, strict descendant boundaries, no aliases, no overlapping denies, and no intervening different-access or enumeration grant. Unsupported coverage is rejected rather than inferred. | Helper implementation; documented BaseContainer directory inheritance; normal retest still required |
| Consolidate new same-path read/write grants | If newly proposed read-only and read/write grants name the same normalized path, retain only read/write when the write requirement is justified and within approved write scope. This does not authorize replacing an active or caller-supplied read-only entry, weakening a deny, or treating enumeration as content access. | Guidance; agent cleanup before helper review |
| Respect access differences | Read-only access does not satisfy a write requirement. Enumeration does not satisfy file-content reads or writes. Do not discard a requirement merely because the path appears in a different access list. | Documented; guidance |
| Do not broaden for compactness | Do not replace several file grants with their parent directory just to shorten JSON. The parent can expose unrelated siblings and needs its own justification and authorization. | Guidance |
| Keep existing-file writes narrow | For an existing target file, prefer that exact file over its containing directory when it satisfies the operation. Creating, renaming, or deleting a file may have additional requirements; see the qualified observations below. A file write does not itself establish a directory-wide requirement. | Native writer implementation; guidance |
| Treat volume roots separately | Do not use `C:\` as a universal covering parent. BaseContainer documents a non-cascading volume-root read/write exception; the helper rejects new volume-root content grants. Do not infer read-only root semantics from the enumeration result. | Documented; helper implementation |
| Describe enumeration breadth | On the tested host, parent enumeration, including `C:\`, covered descendant queries/listings but not file contents. Do not call it root-only access or permission for just one `lstat`; do not generalize the result to other hosts/backends. | Runtime-tested |
| Preserve explicit restrictions | Do not remove or relax denies. The helper rejects new grants overlapping a denied path in either direction, even where a backend might accept a parent allow with a child deny. | Helper implementation |
| Reject remaining same-path conflicts | After new-grant cleanup, do not leave the same path in multiple grant lists or assume the runtime chooses read/write. Native exact-string precedence is deny, then enumeration, then read-only, then read/write. The helper rejects conflicting normalized grant intents instead. | Native parser/helper implementation |
| Do not guess alias identity | Junctions, symlinks, short names, UNC paths, and ambiguous forms require separate review. Lexical prefix matching does not prove object identity; do not rewrite such paths to evade rejection. | Helper implementation; guidance |
| Preserve baseline and retained entries | Never remove caller/initial-baseline entries, replace an active read-only grant with read/write, or reorder/rewrite retained entries. Append new entries after retained ones. Only covered generated-child removal is an exception to append-only content changes; enumeration, capability, and network additions remain append-only. Report redundancy that cannot be safely consolidated. | Helper implementation; guidance |

Explain each removed child and its covering parent in the changed field's
reason, alongside the parent's independent justification if newly added. Show
the entire before/after diff. A removal-only candidate is allowed when a parent
already covers it, but only through the normal proposal workflow after a failed
run. Native validation and exact-candidate approval still precede the retest;
one decision can approve the change and one bounded rerun. Never simplify a successful snapshot after the fact or label
an untested simplified candidate as tested.

### Filesystem troubleshooting hints

These are **coworker-reported observations from the v3 bundle**, on one Windows
x64 BaseContainer host in November 2026, not universal platform guarantees or
observations independently rerun for this revision:

- An exact read/write grant for a nonexistent file did not permit its creation;
  a grant on the existing containing directory did. Establish whether the workload
  modifies an existing file or creates a new entry before proposing a grant.
  Directory access exposes siblings and needs its own justification and approved
  scope. Do not first add a read-only parent expecting to replace that active
  restriction with read/write in the same session.
- Some Windows PowerShell 5.1 file cmdlets, including `Remove-Item`, queried
  drive-root metadata despite content access to the target. Equivalent .NET APIs
  did not in those tests. Inspect actual errors and root read/unknown denials;
  do not infer a root requirement from the cmdlet name or add unrelated grants.
  Enumeration is not content access and can expose descendant names/metadata,
  not just one root query. It requires host support and the normal review/consent.

Use these hints to diagnose evidence, not automatically broaden permissions or
rewrite the agreed workload. A command/API change needs a newly agreed session.

### Bounded enumeration observation

A controlled four-case probe on 2026-11-01 used one Windows ARM64
BaseContainer host and the same inline Node command and working directory.
Only enumeration grants varied; generated files supplied content-read
negative controls. The fixture directories were outside the working directory.

| Enumeration grant | Queries and listings allowed | Generated file-content reads |
|---|---|---|
| None | None of the probed root/parent/child/grandchild paths | Blocked |
| Volume root only | Root, parent, child, grandchild | Blocked |
| Parent only | Parent, child, grandchild; not root | Blocked |
| Child only | Child, grandchild; not parent or root | Blocked |

Executor SHA-256:
`839a3d3648ace20a2ce2ef19f7a4668c7bab98b69e1b332b1e73c4a8a286d8be`.
The host probe reported `tier: "base-container"` and
`baseContainerSupportsEnumeratePaths: true`. The retained experiment record is
identified as `mxc-enumeration-inheritance`; its artifacts are not runtime
dependencies of this skill.

This establishes downward, not upward, enumeration inheritance for those
paths on that host. It does not test volume-root content grants, other
backends, alias behavior, or the minimum configuration for another workload.
Treat untested combinations as uncertain rather than borrowing this result.

### Native audit authoring versus runtime behavior

The native authoring code behind `--audit` normalizes file-path comparisons,
skips duplicate/already-covered additions, checks denied-path matches, and
emits exact-file write grants. It skips a child when a covering parent is
already present; it does not retroactively remove child entries when a parent
is added later. This is not order-independent configuration minimization.

Its coverage checks use lexical prefixes, including existing volume-root
entries, and its root-rejection comments describe whole-volume content
access. Those assumptions are not consistent with the documented
BaseContainer read/write root exception. Do not treat the writer as a
runtime specification or copy its coverage assumptions without checking
backend and access type. These are implementation notes, not an instruction
to run a permissive audit or change the helper's boundaries.

## UI and capability breadth

`allowedChanges.ui` accepts `win32k`, `clipboardRead`, `clipboardWrite`,
`inputInjection`, `externalUiObjects`, `globalUiNamespace`,
`desktopSystemControl`, `systemParameters`, `displaySettings`, and `ime`.
These names describe approval scope, not configuration fields or denial-to-setting
rules. Use the stable schema's field locations:

| Field | Effect |
|---|---|
| `ui.disable: false` | Allows Win32k calls; does not itself grant clipboard or input injection. Other configured UI permissions may become active. |
| `ui.clipboard` | `none`, `read`, `write`, or `all`; operation-class clipboard access. |
| `ui.injection: true` | Allows synthetic input, subject to other Windows checks. |
| `processContainer.ui.isolation` | `container`: private handles/atoms; `handles`: isolated handles, global atoms; `atoms`: external handles, isolated atoms; `desktop`: external handles/global atoms. |
| `processContainer.ui.desktopSystemControl: true` | Removes restrictions on both desktop management and logoff/shutdown. |
| `processContainer.ui.systemSettings` | `none`, `parameters`, `display`, or `all`. |
| `processContainer.ui.ime: true` | Permits IME use; other checks may still apply. |

Enabling Win32k can activate other UI permissions already present in the baseline.
The helper reviews those latent permissions too; listing `win32k` in the session
scope does not authorize activating them. Include their actual effects in the
exact-candidate approval.

Capability names are not per-resource allowlists. In particular, `registryRead`
is broad registry-read access, not a grant for one observed registry key.
Do not invent per-key registry fields or use unresolved SID strings as names.
Reserved learning capabilities and permissive capture are prohibited.

## Network scope

The [upstream network contract](policy-1.0.0.md#network-and-ui) explains
directional defaults, deny precedence, selectors, and proxies. The loop supports
only append-only, exact numeric egress allow rules; the rest of the network
configuration stays unchanged.

`allowedChanges.networkEgress` uses endpoint strings such as
`tcp://203.0.113.10:443`, `udp://[2001:db8::1]:53`,
`icmp://203.0.113.10`, or `icmpv6://[2001:db8::1]`.
These documentation addresses illustrate syntax, not suggested grants.

Each added rule must contain one destination (`/32` for IPv4 or `/128` for IPv6)
and one protocol selector, with an exact port for TCP/UDP and no port for ICMP.
Domain names, wildcard hosts, subnets, port ranges, and incomplete endpoints are
outside this loop's review boundary. Numeric network rules are not hostname or
URL filtering. Existing denies and allow-rule exclusions remain restrictions;
ingress/host-loopback enablement and proxy changes are not supported additions.

## Source notes

Upstream sources below were checked at the manifest's source revision.
Helper references describe the scripts bundled with these notes; the
runtime-tested observation has its separate scope and executor identity above.

- `docs\schema.md`: ProcessContainer enumeration, Windows BaseContainer
  volume-root read/write exception, and fallback policy.
- `docs\containment-policy\1.0.0\policy.md` and the stable schema: field
  definitions, network contract, and backend constraints; both are bundled here.
- `docs\backends\process-container\UIPolicy_Schema.md`: UI effect descriptions
  only; its draft field locations/examples are superseded by the stable schema.
- `src\mxc-sdk\src\core\mxc_common\config_parser.rs`:
  `normalize_filesystem_paths`, same-path precedence.
- `src\mxc-sdk\src\core\plm\config.rs`: `normalize_path`,
  `path_starts_with_any_norm`, `is_drive_root`, and
  `update_from_access_events`, native authoring and its coverage limitations.
- `scripts\candidates.cjs`: `normalized`, `within`, `noAliases`, `additions`, `contentAdditions`,
  `checkFilesystem`, `networkEndpoint`, `configuredUi`, and `reviewCandidate`,
  the POC's comparison, append-only/generated-child exception, alias, duplicate,
  conflict, scope, and permission-effect checks.
- `scripts\mxc-step.cjs`: `starter` and `prepare`, baseline preparation and
  request-scope checks.

These are reference notes, not an instruction to fetch the source checkout or
approve a permission.
