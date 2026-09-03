# MXC LXC Backend — State-Aware

The per-backend document required by §11.6 of the state-aware sandbox API
specification.  It declares what the LXC backend does at each lifecycle phase:
the config and metadata shapes, the cross-cutting policy honor matrix,
mode-specific fields, idempotence behavior, the concurrency story, and the
error mapping.

`docs/lxc-support/lxc-backend.md` describes the shipped implementation.  This
document declares the contract that implementation meets.

## Scope

### In scope

The five state-aware phases — provision, start, exec, stop, and deprovision —
as reached through `lxc-exec` with a state-aware request.

### Out of scope

One-shot execution, covered by `docs/lxc-support/lxc-backend.md`.  The
cross-backend policy semantics, covered by `docs/sandbox-policy/0.8.0/`.

## Schema version floor

State-aware requires a `schema_version` of at least `0.8.0`.  A request below
that floor is refused before any phase runs, and the sandbox is never created.
One-shot execution has no such floor and continues to accept `0.7.0`.

The floor exists because LXC's state-aware support missed the 0.7.0 cutoff.

## Experimental opt-in

The LXC state-aware lifecycle is experimental.  Every call to a lifecycle phase must pass `--experimental` to `lxc-exec`.  Without it every phase is refused with `backend_unavailable` before any container is touched.  One-shot execution has no such requirement.

## Per-phase config and metadata shapes

### Provision

**Config — `LxcConfig`.** Both fields are required.

| Field | Type | Meaning |
|---|---|---|
| `distribution` | string | Linux distribution for the container rootfs, for example `alpine` or `ubuntu`. |
| `release` | string | Distribution release version, for example `3.20` or `24.04`. |

**Metadata — `LxcProvisionMetadata`.**

| Field | Type | Meaning |
|---|---|---|
| `containerName` | string | The LXC container name backing this sandbox. |
| `created` | bool | True when this call created the container, false when it adopted an existing one. |

#### The `sandboxId` format

Provision returns `lxc:<containerName>`.  Every later phase parses that form
and rejects anything else as `malformed_id` — a missing or foreign prefix, an
empty name, or a name longer than the LXC limit.

### Start

**Config — none.**  Start is the only phase that accepts cross-cutting policy;
see the honor matrix below.

**Metadata — none.**

### Exec

**Config — the process fields of the request**, matching one-shot execution.

**Metadata — none.**  LXC relays the sandbox's output to this process's own
stdout and stderr rather than handing back pipes.  The returned handle carries
null stream handles and a waiter holding the exit code.

An in-process caller that needs the streams back is refused up front, before
the workload runs, because a later refusal would describe output that has
already gone somewhere the caller never asked for.

### Stop

**Config — none.  Metadata — none.**

### Deprovision

**Config — none.  Metadata — none.**

## Cross-cutting policy honor matrix

Per §10.3.  LXC applies filesystem and network policy at start and refuses it
everywhere else.

| Field | provision | start | exec | stop | deprovision |
|---|---|---|---|---|---|
| `filesystem` | `policy_validation` | applied | `policy_validation` | `policy_validation` | `policy_validation` |
| `network` | `policy_validation` | applied | `policy_validation` | `policy_validation` | `policy_validation` |
| `ui` | ignored | ignored | ignored | ignored | ignored |

The two fields differ on an empty block.  A `network` block that is present
but sets nothing is refused — the check reads the "was a network section
supplied" bit, not the fields inside it.  A `filesystem` block that is present
but lists no paths is **not** refused; the check reads only whether a path
list is non-empty, and an empty block is indistinguishable from an absent one.

A request that carries no policy at all passes every phase.

The rejection is deliberate rather than incidental.  A container's filesystem
mounts and firewall rules are installed when it starts, and a caller that
passed them to stop or exec would receive a silent no-op instead of the
isolation they asked for.

## Mode-specific fields

### `containerId`, state-aware provision only

LXC accepts an optional `containerId` at provision, naming the container to
adopt instead of minting a fresh name.  This is the exception to the rule in
`mxc-state-aware-sandbox-api-overview.md` that neither request shape carries
a container identifier, and it is called out in the specification at §6.1.

When `containerId` names an existing container, provision adopts it and
returns `created: false`.  When it names one that does not exist, provision
creates it under that name and returns `created: true`.

## Idempotence per phase

| Phase | Repeated call | Notes |
|---|---|---|
| provision | non-idempotent without `containerId` | Each call mints a fresh container name.  With `containerId`, a repeated call adopts the container the first one created and reports `created: false`. |
| start | `already_started` | A second start against a running container is refused. |
| exec | per-call | Each exec runs the command again.  There is no deduplication. |
| stop | `already_stopped` | A stop against a container that is not running is refused, whether it was never started or has already been stopped. |
| deprovision | idempotent success | A second deprovision against a destroyed sandbox exits 0. |

### Why stop reports one code for two histories

LXC answers "is this container running" with a single probe, and that probe
cannot distinguish a container that was never started from one that ran and
has since stopped.  Reporting one code for one observable state keeps the
answer honest.  `not_started` is reserved for exec, the only other phase that
needs a running container.  Each code is emitted by exactly one phase.

### Why deprovision is the one idempotent phase

Deprovision runs the authoritative network teardown whether or not the
container still exists.  A caller that retries after a failure partway through
teardown has to be able to reach that cleanup a second time.  Every other
phase reports `stale_id` against a destroyed sandbox, provided the request
carries nothing that fails earlier — see Precedence.

### Stopping a container also tears down its network

A container that exits on its own leaves the current start's iptables rules on
the host.  Stop removes them on both paths — before returning success for a
container it stopped, and before returning `already_stopped` for one that was
already down.  A refusal never leaves host state behind.

## Concurrency

### Multiple sandboxes

Distinct `sandboxId`s name distinct LXC containers, and their lifecycle locks
are independent.  Their firewall chains are not guaranteed independent; see
Known issues.

### The same sandbox

Provision, start, stop, and deprovision take a lifecycle lock keyed on the
container name.  Concurrent calls against one sandbox serialize rather than
interleave, and the second caller observes the state the first one left.

### Concurrent exec calls

Exec does not take the lifecycle lock.  Two execs against one sandbox run
concurrently inside the same container, and MXC does not order them.  A caller
that needs them ordered has to sequence them itself.

## Error mapping

LXC emits nine of the twelve codes in the specification's closed union.

| Observable condition | Wire `error.code` | Trigger |
|---|---|---|
| Caller did not pass `--experimental` | `backend_unavailable` | The state-aware lifecycle is experimental.  Reported by all five phases before any container is touched. |
| Provision config missing or incomplete | `malformed_request` | No `experimental.lxc.provision` block, or an empty `distribution` or `release`. |
| The `sandboxId` does not parse | `malformed_id` | Missing or foreign prefix, empty name, a name over 20 characters, or a character outside ASCII alphanumerics, `-`, and `_`.  Detected before any container is touched. |
| The id parses, the container does not exist | `stale_id` | The sandbox was deprovisioned, or the container was destroyed out of band.  Reported by start, exec, and stop. |
| The container exists but is not running, at exec | `not_started` | Exec needs a running container. |
| The container is already running, at start | `already_started` | |
| The container is not running, at stop | `already_stopped` | See the idempotence table. |
| A phase received policy it does not accept | `policy_validation` | See the honor matrix.  Also covers a network policy LXC cannot enforce on this host. |
| A container state probe could not be read | `backend_error` | LXC could not answer whether the container exists or is running.  An unreadable probe is never treated as "gone" or "stopped".  Also returned when an in-process caller asks exec for the sandbox's streams, which LXC cannot hand back. |
| The `lxc-*` tools are absent from the host | `backend_unavailable` | LXC drives every phase by spawning those tools.  Reported by all five phases before any container is touched, which separates a machine without LXC installed from a container operation that failed. |

### Precedence

Every phase runs in two stages, and the first stage never touches the
container.  Validation checks the provision config shape, parses the
`sandboxId`, and rejects policy the phase does not accept.  Only then does the
phase itself acquire the lifecycle lock and probe the container.

What follows from that split is the part callers can rely on:

- `malformed_request`, `malformed_id`, and a *phase-acceptance*
  `policy_validation` are reported before any state code.  An exec, stop, or
  deprovision against a destroyed sandbox that also carries rejected policy
  reports `policy_validation`, not `stale_id`.
- Within the second stage there is no single ordering.  The lifecycle lock is
  taken before the existence probe, and failing to take it reports
  `backend_error`.  Start applies filesystem policy after its existence and
  running probes, and a failure there also reports `policy_validation`.

`policy_validation` and `backend_error` each have two arrival points, one in
each stage.  Neither code identifies which stage produced it; the message
does.

### The remaining three codes

None of these is emitted by LXC backend code.  Two of the three still reach a
caller of `lxc-exec`, because shared routing decides them before any backend is
chosen.

**`not_provisioned` is unreachable.**  The specification reserves it for a
sandbox whose id is recognized but whose resources have not been created.  LXC
has no such state — `lxc-create` runs during provision, and the container is
defined from the moment an id exists.  Every condition that would reach
`not_provisioned` on another backend reaches `stale_id` here.

**`unsupported_containment` answers a sandbox id naming no known backend.**
Shared routing returns it for a prefix with no entry in the lookup table, which
is the outcome the specification assigns to a direct wire call.  An id carrying
the `lxc` prefix routes to this backend instead.

**`unsupported_phase` comes from shared dispatch**, above the backend, never
from LXC code.  A caller reaches it by naming a backend that has no state-aware
lifecycle on this host.

## Known issues

### Firewall chain names are not guaranteed unique

A container's iptables chain name is derived from its container name through a
non-cryptographic hash.  That derivation is not injective, and a caller that
chooses `containerId` can construct two names that land on one chain.  When
that happens, one sandbox's stop or deprovision tears down the other's rules,
leaving a running container with no firewall.

The name length limit and character set narrow the input set; they do not make
the derivation injective.  The durable fix is persisted chain ownership
verified before any flush or delete.  Tracked in AB#62953349.

## References

- `docs/state-aware-lifecycle/mxc-state-aware-sandbox-api.md` — the
  specification this document declares against.
- `docs/lxc-support/lxc-backend.md` — the shipped LXC implementation.
- `docs/sandbox-policy/0.8.0/` — the cross-backend policy contract.
- `tests/scripts/run_lxc_state_aware_phase_ordering_test.sh` — the phase
  ordering and error codes above.
- `tests/scripts/run_lxc_state_aware_network_test.sh` — the honor matrix.
- `tests/scripts/run_lxc_state_aware_version_floor_test.sh` — the schema
  version floor.
- `tests/scripts/run_lxc_state_aware_routing_test.sh` — the refusals decided
  from the sandbox id alone, the missing runtime dependency, and the envelope
  discipline stdout has to keep.
- `tests/scripts/run_lxc_state_aware_adopt_test.sh` — the identifier form and
  adopt-or-create.
