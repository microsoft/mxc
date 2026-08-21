# Bubblewrap Backend

The Bubblewrap backend provides **unprivileged Linux sandboxing** using
[Bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`). It uses
Linux user namespaces to create isolated sandbox environments without
requiring root privileges or a container runtime.

> **Status:** Experimental — requires the `--experimental` CLI flag.

## Prerequisites

- **Linux** host with kernel 3.8+ (user namespace support)
- **Bubblewrap** installed and on PATH:
  ```bash
  # Debian/Ubuntu
  sudo apt install bubblewrap

  # Fedora/RHEL
  sudo dnf install bubblewrap

  # Alpine
  apk add bubblewrap
  ```
  The deny-by-default baseline (see [How It Works](#how-it-works)) emits its
  read-only mounts via `--ro-bind-try` (bwrap 0.3.1+) and the sandbox
  environment is built with `--clearenv` (bwrap 0.5.0+), so **bwrap 0.5.0 or
  newer** is required. Platform detection probes `bwrap --version` and reports
  the backend as unavailable — with the detected version — when the host is
  below that floor.
- **Schema 0.8 private-namespace modes:** `slirp4netns` installed and on PATH,
  plus `nsenter`, `iptables`, `ip6tables`, `iptables-restore`, and
  `ip6tables-restore` for the in-namespace egress and ingress rules, and the
  `nf_conntrack` kernel module loaded for the inbound chain's connection-state
  match (unprivileged Bubblewrap cannot load it on demand).

  This covers **both** 0.8 modes that get a private network namespace —
  `network.proxy` (proxy-only egress) *and* `network.enforcementMode:
  "firewall"` with host lists — because `validate` runs the same dependency
  probe for each, and both render the same two chains. None are required when
  the request resolves to neither mode (no proxy and no enforced host lists),
  or when a 0.6/0.7 policy uses the legacy proxy behavior.

  > `ip6tables` is required to *deny* IPv6, not to carry it. slirp4netns is
  > launched without `--enable-ipv6`, so the sandbox namespace has no IPv6
  > connectivity at all and the v6 rules exist to keep the unmatched family
  > closed. An IPv6 destination is unreachable even when a rule allows it
  > (see #955).
  ```bash
  # Debian/Ubuntu
  sudo apt install slirp4netns util-linux iptables

  # Fedora/RHEL
  sudo dnf install slirp4netns util-linux iptables

  # Alpine
  apk add slirp4netns util-linux iptables
  ```
  `iptables` must resolve to the **`nf_tables` backend** (the default on
  Debian 10+, Ubuntu 20.10+, RHEL 8+, and Alpine). The legacy backend opens
  `/run/xtables.lock` before touching any table, and the rules are installed by
  an unprivileged supervisor that keeps the caller's uid — so on a stock host,
  where `/run` is root-owned, it cannot take that lock. `validate` refuses such
  a host with a message naming the backend, rather than letting the supervisor
  die at the first rule. If a host is pinned to legacy, switch it:
  ```bash
  sudo update-alternatives --set iptables /usr/sbin/iptables-nft
  sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-nft
  ```
  (A legacy backend is still accepted where the lock *is* writable — for
  example when running as root — since it works there.)
  Both modes fail explicitly if any of these is unavailable; neither ever falls
  back to sharing the host network namespace or to running without egress
  rules. The host must also provide the util-linux `unshare` command with
  `--map-current-user` and `--keep-caps`. No root is needed: `iptables` runs
  against the sandbox's own network namespace, where the supervisor holds
  `CAP_NET_ADMIN`.
- User namespaces must be enabled:
  ```bash
  # Check: should print "1"
  cat /proc/sys/kernel/unprivileged_userns_clone
  ```

## Quick Start

```json
{
  "version": "0.6.0-alpha",
  "containment": "bubblewrap",
  "process": {
    "commandLine": "echo 'Hello from Bubblewrap sandbox'"
  }
}
```

Run with:
```bash
lxc-exec --experimental --config bubblewrap_hello.json
```

Or via base64:
```bash
lxc-exec --experimental --config-base64 "$(base64 -w0 bubblewrap_hello.json)"
```

## How It Works

Bubblewrap creates a namespace-isolated process by:

1. Unsharing user, PID, IPC, and UTS namespaces (`--unshare-*`)
2. Bind-mounting a **minimal deny-by-default baseline** read-only into the
   sandbox (`/bin`, `/sbin`, `/lib*`, `/usr/bin`, `/usr/sbin`, `/usr/lib*`,
   `/usr/libexec`, `/usr/share`, `/etc`, plus DNS stub-resolver dirs
   under `/run`). Everything else on the host — including the caller's
   `$HOME`, `/root`, `/opt`, `/var`, `/sys`, and `/run/user/<uid>` — is
   invisible inside the sandbox.
3. Layering filesystem policy overrides (read-write, read-only, denied paths)
4. Setting up minimal `/dev`, `/proc`, and `/tmp`
5. Clearing the environment and applying only requested variables
6. Executing the command via `sh -c`

The sandboxed process runs as a child of `bwrap` and dies automatically when
execution completes — no container lifecycle management required.

### Deny-by-default filesystem

The baseline mirrors the macOS Seatbelt backend's `(deny default)` posture:
the sandbox can read the dynamic linker, libc, system tools, and system
configuration — and **nothing else** — until the caller opts in via
`readonlyPaths` / `readwritePaths`. To make a host directory visible inside
the sandbox, list it explicitly:

```json
{
  "filesystem": {
    "readonlyPaths": ["/home/alice/project", "/usr/local"],
    "readwritePaths": ["/tmp/workspace"]
  }
}
```

Common consequences of this default:

- `$HOME` (e.g. `~/.aws/credentials`, `~/.ssh/id_*`, browser cookies) is
  not readable from the sandbox.
- `/opt` and `/usr/local` tooling is not on PATH; list either path under
  `readonlyPaths` if the script depends on it.
- `working_directory` must live under the baseline or a policy path — a
  `cwd` of `~/project` without a matching `readonlyPaths` entry will fail.
- DNS works on systemd-resolved, NetworkManager, and resolvconf hosts
  because the corresponding `/run/...` directories are bound. The common
  symlink targets *outside* `/run` are covered too: `/var/run/...`-routed
  `/etc/resolv.conf` symlinks resolve via a synthesised `/var/run -> /run`
  compat symlink, and WSL's `/mnt/wsl/resolv.conf` is bound directly.
  Neither exposes host `/var` or `/mnt` contents. Hosts that point
  `/etc/resolv.conf` at some other custom location still need that target
  listed in `readonlyPaths`.

Files in `/etc` that contain secrets (`/etc/shadow`, `/etc/sudoers`,
`/etc/ssh/ssh_host_*_key`) are mode `0400` / `0640` `root` and remain
unreadable to a non-root caller — user-namespace UID mapping does not
bypass kernel DAC.

## Configuration

Bubblewrap uses the shared cross-backend configuration fields. No
backend-specific config block is needed.

### Filesystem Policy

| Field | bwrap Mapping | Description |
|-------|---------------|-------------|
| `readwritePaths` | `--bind <path> <path>` | Read-write bind mount (overrides base RO) |
| `readonlyPaths` | `--ro-bind <path> <path>` | Explicit read-only bind mount |
| `deniedPaths` (directory) | `--tmpfs <path>` | Masked with an empty tmpfs |
| `deniedPaths` (file) | `--ro-bind /dev/null <path>` | Masked with `/dev/null` (a tmpfs would turn the file into a directory) |

A denied path is classified by its own on-disk type (via `symlink_metadata`,
no symlink-follow): a directory is masked with an empty `--tmpfs`, while a
regular file is masked by binding `/dev/null` over it (masking a file with a
tmpfs would replace it with an empty *directory*, changing its type). Paths that
cannot be stat'd (missing/unreadable) fall back to `--tmpfs`.

**Denied paths are resolved through symlinks before masking.** bwrap creates a
mask by mounting over the destination path, and it cannot create a mount point
when **any** component of that path — the leaf itself *or* an ancestor directory
— is a pre-existing host symlink whose parent is bound into the sandbox (the
mount then resolves through the host symlink and fails with `ENOENT`, aborting
the sandbox). So both `/a/link` (symlinked leaf) and `/a/link/secret` (symlinked
ancestor) would abort. A `deniedPaths` entry is therefore rewritten to its real
filesystem path before mounting — canonicalizing the deepest existing ancestor
(following symlinks at every level) and re-appending any not-yet-created trailing
components — so the mask lands on the real object and its file/directory type is
classified from that target. Fully unresolvable paths are left as-is — there is
nothing behind them to leak.

Example:
```json
{
  "version": "0.6.0-alpha",
  "containment": "bubblewrap",
  "process": {
    "commandLine": "cat /data/input.txt && echo result > /workspace/output.txt"
  },
  "filesystem": {
    "readonlyPaths": ["/data"],
    "readwritePaths": ["/workspace"],
    "deniedPaths": ["/secrets"]
  }
}
```

### Network Policy

Bubblewrap supports two network modes:

**Full block** (`defaultPolicy: "block"`, no host lists, no `network.proxy`)
— uses `--unshare-net` for complete network namespace isolation. The sandbox
gets a private network stack with only its own loopback (bwrap brings `lo`
up), so nothing outside the sandbox is reachable and nothing outside can
reach in. Runs fully unprivileged.

```json
{
  "network": {
    "defaultPolicy": "block"
  }
}
```

**Per-host filtering** (`allowedHosts`/`blockedHosts`) — the behavior
depends on the schema version, because 0.8 replaced a path that did not
actually filter.

**Schema 0.8+ — enforced.** `enforcementMode: "firewall"` puts the sandbox in
the same private, slirp-backed network namespace proxy mode uses, and programs
the rules into *that* namespace from a supervisor holding `CAP_NET_ADMIN`
inside an unprivileged user namespace. **No root required**, and the sandbox
cannot undo the rules: it drops `CAP_NET_ADMIN` before the workload starts.

Rule addresses must be **IP literals or CIDR blocks**; a DNS name is rejected
at validation time rather than resolved on the caller's behalf. The backend
does not resolve, because the sandbox resolves names itself and a lookup that
disagreed with the one behind the rules would hand the workload an address the
chain never authorized. An IPv6 rule programs `ip6tables`, but the sandbox's
namespace has no IPv6 connectivity today — slirp4netns is launched without
`--enable-ipv6` — so an allowed IPv6 destination stays unreachable regardless
of the rule (see #955). The terminal verdict of the unmatched family still
follows `defaultPolicy`, so a v4-only allowlist under `block` does not leave
IPv6 open.

An IPv4-mapped address such as `::ffff:203.0.113.5` is programmed as IPv4:
Linux puts a genuine IPv4 packet on the wire for one, so an `ip6tables` rule
naming it would never match and a `blockedHosts` entry under `defaultPolicy:
allow` would fail open. A mapped CIDR is translated the same way — the mapped
range is the last 32 bits of `::ffff:0:0/96`, so a `/96 + n` prefix becomes a
v4 `/n`.

An IPv6 block **shorter** than `/96` that contains `::ffff:0:0/96` is
**rejected** rather than programmed. CIDR blocks nest or are disjoint, so such a
block always swallows the mapped range whole, and neither available reading is
safe to apply silently: leaving it on `ip6tables` unenforces the mapped half
(the same fail-open the translation above exists to prevent), while projecting
it onto IPv4 would always widen it to `0.0.0.0/0` — turning `blockedHosts:
["::/0"]` from "block all IPv6" into "block all IPv4 as well". The rejection
asks the caller to write the IPv4 side explicitly. Blocks that do not contain
the mapped range, such as `2001:db8::/32`, are unaffected.

> **Divergence from LXC.** LXC normalizes mapped literals and `/96`-or-longer
> mapped CIDRs the same way, so those policies mean the same thing on both
> backends. It does **not** yet reject the shorter straddling blocks — there,
> such a rule stays on `ip6tables` and its mapped half goes unenforced. Until
> LXC adopts the same check, a policy using one of those blocks is the one case
> where the two backends differ.

An explicit `blockedHosts` entry outranks any `allowedHosts` entry that covers
it, including a broader CIDR: denies are installed ahead of allows in a
first-match chain.

```json
{
  "network": {
    "defaultPolicy": "block",
    "enforcementMode": "firewall",
    "allowedHosts": ["10.0.2.2/32", "203.0.113.0/24"],
    "blockedHosts": ["10.0.2.2"]
  }
}
```

**Schema 0.7 and earlier — accepted but not enforced.** The legacy path shares
the host network namespace and applies rules to the *host* via
`NetworkIptablesManager`, which **requires root**. Unprivileged, the request
fails closed rather than running unfiltered: `spawn_bwrap` returns the
`apply_firewall_rules` error before `bwrap` is spawned, so no workload runs.
The unenforced case is the *privileged* one — the rules install on the host's
chains, which the sandbox does not traverse, so they filter nothing while
appearing to succeed. This is retained unchanged for existing callers and is
the reason enforcement is 0.8+ only. Names are accepted on this path and
resolved to IPv4 only.

> **Legacy path, IPv4 only.** On schema ≤ 0.7, host names are resolved to
> IPv4 addresses only; AAAA records and IPv6 literals are silently dropped
> because `iptables` (the IPv4 tool) cannot accept IPv6 destinations. A host
> with only AAAA records is effectively unreachable. Moving to 0.8 programs
> `ip6tables` as well, but does not make such a host reachable while the
> sandbox namespace has no IPv6 (see #955); use proxy mode (below) instead.

**Full allow** (`defaultPolicy: "allow"`, no host lists) — the sandbox
shares the host network namespace with no restrictions.

#### `allowLocalNetwork` is not independently enforceable

`network.allowLocalNetwork` controls whether the sandboxed process may
`bind()`/`listen()` on local IPs and accept **inbound** connections. It says
nothing about *outbound* reachability of loopback or RFC1918 addresses —
that is governed by `defaultPolicy` / `allowedHosts` / `blockedHosts`.

Bubblewrap has no inbound-only primitive. Unprivileged bwrap has no veth
interface to scope iptables to, and seccomp cannot dereference the `sockaddr`
passed to `bind()`, so an AF_INET-only filter is not expressible. The
namespace choice alone decides the outcome:

| `allowLocalNetwork` | Namespace | Result |
|---------------------|-----------|--------|
| `false` (default) | private (`--unshare-net`; isolated, plus 0.8 proxy and firewall modes) | Honored at the sandbox boundary — nothing outside can reach in, and on 0.8 the proxy and firewall modes additionally drop new inbound connections in an `MXC_INGRESS` chain (see below). `bind()`/`listen()` still succeed on the sandbox's own loopback, so its processes can talk to each other; that is already inside the caller's trust boundary |
| `false` | shared with host | **Not honored** — the process can bind/listen on host-local addresses |
| `true` | private (`--unshare-net`) | **Partially honored** — the listener is reachable only from inside the sandbox |
| `true` | shared with host | Honored |

Rows 2 and 3 are rejected on schema `0.8.0-alpha` and later — in the backend's
validation, which every caller passes through, so a programmatic
`ExecutionRequest` is refused just like a JSON config — and
emit a
`WARNING:` line to the runner log at preflight on earlier schemas rather than
failing silently. Windows (AppContainer's `privateNetworkClientServer`
capability) and macOS (Seatbelt's `(allow network-inbound (local ip))`)
enforce the field at the syscall level; this divergence is Linux-specific.

Row 2 is keyed on the value, not on whether the caller wrote the field.
`false` is the schema's default *and* a deny, so an omitted `allowLocalNetwork`
is still a request for inbound denial and is rejected the same way: a bare
`defaultPolicy: "allow"` does not silently opt out of the deny it inherits.
Callers who want the shared namespace acknowledge the exposure with
`allowLocalNetwork: true` (row 4), the same acknowledgment IsolationSession
requires for this field.

#### Inbound is closed by the namespace, and by a chain
On schema `0.8.0-alpha` and later, the modes that build a private network
namespace (proxy and firewall-enforced) also install an `MXC_INGRESS` chain
hooked into `INPUT`, for both families:

```
-i lo -j ACCEPT
-m state --state ESTABLISHED,RELATED -j ACCEPT
-m state --state NEW -j DROP
-j DROP
```

Be honest about what this buys. It is **not** new protection: nothing outside
the sandbox can reach in already, because the runner configures no port
forwarding into the namespace, so there is no path for an inbound packet to
arrive on. The chain is defense in depth against a future change that adds
one, and the mechanism the GA networking spec expects a backend to apply
`ingress.default` through. The terminal `DROP` is deliberately independent of
`network.defaultPolicy`, which governs egress only — an open outbound posture
must not open inbound as a side effect.

The `ESTABLISHED,RELATED` accept is not optional. A terminal `INPUT` drop
applies to reply packets too, so without it the sandbox would lose all
networking rather than gain an inbound restriction.

That connection-state match requires `nf_conntrack` on the host. Unprivileged
Bubblewrap cannot `modprobe`, so if the module is not already loaded the
`iptables-restore` transaction fails, iptables rolls the whole table back, and
the supervisor aborts before releasing the workload. The failure is loud and
fail-closed by construction, not a silently unenforced sandbox. No separate
probe is performed: the transaction is a stricter check than probing the
userspace extension would be, because it exercises the match in the actual
namespace.

No RFC 4890 ICMPv6 exemptions are emitted. `slirp4netns` runs without
`--enable-ipv6`, so the namespace has no IPv6 for them to govern; they must be
added in the same change that enables it.

Legacy schemas are unaffected. Below `0.8.0-alpha`, proxy mode resolves to the
shared host network namespace, where no chain of any kind is installed.

#### Directional policy (`network.egress` / `network.ingress`)

Schema `0.8.0-alpha` adds a directional network shape that replaces the
`defaultPolicy` / `allowedHosts` / `blockedHosts` triple with an explicit
`egress` and `ingress` section. The two shapes are **mutually exclusive**: a
config that mixes legacy and directional fields is a parse error, and one that
uses directional fields on a pre-0.8 schema is refused by the parser with
`network.egress, network.ingress, runtimeConfig, and processContainer.network
require schema version 0.8 or later`.

A config carrying *any* legacy field takes the legacy path described above and
is byte-identical to what it was before directional support existed. This
matters: the proxy-mode callers on 0.6/0.7 are unaffected by anything in this
section.

```json
{
  "network": {
    "egress": {
      "default": "deny",
      "allow": [
        {
          "to": [{ "cidr": "1.1.1.1/32" }],
          "ports": [{ "protocol": "tcp", "port": 443 }]
        }
      ]
    },
    "ingress": { "default": "deny", "hostLoopback": "deny" }
  }
}
```

Egress lowers into the same private-namespace iptables chains the legacy
firewall mode uses, so the enforcement properties are identical — supervisor
holds `CAP_NET_ADMIN`, sandbox drops it, no root required, IP literals and
CIDRs only. An `except` list on a rule is lowered by CIDR subtraction into the
remaining covering blocks, so `allow 0.0.0.0/0 except 1.1.1.0/24` becomes a set
of accepts that provably omit the carve-out rather than an accept followed by a
hoped-for later deny.

**Mode selection.** Directional never resolves to the shared host namespace:

| Directional policy | Resolved mode |
|---|---|
| proxy configured | proxy-only (unchanged; the proxy arm wins) |
| ruleless `egress.default: "deny"` | isolated (`--unshare-net`) |
| anything else — rules present, or `egress.default: "allow"` | firewall-enforced (private namespace) |

An open outbound posture therefore becomes an accept-all chain **inside a
private namespace**, not a shared host namespace. That is deliberate. The
parser fills `network.ingress` unconditionally on the directional path —
including when the config has no `network` section at all — and there is no
`_specified` twin to distinguish a defaulted `ingress.default: "deny"` from a
written one. Sharing the host namespace would leave that deny unenforceable,
and it could not be refused without also refusing every legitimate "allow all
outbound" config. Choosing the private namespace keeps the inbound half true
for the cost of a slirp hop.

A consequence worth knowing: on 0.8, a config with **no `network` section at
all** selects the directional shape with a synthesized default-deny. It renders
identically to the legacy default only because `NetworkPolicy::default()` and
`NetworkAction::default()` both mean deny — a coincidence the tests pin rather
than rely on silently.

**What the backend refuses.** Bubblewrap declares support for
`egress.default`, `egress` rules, `ingress.default`, `ingress.hostLoopback`,
and `runtimeProxy`. Declaring the two inbound features means the backend
*understands* those fields — not that it honors both of their values. Only the
deny posture is reachable, so the allow posture is refused rather than accepted
and dropped on the floor:

| Rejected | Why |
|---|---|
| `ingress.default: "allow"` | slirp4netns installs no route into the namespace, and the schema carries no port list with which to forward one. Nothing would arrive, so "allow" would be a lie |
| `ingress.hostLoopback: "allow"` | the inbound half needs the same port forwarding `ingress.default: "allow"` lacks. Granting only the outbound half would honor half a bidirectional field under its full name |
| directional `egress` rules combined with a proxy | a proxy resolves to the proxy-only posture, whose chain opens the proxy endpoint alone. The rules would be silently discarded, so they are refused instead. This holds for `builtinTestServer` too: its exemption covers legacy host *lists*, which MXC applies itself, and must not extend to directional rules, which nothing applies |
| any directional section before 0.8 | the parser refuses it first; the backend keeps its own twin of the check for programmatic callers that build an `ExecutionRequest` directly and never pass through the parser |

**What the deny postures actually do.** `ingress.default` installs the
`MXC_INGRESS` chain on `INPUT`. `ingress.hostLoopback` is bidirectional per the
0.8 contract, so its deny also has to close container-to-host: under slirp that
path is the gateway `10.0.2.2`, which maps onto the host's own loopback. That
drop is lowered *ahead* of every caller rule, because the chain is first-match
and a broad allow — a bare `0.0.0.0/0` included — would otherwise win and the
deny would be decorative. An omitted `ingress` section enforces the same deny,
since deny is the schema's default rather than an absence of policy. Proxy mode
needs no equivalent: it opens the proxy endpoint alone and closes on `DROP`, so
the rest of the gateway is already unreachable. IPv4 only — slirp gives the
sandbox no IPv6 route to the host, so there is no V6 gateway to close. The
legacy shape gains no such rule.

The declaration and these refusals must ship together — declaring the inbound
features without them would be a fail-open. A unit test asserts exactly that
pairing, driven through `validate()` rather than the gate function, so deleting
the wiring fails the test.

**Declaration alone is not evidence.** `hostLoopback` was declared, accepted,
and completely unenforced for its whole first life: egress to `10.0.2.2` was
open on every directional config, and the end-to-end suite used exactly that
address as its "reachable" target — so the tests were passing *because of* the
bug. Acceptance proved only that shared validation did not refuse the field.
Each declared bit therefore carries an **enforcement probe** in
`every_network_policy_support_bit_is_a_deliberate_decision`: the probe flips the
field in a copy of the request and requires the rendered `iptables-restore`
payload to change. A bit whose field can be flipped with no effect on the chain
is over-declared and fails there. Reverting the host-loopback drop reproduces
the original bug as a test failure.

`runtimeProxy` is declared. The parser normalizes
`runtimeConfig.networkProxy` into the same `policy.network_proxy` the legacy
`network.proxy` field feeds, pinned to a loopback endpoint and accepted only
alongside `egress.default: "deny"` with no direct rules. That is exactly the
proxy-only posture this backend already enforces, so the 0.8 spelling reaches
the identical enforcement as the 0.7 one rather than a second implementation.
An end-to-end test runs both spellings against the same workload and compares
their verdicts to each other, anchored to an expected result so that two
identically-broken spellings cannot agree their way to a pass.

`proxyPeerIdentity` stays undeclared: it is a ProcessContainer concept with no
Bubblewrap equivalent, so shared validation refuses it here.

Declaring the bit was necessary but not sufficient. The backend's
`external_proxy_host_rules_rejection` guard — which stops an operator-supplied
proxy from being combined with host lists MXC never forwards to it — also keyed
off `defaultPolicy: "block"`. That is a *legacy-shape* field the directional
path never writes, so it sits at its `Block` default on every directional
request. Since the parser requires `egress.default: "deny"` with no direct
rules for a runtime proxy, the guard refused every such config: the capability
would have been declared but unusable. The guard now reads `defaultPolicy` only
on the legacy shape, using the same `network_egress.is_some()` discriminator as
`EgressPlan::for_request` and `ResolvedNetworkMode::from_request`. Real host
lists are still refused in either shape.

Because the bits are a hand-written declaration with nothing deriving them from
the fields the backend actually consumes, a bit that is simply never added is
indistinguishable from one that was considered and refused — both surface as
the same clean rejection. `runtimeProxy` sat undeclared for exactly that
reason while the proxy machinery behind it was already complete. A unit test
now enumerates every `NetworkPolicySupport` bit and fails if a newly added one
is left uncategorized, so the decision can no longer be made by omission.

### Process Settings

Standard `process` fields work as expected:

```json
{
  "process": {
    "commandLine": "python3 script.py",
    "cwd": "/workspace",
    "env": ["PATH=/usr/bin", "HOME=/tmp"],
    "timeout": 30000
  }
}
```

## Network proxy (private namespace, unprivileged)

Bubblewrap supports an **unprivileged, cooperative network proxy** that
enforces `allowedHosts` / `blockedHosts` at the proxy layer instead of via
host-level iptables. The workload runs in a private network namespace and
reaches the proxy through rootless `slirp4netns` routing. This requires no root
privileges.

This private-network behavior applies to schema **0.8 and later**. Policies
using schema 0.6 or 0.7 retain the existing shared-host-network proxy behavior
for compatibility and do not require `slirp4netns`. An absent schema version is
also treated as legacy. The runner never silently falls back: a 0.8 proxy
request fails if its private namespace cannot be configured.

### How it works

0. Before anything is launched, `validate` probes the host tools this mode
   depends on — `slirp4netns`, `unshare` (checked for `--map-current-user` and
   `--keep-caps`), `nsenter`, `iptables`, `ip6tables`, `iptables-restore`, and
   `ip6tables-restore` — so a host that is
   missing one fails immediately with a message naming it, rather than partway
   through supervisor startup. For the `iptables` family presence is not
   enough: the probe also reads the backend from the version banner and refuses
   a legacy backend whose `/run/xtables.lock` this user cannot open, because
   the unprivileged supervisor would otherwise die at the first rule. Each
   probe is bounded by a short timeout: a
   wedged binary is reported as hung and named, instead of stalling every
   proxy-mode execution on the host indefinitely. A successful probe is cached
   for the life of the process; failures are not, so installing the missing
   tool takes effect without a restart.
1. When `network.proxy` is set, the runner launches an unprivileged HTTP
   proxy on loopback (`127.0.0.1:N`). For tests, the bundled
   `unix-test-proxy` binary is used (`builtinTestServer: true`,
   testing-only and gated behind `--allow-testing-features`); in production callers
   supply their own proxy via `localhost: <port>` or `url: <url>`.
2. The runner creates a same-UID user-namespace supervisor, starts Bubblewrap
   with `--unshare-net`, and keeps the workload behind a startup barrier.
3. The supervisor attaches `slirp4netns` to Bubblewrap's private network
   namespace. Host-loopback proxy endpoints are presented to the sandbox
   through slirp's `10.0.2.2` host gateway. Once slirp is up, the supervisor
   programs a default-DROP `MXC_EGRESS` chain into that namespace via
   `nsenter`, permitting only loopback and the proxy endpoint (IPv6 gets a
   DROP-only chain), plus a default-DROP `MXC_INGRESS` chain on `INPUT`
   (see [Inbound](#inbound-is-closed-by-the-namespace-and-by-a-chain)).
   Each family's whole table — both chains, their rules in
   order, the terminal verdicts and the `OUTPUT` / `INPUT` hooks — is applied
   with `iptables-restore` rather than rule by rule, so the cost of a policy
   does not grow with the caller's host lists. One restore is one bounded
   netlink transaction, so a table too large for it is split across numbered
   payload files against a byte budget and applied in order (`-n`, so each
   later transaction appends). Both built-in hooks ride in the *last*
   transaction of a family, so a hook is never live over a half-built chain
   and a partial apply leaves the policy unhooked rather than half-enforced.
   The workload is released only after every transaction is
   applied, so it can never run with egress open. A failure to program any
   rule aborts the supervisor rather than starting an unenforced sandbox.

   Bubblewrap joins the supervisor's user namespace (`--userns`) rather than
   creating its own, so the sandbox lives in the namespace that owns the
   rule-bearing network namespace. This relies on Bubblewrap dropping
   capabilities in the sandboxed process — the runner passes no `--cap-add` —
   which is what prevents the workload from holding the `CAP_NET_ADMIN` needed
   to flush the chain.
4. The command builder sets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`,
   `FTP_PROXY`, and their lowercase variants inside the sandbox via
   `bwrap --setenv` (caller-supplied values for these keys, including
   `NO_PROXY` / `no_proxy`, are stripped before injection). The runner
   deliberately does **not** set `NO_PROXY`, because exempt destinations would
   bypass the configured proxy policy.
5. Cooperative tools (curl, wget, Python `requests`, Node `https`, etc.)
   honor the env vars and traffic flows through the proxy, which applies
   the `allowedHosts` / `blockedHosts` lists. Non-cooperating clients are not
   merely unrouted — their traffic is dropped by the egress chain.

### Example: builtin test proxy with allowlist

```json
{
  "version": "0.8.0-alpha",
  "platform": "linux",
  "containment": "bubblewrap",
  "process": {
    "commandLine": "curl -fsSL https://api.github.com/zen && echo OK"
  },
  "network": {
    "defaultPolicy": "allow",
    "proxy": { "builtinTestServer": true },
    "allowedHosts": ["api.github.com"]
  }
}
```

### Example: external proxy on loopback

```json
{
  "version": "0.8.0-alpha",
  "containment": "bubblewrap",
  "process": { "commandLine": "curl -fsSL https://example.com" },
  "network": {
    "proxy": { "localhost": 8080 }
  }
}
```

> Both examples declare `0.8.0-alpha` deliberately: the private-namespace and
> egress-enforcement behavior described above is selected by the schema version,
> so the same config on `0.6`/`0.7` runs the legacy shared-host-network proxy
> path instead.

### Caveats

- **Host loopback moves to the gateway address (breaking change in 0.8+
  proxy mode)**: the sandbox gets its own network namespace, so inside it
  `127.0.0.1` now means *the sandbox itself*, not the host. A config that
  reaches a host-local service by loopback address — a database on
  `127.0.0.1:5432`, a metadata endpoint, a second proxy — silently stops
  connecting to the host and starts connecting to nothing. Under the schema
  0.6/0.7 legacy proxy path the sandbox shared the **host's own network
  namespace**, so `127.0.0.1` did reach the host; that is the behavior
  changing here.

  The configured proxy remains reachable, but at slirp's gateway address
  `10.0.2.2` instead — which is exactly how the runner rewrites a
  `localhost` proxy endpoint so the sandbox can still find it. Other
  host-local services do **not** come along: slirp itself runs without
  `--disable-host-loopback`, so the gateway can in principle carry traffic to
  any host-loopback port, but the egress chain admits only the single
  `10.0.2.2:<proxy-port>` destination and drops the rest. The host-loopback
  surface is therefore the proxy endpoint alone.
- **The supervisor's user namespace is visible to the sandbox**: in proxy
  mode `bwrap` joins the supervisor's user namespace via `--userns` rather
  than creating its own, and the namespace descriptor stays open in the
  workload — `bwrap` keeps it across its own `fork`/`exec` and offers no flag
  to close it. Re-entering the namespace with `setns` requires
  `CAP_SYS_ADMIN`, which the sandbox cannot hold: `bwrap` empties the
  capability bounding set before `exec`, so the workload runs with
  `CapBnd`/`CapEff`/`CapPrm` all zero. The end-to-end test suite asserts
  those are zero, because that assumption is what makes the exposed
  descriptor inert.
- **Cooperative routing, enforced egress (schema 0.8+)**: the runner injects
  `HTTP_PROXY` / `HTTPS_PROXY` so cooperating clients route through the proxy,
  and additionally programs a default-DROP egress chain inside the sandbox's
  private network namespace. Clients that ignore the env vars (raw sockets,
  custom HTTP clients) can no longer reach the network directly: only loopback
  and the proxy endpoint are permitted. DNS is deliberately **not** opened —
  the proxy resolves on the workload's behalf. IPv6 egress is denied outright.

  Host-local proxy endpoints — `localhost`, `127.0.0.0/8` and the wildcards
  `0.0.0.0` / `::` — are rewritten to `10.0.2.2`. `::1` is **rejected at
  validation time**: a proxy bound only to the IPv6 loopback cannot accept the
  IPv4 connection slirp's gateway produces, so translating it would hand the
  sandbox an address nothing answers on. Bind such a proxy to `127.0.0.1` or to
  a dual-stack wildcard instead.

  On schema **0.6/0.7** the legacy behavior applies: the sandbox shares the
  host network namespace, no egress rules are installed, and only the
  cooperative env-var routing is in effect — a client that ignores
  `HTTP_PROXY`/`HTTPS_PROXY` reaches the network directly. For strict
  whole-network isolation on those versions, omit `network.proxy` so the
  runner can apply `--unshare-net` instead.
- **Hostname proxy endpoints are pinned, not resolved in the sandbox**: because
  DNS is closed, a hostname in `network.proxy.url` cannot be resolved by the
  workload. The runner resolves it **once on the host** before the sandbox
  starts, opens the egress chain for that address, and pins
  `<address> <hostname>` as the first line of a generated `/etc/hosts` that is
  bind-mounted read-only over the sandbox's copy. The workload therefore sees
  the URL exactly as configured, so `Host` headers and proxy-auth realms match.
  Consequences worth knowing:
  - The name is resolved **once**, at start. A proxy whose address changes
    mid-run is not followed.
  - Only the pinned address is opened in the egress chain, so a resolver that
    bypasses `/etc/hosts` (for example a client that speaks DNS directly, which
    is itself blocked) cannot reach a different address. The failure is closed.
  - IP **literals** are rewritten rather than pinned, per the rules above. A
    hostname that resolves to a loopback address is likewise pinned to the
    gateway.
  - `localhost` is always rewritten, never pinned. It is reserved to loopback
    (RFC 6761) and a pin is a sandbox-wide mapping, so pinning it would
    redirect the workload's own loopback traffic to the host.
  - The generated `/etc/hosts` preserves the host's existing entries after the
    pin line, so `localhost` and friends keep working. A `readwritePaths` or
    `readonlyPaths` entry covering `/etc/hosts` is overridden by the pin mount,
    with a warning — that narrows the caller's access rather than widening it.
  - A **`deniedPaths`** entry covering `/etc/hosts` (directly or via an
    ancestor such as `/etc`) is **rejected** instead. The pin is applied after
    every policy mount, so honouring it would hand back a readable file
    populated from the host's own `/etc/hosts` — the opposite of the requested
    denial. Give the proxy an IP address instead, which needs no pin. A more
    specific grant beneath the denial (for example denying `/etc` while listing
    `/etc/hosts` under `readonlyPaths`) takes effect and is accepted.
  - IPv6-only proxy hostnames are rejected, matching the IPv6 egress denial.
- **Mutually exclusive with iptables enforcement**: setting
  `network.proxy` together with `network.enforcementMode` of `"firewall"`
  or `"both"` is rejected at config-parse time. Both postures build the same
  private namespace, so the combination is ambiguous rather than impossible —
  it is refused because there is no defined precedence between an endpoint pin
  and a rule list, not because of any privilege requirement.
- **External proxy delegates policy**: when `network.proxy` uses
  `localhost: <port>` or `url: <url>` (not `builtinTestServer`), the
  external proxy is responsible for any host filtering. The runner does
  **not** forward `allowedHosts` / `blockedHosts` / `defaultPolicy: "block"`
  to it, and config combinations that would silently weaken enforcement
  are rejected at parse time.
- **`builtinTestServer` is testing-only**: gated behind `--allow-testing-features`
  and never to be used as a real production proxy. It has no auth, no
  body-size limits, and minimal hop-by-hop header handling. Use a real
  HTTP proxy for production deployments. (Selecting the Bubblewrap backend
  itself still also requires `--experimental`.)
- **HTTPS via CONNECT**: the proxy uses HTTP `CONNECT` tunnels for TLS, so
  certificate validation continues to work end-to-end (the proxy does not
  see plaintext).

### Common pitfalls when configuring `allowedHosts`

The proxy applies `allowedHosts` and `blockedHosts` by **case-insensitive
exact host match** — there is no subdomain wildcard and no IP-vs-hostname
resolution.

- `allowedHosts: ["github.com"]` does **not** match `api.github.com`. List
  each subdomain explicitly (e.g. `["api.github.com", "objects.githubusercontent.com"]`).
- `allowedHosts: ["api.github.com"]` does **not** match a CONNECT to a raw
  IP literal such as `140.82.114.6:443`. If your workload bypasses DNS,
  include the IPs.
- `allowedHosts: ["localhost"]` does **not** match `127.0.0.1`; if you
  need both, list both.
- IPv6 literals are normalised: an allowlist entry of `"::1"` matches a
  CONNECT to `[::1]:443`, but not the unrelated `[fe80::1]:443`.

## Comparison with LXC

| Aspect | LXC | Bubblewrap |
|--------|-----|------------|
| Privileges | Root required | Unprivileged (user namespaces) |
| Rootfs | Downloads distro rootfs | Bind-mounts host filesystem |
| Startup | Create → Start → Attach | Single `bwrap` exec; the 0.8 private-namespace modes (proxy and firewall enforcement) add a user/network-namespace supervisor, a `slirp4netns` instance and an egress rule set |
| Network isolation | iptables + veth | `--unshare-net`, private netns + slirp4netns, or iptables |
| Dependencies | `lxc-*` tools, templates | `bwrap`; the 0.8 private-namespace modes also need `slirp4netns`, util-linux `unshare` and `nsenter`, plus `iptables`, `ip6tables` and their `-restore` counterparts on the `nf_tables` backend |
| Lifecycle | Create/destroy containers | Process dies on exit; proxy mode's supervisor is reaped with it |

**When to use Bubblewrap:**
- Quick sandboxing without root access
- Environments where LXC is not available
- Fast iteration (no container create/destroy overhead)

**When to use LXC:**
- Need a separate rootfs (different distro/packages)
- Need container networking with veth interfaces
- Need persistent containers across executions

## Running Tests

```bash
# Single basic test
tests/scripts/run_bwrap_basic_test.sh

# All Bubblewrap tests
tests/scripts/run_bwrap_all_tests.sh
```

Test configs are in `tests/configs/bubblewrap_*.json`.

## Limitations

- **Experimental** — requires `--experimental` flag
- **Linux only** — Bubblewrap requires Linux kernel namespaces
- **Deny-by-default filesystem** — the sandbox sees a minimal allowlist
  of host paths (system binaries, libs, `/etc`, DNS stub-resolver dirs)
  and nothing else. `$HOME`, `/opt`, `/var`, `/sys`, `/run/user/<uid>`,
  and `/usr/local` are invisible unless explicitly listed in
  `readonlyPaths` / `readwritePaths`. There is no separate rootfs — the
  visible paths are bind-mounted from the host.
- **Network filtering** — per-host `allowedHosts`/`blockedHosts` is enforced
  natively on schema 0.8+ via `network.enforcementMode: "firewall"`, with
  **no privilege required** (rules are programmed inside the sandbox's own
  namespace; addresses must be IP literals or CIDRs). The cooperative env-var
  **network proxy** remains the option when you need name-based rules. On
  schema ≤ 0.7 the firewall path targets the *host* and requires root; it is
  retained for compatibility but does not filter unprivileged.
- **No state-aware lifecycle** — Bubblewrap implements `ScriptRunner` only
  (one-shot), not `StatefulSandboxBackend`
