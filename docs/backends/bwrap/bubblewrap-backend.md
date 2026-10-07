# Bubblewrap Backend

> **Audience:** MXC consumers and developers

The Bubblewrap backend provides **unprivileged Linux sandboxing** using
[Bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`). It uses
Linux user namespaces to create isolated sandbox environments without
requiring root privileges or a container runtime.

> **Status:** Stable — the default Linux backend.

> **Supported exact contracts (v0.9+):** author `network.egress` /
> `network.ingress` and, for proxy requests, `runtimeConfig.networkProxy`.
> Versions before `0.9.0-alpha` are rejected; changing only the version of an
> old config does not migrate its policy. Legacy `defaultPolicy`,
> `enforcementMode`, host lists, `allowLocalNetwork`, and `network.proxy`
> are rejected by supported exact contracts. Typed Rust requests no longer
> contain these fields. See [schema migration](../../schema.md).
> Bubblewrap still rejects enforceable-looking requests it cannot honor
> (such as `ingress.default: "allow"` or direct egress rules combined with a
> runtime proxy) before provisioning. An omitted `network` section takes the
> directional deny defaults.

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
  below that floor. The probe has a 5-second deadline and retains at most 64 KB
  from each output stream. On timeout, its process group is terminated with
  `SIGKILL` so wrappers and descendants cannot keep the probe alive. Successful
  Rust-executor advisory results are cached for the process lifetime; Rust
  failures are not cached, and execution validation probes again before launch
  so a changed PATH target cannot reuse an advisory result. The Node SDK caches
  the complete `getPlatformSupport()` result, including failures, for the module
  lifetime; restart the Node process after remediating the host.
- **Network-enabled private-namespace modes (v0.9+):** `slirp4netns` installed
  and on PATH, plus util-linux `unshare` (with `--map-current-user` and
  `--keep-caps`), `nsenter`, `iptables`, `ip6tables`, `iptables-restore`, and
  `ip6tables-restore` for the in-namespace egress and ingress rules, a POSIX
  `sh` (the supervisor runs as `sh -c`), and the
  `nf_conntrack` kernel module loaded for the inbound chain's connection-state
  match (unprivileged Bubblewrap cannot load it on demand).

  This covers both proxy-only egress via `runtimeConfig.networkProxy` and
  directional firewall enforcement (egress rules or `egress.default: "allow"`).
  Both use the same dependency probe and install egress and ingress chains.
  Ruleless `egress.default: "deny"` instead uses `--unshare-net` alone and
  needs none of these additional network tools.

  > `ip6tables` is required to *deny* IPv6, not to carry it. slirp4netns is
  > launched without `--enable-ipv6`, so the sandbox namespace has no IPv6
  > connectivity at all and the v6 rules exist to keep the unmatched family
  > closed. An IPv6 destination is unreachable even when a rule allows it
  > (see #955). On a kernel without IPv6 (built without `CONFIG_IPV6`, or
  > booted with `ipv6.disable=1`) the sandbox cannot open an IPv6 socket, so
  > the runner returns a warning that it is skipping the v6 rules and installs
  > only the IPv4 chains. The `ip6tables` tools are still probed there,
  > because they ship in the same package as `iptables`.
  ```bash
  # Debian/Ubuntu
  sudo apt install slirp4netns util-linux iptables

  # Fedora/RHEL
  sudo dnf install slirp4netns util-linux iptables

  # Alpine
  apk add slirp4netns util-linux iptables
  ```
  `iptables` should resolve to the **`nf_tables` backend** (the default on
  Debian 10+, Ubuntu 20.10+, RHEL 8+, and Alpine). The `iptables-legacy`
  backend opens `/run/xtables.lock` before touching any table. The rules are
  installed by an unprivileged supervisor that keeps the caller's uid, so on
  a stock host with root-owned `/run` it cannot take that lock. `validate`
  refuses such a host with a message naming the backend rather than letting
  the supervisor die at the first rule. If pinned to `iptables-legacy`, switch it:
  ```bash
  sudo update-alternatives --set iptables /usr/sbin/iptables-nft
  sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-nft
  ```
  (`iptables-legacy` works only where the lock is writable, for example when
  running as root. This is a tooling distinction, not a retired schema mode.)
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
  "version": "0.9.0-alpha",
  "containment": "bubblewrap",
  "process": {
    "commandLine": "echo 'Hello from Bubblewrap sandbox'"
  }
}
```

Run with:
```bash
lxc-exec --config bubblewrap_hello.json
```

Or via base64:
```bash
lxc-exec --config-base64 "$(base64 -w0 bubblewrap_hello.json)"
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

### Process environment

The host environment is never inherited — the sandbox is built with
`--clearenv`, so host secrets can't leak into untrusted code.

**From schema 0.9** the child gets a default block of `PATH`
(`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`), `TERM`
(`xterm-256color`), and — only when `process.cwd` resolves one — `HOME` (the
directory the child is started in):

| `process.env` | `inheritDefaultEnv` | Result |
| --- | --- | --- |
| omitted | — | the default block |
| `[]` | — | nothing at all |
| `["FOO=bar"]` | `false` (default) | `FOO` only — **no `PATH`** |
| `["FOO=bar"]` | `true` | the default block plus `FOO`; a same-named entry wins |

> ⚠️ **`HOME` is only set when `process.cwd` is supplied.** MXC has no private
> directory it can guarantee otherwise: a `readwritePaths` grant is bind-mounted
> after `--tmpfs /tmp` and therefore replaces it, so `/tmp` may be the host's
> shared directory. Pass `"HOME=…"` in `process.env` if your command needs it.

> ⚠️ **`HOME` is the working directory.** Dotfiles inside it — `.gitconfig`,
> `.npmrc`, `.curlrc`, `.config/*` — are therefore read as *user-level* tool
> configuration, not just project input. Pass `"HOME=…"` to point elsewhere
> when the workspace is untrusted.

The table is the environment MXC hands the child. Bubblewrap runs the workload
under the host's `/bin/sh`, and a shell started without these assigns its own:
dash (Debian, Ubuntu) fabricates a `PATH` that happens to equal the default
block's value, while bash (RHEL) fabricates a shorter `/usr/local/bin:/usr/bin`
plus `TERM=dumb`. So neither reads back as empty from inside the workload,
whatever MXC passed.

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
  "version": "0.9.0-alpha",
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

All supported exact requests use directional `network.egress` and
`network.ingress`. Both ingress controls default to `deny` when omitted.
The JSON objects below are network fragments to place in a v0.9+ request.

**Full block** (ruleless `egress.default: "deny"`, no runtime proxy) uses
`--unshare-net` for complete network namespace isolation. The sandbox gets a
private network stack with only its own loopback (bwrap brings `lo` up), so
nothing outside the sandbox is reachable and nothing outside can reach in.
This needs no root or `slirp4netns`.

```json
{
  "network": {
    "egress": { "default": "deny" },
    "ingress": { "default": "deny", "hostLoopback": "deny" }
  }
}
```

**Address filtering** (`egress.allow` / `egress.deny`) puts the sandbox in a
private, slirp-backed network namespace and programs its rules there from a
supervisor holding `CAP_NET_ADMIN` inside an unprivileged user namespace.
**No root required**; the sandbox drops `CAP_NET_ADMIN` before the workload
starts, so it cannot undo the rules.

Rule addresses must be **IP literals or CIDR blocks**; a DNS name is rejected
at validation time rather than resolved on the caller's behalf. The backend
does not resolve, because the sandbox resolves names itself and a lookup that
disagreed with the one behind the rules would hand the workload an address the
chain never authorized.

**IPv6 rules are filtered, but IPv6 traffic has nowhere to go.** The two are
separate concerns and only the second is missing. Filtering works: an IPv6 rule
programs `ip6tables`, and the terminal verdict of the unmatched family follows
`egress.default`, so an IPv4-only allow rule under `deny` does not leave IPv6 open.
What the sandbox lacks is IPv6 *connectivity* — slirp4netns is launched without
`--enable-ipv6`, so the namespace has no IPv6 route at all (see #955). The
consequence is one-sided: an IPv6 **block** is already satisfied, while an IPv6
**allow** grants nothing in practice, because the destination stays unreachable
regardless of the rule. MXC emits a warning naming those allowed destinations
rather than refusing them, since the posture fails closed.

An IPv4-mapped address such as `::ffff:203.0.113.5` is programmed as IPv4:
Linux puts a genuine IPv4 packet on the wire for one, so an `ip6tables` rule
naming it would never match and a directional deny rule under
`egress.default: "allow"` would fail open. A mapped CIDR is translated the
same way — the mapped range is the last 32 bits of `::ffff:0:0/96`, so a
`/96 + n` prefix becomes a v4 `/n`.

An IPv6 block **shorter** than `/96` that contains `::ffff:0:0/96` is
**rejected** rather than programmed. CIDR blocks nest or are disjoint, so such a
block always swallows the mapped range whole, and neither available reading is
safe to apply silently: leaving it on `ip6tables` unenforces the mapped half
(the same fail-open the translation above exists to prevent), while projecting
it onto IPv4 would always widen it to `0.0.0.0/0` — turning a deny rule for
`::/0` from "block all IPv6" into "block all IPv4 as well". The rejection
asks the caller to write the IPv4 side explicitly. Blocks that do not contain
the mapped range, such as `2001:db8::/32`, are unaffected.

An explicit `egress.deny` rule outranks a broader `egress.allow` rule: denies
are installed ahead of allows in a first-match chain.

```json
{
  "network": {
    "egress": {
      "default": "deny",
      "allow": [{ "to": [{ "cidr": "203.0.113.0/24" }] }],
      "deny": [{ "to": [{ "cidr": "203.0.113.4/32" }] }]
    },
    "ingress": { "default": "deny", "hostLoopback": "deny" }
  }
}
```

**Open external egress** (`egress.default: "allow"` with no rules or proxy)
also uses the private slirp-backed namespace. Its egress chain defaults to
`ACCEPT`, but drops host-loopback traffic first. It never shares the host
network namespace; ingress and host loopback still default to deny.

#### Ingress and host-loopback isolation

The retired `allowLocalNetwork` field has no v0.9 spelling. Use
`network.ingress.default` to express unsolicited inbound policy and
`network.ingress.hostLoopback` for the bidirectional host-loopback path.
Bubblewrap currently honors only `deny` for either control. An `allow` value
is rejected before sandbox creation: slirp has no host-to-sandbox port
forwarding, so no inbound-accepting posture could be delivered.

The sandbox's own loopback remains usable by its processes for `bind()` and
`listen()`; that does not open an inbound path from the host. Under slirp,
host-loopback denial also blocks container-to-host traffic at `10.0.2.2`,
ahead of any outbound allow rule. The only exception is the configured
runtime proxy endpoint, which proxy-only egress opens on that gateway.

#### Inbound is closed by the namespace, and by a chain

The v0.9+ proxy and firewall-enforced modes also install an `MXC_INGRESS` chain
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
one, and a defense-in-depth implementation of `ingress.default`. The terminal
`DROP` is deliberately independent of
`egress.default`, which governs outbound traffic only — an open outbound posture
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

#### Directional policy (`network.egress` / `network.ingress`)

Schema `0.9.0-alpha` uses an explicit `egress` and `ingress` section instead
of the retired `defaultPolicy` / `allowedHosts` / `blockedHosts` fields. An
exact v0.9 config carrying a legacy field fails parsing; a config declaring
an earlier version is refused as an unsupported contract before its network
section is read.

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

Egress lowers into the namespace-local iptables chains described above. The
supervisor holds `CAP_NET_ADMIN`, the sandbox drops it, and no root is required.
Addresses are IP literals or CIDRs only. An `except` list on a rule is lowered
by CIDR subtraction into the remaining covering blocks, so
`allow 0.0.0.0/0 except 1.1.1.0/24` becomes a set of accepts that provably
omit the carve-out rather than an accept followed by a hoped-for later deny.

**Protocol support.** `ports[].protocol` accepts `tcp`, `udp`, `icmp`, and
`any`. What Bubblewrap actually enforces is bounded by its *transport*, not by
its rule engine: every mode that installs egress rules puts the sandbox behind
`slirp4netns`, a userspace network stack that carries **TCP, UDP, and ICMP echo
only**. No other IP protocol — SCTP, DCCP, GRE — has a path out of the
namespace, whether or not a rule names it.

| Selector | Rules emitted | Notes |
|---|---|---|
| `tcp` | `-p tcp` | |
| `udp` | `-p udp` | |
| `icmp` | `-p icmp` (IPv4) / `-p icmpv6` (IPv6) | Expands by destination address family. |
| `any`, no `port` | no `-p` match at all | Matches every protocol, ICMP included. |
| `any` with a `port` | `-p tcp` and `-p udp` | ICMP is omitted: it carries no port numbers for a port-scoped rule to name. |

The `any` selector covers at minimum TCP, UDP, and ICMPv4/6.
ICMPv6 is satisfied vacuously: `slirp4netns` is launched without
`--enable-ipv6`, so the namespace has no IPv6 route. The `ip6tables` rules
render correctly, but nothing traverses them.

**Mode selection.** Directional never resolves to the shared host namespace:

| Directional policy | Resolved mode |
|---|---|
| runtime proxy with ruleless `egress.default: "deny"` | proxy-only |
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

A config with **no `network` section** also gets a synthesized directional
default-deny policy. It runs isolated, with ingress and host loopback denied;
omitting ingress never requests a shared host namespace.

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
| `egress.default: "allow"` or direct egress rules combined with a runtime proxy | proxy-only egress opens the proxy endpoint alone; a simultaneous open default or rule list would be silently discarded and is refused |

**What the deny postures actually do.** In proxy-only and firewall-enforced
modes, `ingress.default` installs the `MXC_INGRESS` chain on `INPUT`. Ruleless
egress deny instead isolates the namespace, leaving no external inbound path.
`ingress.hostLoopback` is bidirectional, so its deny also closes
container-to-host traffic under slirp at gateway `10.0.2.2`. That drop is
lowered *ahead* of every caller rule: a broad allow, including `0.0.0.0/0`,
would otherwise win. An omitted `ingress` section enforces the same deny,
since deny is the schema's default rather than an absence of policy. This
gateway drop is IPv4 only — slirp gives the sandbox no IPv6 route to the host.

Proxy mode is the defined exception. The proxy is reached at the gateway
`10.0.2.2:<port>`, which *is* host loopback, so its chain opens that single TCP
endpoint and drops the rest of the gateway. The supported proxy-only policy
permits this exception: the endpoint named by `runtimeConfig.networkProxy` is
allowed independently of `ingress.hostLoopback`, and no other host-loopback path
is opened. A proxy config that states — or defaults to — `deny` therefore gets
the posture it writes, since the deny still covers every host-loopback path but
that endpoint. `ingress.hostLoopback` is not consulted there — `EgressPlan::for_proxy`
builds that chain, not the directional builder that lowers the drop — but the
observed result matches the contract regardless.

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
`runtimeConfig.networkProxy` into `policy.network_proxy`, pinned to a loopback
endpoint and accepted only alongside `egress.default: "deny"` with no direct
rules. That is the proxy-only posture this backend enforces. The end-to-end
test runs the supported proxy configuration with ingress denial both omitted
and explicit, checks each against expected proxy-only verdicts, and compares
the two. A direct-egress probe targets a live listener on a different port
from the proxy, so an unreachable external host cannot falsely pass the test.

`proxyPeerIdentity` stays undeclared: it is a ProcessContainer concept with no
Bubblewrap equivalent, so shared validation refuses it here.

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
routes cooperating clients through the endpoint named by
`runtimeConfig.networkProxy`. Any hostname filtering belongs to that external
proxy, not MXC host lists. The workload runs in a private network namespace
and reaches the proxy through rootless `slirp4netns` routing. This requires
no root privileges. All supported exact requests use this private-network
behavior; a missing or pre-v0.9 version is rejected, not routed to the old
shared-host-network behavior.

### How it works

0. Before anything is launched, `validate` probes the host tools this mode
   depends on — `slirp4netns`, `unshare` (checked for `--map-current-user` and
   `--keep-caps`), `sh`, `nsenter`, `iptables`, `ip6tables`, `iptables-restore`, and
   `ip6tables-restore` — so a host that is
   missing one fails immediately with a message naming it, rather than partway
   through supervisor startup. For the `iptables` family presence is not
   enough: the probe also reads the backend from the version banner and refuses
   a legacy backend whose `/run/xtables.lock` this user cannot open, because
   the unprivileged supervisor would otherwise die at the first rule. Each
   probe is bounded by a short timeout, and runs in its own process group so a
   backgrounded descendant that inherited the probe's output cannot outlive it:
   a wedged binary is reported as hung and named, instead of stalling every
   proxy-mode execution on the host indefinitely. A successful probe is cached
   for the life of the process; failures are not, so installing the missing
   tool takes effect without a restart.
1. The caller starts the proxy and names its loopback endpoint with
   `runtimeConfig.networkProxy`. The parser admits `localhost`, `127.0.0.1`,
   or `[::1]`; Bubblewrap rejects `[::1]` because its gateway reaches only
   IPv4. Use a proxy listening on `127.0.0.1` or `localhost`.
2. The runner creates a same-UID user-namespace supervisor, starts Bubblewrap
   with `--unshare-net`, and keeps the workload behind a startup barrier.
3. The supervisor attaches `slirp4netns` to Bubblewrap's private network
   namespace. Host-loopback proxy endpoints are presented to the sandbox
   through slirp's `10.0.2.2` host gateway. Once slirp is up, the supervisor
   programs a default-DROP `MXC_EGRESS` chain into that namespace via
   `nsenter`, permitting only loopback and the proxy endpoint (IPv6 gets a
   DROP-only chain, or no chain when the kernel has no IPv6 to carry), plus a
   default-DROP `MXC_INGRESS` chain on `INPUT`
   (see [Inbound](#inbound-is-closed-by-the-namespace-and-by-a-chain)).
   Each family's whole table — both chains, their rules in
   order, the terminal verdicts and the `OUTPUT` / `INPUT` hooks — is applied
   with `iptables-restore` rather than one `iptables` invocation per rule.
   One restore is one bounded netlink transaction, so a table too large for
   it is split across numbered payload files against a byte budget and
   applied in order with `-n`, so each later transaction appends. Both
   built-in hooks ride in the *last*
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
   honor the env vars and traffic flows through the external proxy, which
   applies its own host restrictions if configured. Non-cooperating clients
   are not merely unrouted — their direct traffic is dropped by the egress
   chain.

### Losing the network provider mid-run

`slirp4netns` carries the sandbox's only route, so a slirp that dies under a
running workload leaves the sandbox running against a dead network: every
connection fails with a generic transport error, and the run is attributed to
whatever the workload reported. Two checks close that, and both apply to
firewall-enforcement mode as well, since it stands up the same supervisor and
the same slirp.

**Before the workload starts.** Readiness is latched, not revoked — it says
slirp *came up*, not that it is still up — so it can already be stale by the
time the startup gate opens. The supervisor is re-checked immediately before
the gate is released. Any exit fails the run, including a successful one:
slirp's exit code says nothing about whether the sandbox still has a route.

**For the lifetime of the workload.** The supervisor inherits the write end of
a pipe nothing ever writes to, and slirp inherits it in turn; the runner keeps
only the read end. That descriptor reaches EOF when *both* have exited, which
is what separates a dead network from an orphaned slirp still carrying traffic
after its supervisor was killed. A monitor thread in the executor watches the
descriptor, terminates the sandbox when it closes, and fails the run naming the
supervisor's exit status and a bounded tail of its stderr:

```text
wait failed: Bubblewrap: the sandbox lost its network provider while the
workload was running; the proxy network supervisor exited with exit status: 137
(stderr: sent tapfd=7 for tap0
received tapfd=7
Killed)
```

The monitor is disarmed *before* teardown stops the supervisor, so an ordinary
shutdown — which closes the same descriptor — is never reported as a loss. Only
an exit is detected; see [Limitations](#limitations).

### Example: proxy on v0.9

```json
{
  "version": "0.9.0-alpha",
  "containment": "bubblewrap",
  "process": { "commandLine": "curl -fsSL https://example.com" },
  "network": {
    "egress": { "default": "deny" },
    "ingress": { "default": "deny", "hostLoopback": "deny" }
  },
  "runtimeConfig": { "networkProxy": "http://127.0.0.1:8080" }
}
```

A proxy request is the proxy-only posture, so `egress.default` must be `deny`
with no `allow` / `deny` rules; the chain opens the proxy endpoint alone.

Exact contracts before v0.9 are retired. Legacy `network.proxy` and host-list
configurations cannot be expressed by declaring v0.9; use
`runtimeConfig.networkProxy` with a ruleless, deny-default directional egress
policy as shown above. The external proxy enforces any host filtering itself.

### Checking host support before you run

There is deliberately **no automatic fallback**: a `0.9.0-alpha`+ proxy config
that cannot configure private networking fails rather than silently degrading to
the weaker shared-host-network model, because a silent degradation would
reintroduce exactly the proxy-bypass this mode exists to close.

So that callers do not have to discover a missing dependency by failing a run,
the host requirements are reported ahead of time.

From the command line:

```bash
lxc-exec --available-backends
```

This emits the available backends as JSON and exits without running the workload.
Bubblewrap advertises a `proxyEnforcement` capability when the host can enforce
proxy-only egress, and a `warnings` entry explaining why when it cannot:

```json
[
  { "backend": "bubblewrap", "capabilities": ["proxyEnforcement"] },
  { "backend": "lxc" }
]
```

From the TypeScript SDK, `getPlatformSupport()` surfaces the same fact as
`bubblewrapNetwork`; from Rust, `mxc_engine::platform_support()` surfaces it as
`bubblewrap_network`. Both are reported **fail closed** — if the probe cannot
run, the result is `unsupported`, never "unknown".

This check is advisory, not a gate. The runner still probes the dependencies at
launch: the probe runs in a different process and at an earlier time, so a
package can be removed in between.

The pre-flight walk is bounded to a few seconds in total, tighter than the
per-tool timeout the launch path allows itself, so `getPlatformSupport()`
answers promptly. A host slow enough to exhaust that budget is reported
`unsupported` with a warning naming the timeout — the run itself is not
subject to that budget, so such a host may still launch successfully.

It is also not exhaustive. It confirms `slirp4netns`, the `iptables` tooling and
a usable backend, and that the kernel actually grants the unprivileged user and
network namespaces `bwrap` will ask for — but a missing `nf_conntrack` module is
only detectable once the rules are installed, so that case still surfaces at
launch with a targeted error message rather than here.

Each call re-walks the dependencies, so removing a package is reflected by the
next call and the pre-flight answer never stands in for the runner's own check
at launch. This applies to direct Rust and CLI invocations; the TypeScript
`getPlatformSupport()` memoizes its result for the lifetime of the SDK module,
so a Node caller keeps the first answer it received.

### Caveats

- **Host loopback is not sandbox loopback**: inside the private namespace
  `127.0.0.1` means *the sandbox itself*, not the host. The configured proxy
  remains reachable at slirp's gateway address `10.0.2.2`; the runner
  rewrites its loopback endpoint so the sandbox can find it. Other
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
- **Cooperative routing, enforced egress (v0.9+)**: the runner injects
  `HTTP_PROXY` / `HTTPS_PROXY` so cooperating clients route through the proxy,
  and additionally programs a default-DROP egress chain inside the sandbox's
  private network namespace. Clients that ignore the env vars (raw sockets,
  custom HTTP clients) can no longer reach the network directly: only loopback
  and the proxy endpoint are permitted. DNS is deliberately **not** opened —
  the proxy resolves on the workload's behalf. IPv6 egress is denied outright.

  An endpoint on `127.0.0.1` or `localhost` is rewritten to the gateway.
  Although the parser also recognizes `[::1]` as loopback, Bubblewrap
  **rejects it before launch**: a proxy bound only to IPv6 loopback cannot
  accept the gateway's IPv4 connection. Hostnames other than `localhost`,
  additional `127.0.0.0/8` addresses, and wildcard addresses are not valid
  `runtimeConfig.networkProxy` endpoints in an exact v0.9 request.
- **Proxy-only, not direct filtering**: `runtimeConfig.networkProxy` requires
  `egress.default: "deny"` and no `egress.allow` or `egress.deny` rules. The
  parser rejects combinations that would discard direct rules or permit
  bypassing the proxy.
- **External proxy delegates host filtering**: MXC does not send hostname
  lists to the proxy. Configure any destination allow/deny policy in the
  external proxy itself; its own availability and behavior are the caller's
  responsibility.
- **HTTPS via CONNECT**: HTTP clients use `CONNECT` tunnels for TLS, so
  certificate validation continues to work end-to-end (the proxy does not
  see plaintext).

### Choosing address or hostname restrictions

`network.egress.allow` and `network.egress.deny` filter IP addresses or CIDR
blocks, not DNS names. Do not put a hostname in a `cidr` field: Bubblewrap
cannot enforce an IP rule against the workload's changing DNS answers and
rejects the request. If policy must inspect requested hostnames, use
`runtimeConfig.networkProxy` with a separately configured external proxy.
The exact v0.9 contract provides no MXC-managed host-list policy for that proxy.

## Comparison with LXC

| Aspect | LXC | Bubblewrap |
|--------|-----|------------|
| Privileges | Root required | Unprivileged (user namespaces) |
| Rootfs | Downloads distro rootfs | Bind-mounts host filesystem |
| Startup | Create → Start → Attach | Single `bwrap` exec; proxy-only and firewall-enforced modes add a user/network-namespace supervisor, `slirp4netns`, and namespace-local firewall chains |
| Network isolation | iptables + veth | `--unshare-net` for ruleless deny; private netns + slirp4netns and namespace-local iptables for proxy or firewall-enforced policies |
| Dependencies | `lxc-*` tools, templates | `bwrap`; proxy and firewall-enforced modes also need `slirp4netns`, util-linux `unshare` and `nsenter`, a POSIX `sh`, plus `iptables`, `ip6tables` and their `-restore` counterparts |
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

- **Linux only** — Bubblewrap requires Linux kernel namespaces
- **Deny-by-default filesystem** — the sandbox sees a minimal allowlist
  of host paths (system binaries, libs, `/etc`, DNS stub-resolver dirs)
  and nothing else. `$HOME`, `/opt`, `/var`, `/sys`, `/run/user/<uid>`,
  and `/usr/local` are invisible unless explicitly listed in
  `readonlyPaths` / `readwritePaths`. There is no separate rootfs — the
  visible paths are bind-mounted from the host.
- **Network filtering** — `network.egress` allows or denies numeric addresses
  and CIDRs without root (rules live in the sandbox's own namespace). Allowed
  IPv6 destinations remain unreachable until slirp supports IPv6 here.
  `runtimeConfig.networkProxy` restricts direct egress to the configured
  loopback proxy endpoint; hostname policy belongs to that external proxy.
- **No state-aware lifecycle** — Bubblewrap implements `ScriptRunner` only
  (one-shot), not `StatefulSandboxBackend`
- **Provider-loss detection is exit-based** — in the private-namespace modes a
  `slirp4netns` that exits mid-run fails the run; one that is alive but wedged
  is not detected, and reaches the workload as an unreachable network
