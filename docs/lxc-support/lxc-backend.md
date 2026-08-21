# LXC Container Backend

The LXC backend provides Linux container isolation using [LXC (Linux Containers)](https://linuxcontainers.org/lxc/).

## Overview

On Linux, MXC uses LXC to create lightweight containers for script execution. This provides:

- **Process isolation** via Linux namespaces (PID, mount, network, user)
- **Filesystem isolation** via bind mounts with read-only/read-write/denied enforcement
- **Network isolation** via iptables/nftables rules scoped to the container's virtual network interface

## Prerequisites

- Linux kernel 4.x or later
- LXC >= 5.0 installed (`liblxc-dev` for building, `lxc-utils` for runtime)
- Root privileges (or unprivileged LXC configured)

### Installation

**Debian/Ubuntu:**
```bash
sudo apt install lxc lxc-utils liblxc-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install lxc lxc-devel
```

**Arch Linux:**
```bash
sudo pacman -S lxc
```

## Configuration

The LXC backend uses the same JSON configuration schema as the Windows backends, with the `containment` field set to `"lxc"` and a required `lxc` section specifying the distribution and release:

```json
{
    "containerId": "my-sandbox",
    "containment": "lxc",
    "process": {
        "commandLine": "echo 'Hello from container'"
    },
    "lifecycle": {
        "destroyOnExit": true
    },
    "lxc": {
        "distribution": "alpine",
        "release": "3.20"
    },
    "filesystem": {
        "readwritePaths": ["/tmp/output"],
        "readonlyPaths": ["/opt/tools"],
        "deniedPaths": ["/etc/shadow"]
    },
    "network": {
        "defaultPolicy": "block",
        "allowedHosts": ["api.github.com"],
        "blockedHosts": ["evil.example.com"]
    }
}
```

### LXC-Specific Options

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `distribution` | string | **Yes** | Linux distribution for the container rootfs (e.g., `"alpine"`, `"ubuntu"`) |
| `release` | string | **Yes** | Distribution release version (e.g., `"3.20"`, `"24.04"`) |

### Supported Distributions

The `distribution` and `release` fields control which LXC template is used to create the container rootfs. Common options:

| Distribution | Release | Notes |
|-------------|---------|-------|
| `alpine` | `3.21`, `3.23` | Minimal footprint, fast startup |
| `ubuntu` | `22.04`, `24.04` | Full-featured, large ecosystem |
| `debian` | `bookworm`, `trixie` | Stable, well-tested |
| `fedora` | `39`, `40` | Modern packages |

### Process Environment and Working Directory

The `process.cwd` and `process.env` fields from the standard schema are honored inside the container:

| Field | LXC Implementation | Notes |
|-------|-------------------|-------|
| `process.cwd` | `cd -- "$1" && exec /bin/sh -c "$2"` wrapper prelude, with the cwd passed as a positional argument | Empty string preserves the container default cwd. A nonexistent or non-permitted path surfaces as a generic non-zero exit (typically `1`, from `cd`'s own status); callers needing strong cwd validation should pre-check the path. The positional-arg trick means cwd values with spaces, quotes, `$vars`, or backticks pass through verbatim with no shell escaping. |
| `process.env` | Each `KEY=VAL` entry becomes a repeated `--set-var=KEY=VAL` flag to `lxc-attach` | Malformed entries — those without `=` (e.g. `"BADENTRY"`) or with an empty key (e.g. `"=foo"`) — are silently skipped. Embedded `=` in the value (e.g. `"X=a=b=c"`) is preserved. |

**Replace semantics.** When `process.env` is non-empty, `lxc-exec` also passes `--clear-env` to `lxc-attach` so the host environment does **not** leak into the sandbox, regardless of how many entries survive the malformed-skip. This is the posture `lxc-attach(1)` recommends for sandbox-spawn callers. If a variable is set in both the host and `process.env`, the `process.env` value wins.

When `process.env` is empty (or absent), the legacy keep-env behavior is preserved and the host environment is inherited.

**Residual baseline.** Even with `--clear-env`, `lxc-attach` injects a small baseline (`container`, `HOME`, `TERM`, a default `PATH`, `USER`) and applies any `lxc.environment` entries from the container config. These layers sit below the user vars from `process.env`.

## Filesystem Policy

Filesystem policies are enforced via bind mounts in the container configuration:

| Policy | LXC Implementation | Effect |
|--------|-------------------|--------|
| `readwritePaths` | `bind,rw` mount entry | Script can read and write |
| `readonlyPaths` | `bind,ro` mount entry | Script can read but not write |
| `deniedPaths` | No mount / tmpfs overlay | Path is not accessible in container |

## Network Policy

Network policy has two independent halves: outbound (egress) filtering on the host, described first, and inbound (ingress) filtering inside the container, described under [Inbound (ingress) policy](#inbound-ingress-policy).

Which configurations reach the firewall depends on what the policy restricts, never on `enforcementMode`.  A policy is owed the firewall when its default is `block`, when it names any `allowedHosts` or `blockedHosts`, when it enables a proxy, or when it states a schema 0.8 `egress` posture — `ContainerPolicy::requires_firewall`.  A caller may get more enforcement than the mode asked for, never less.  Reading the mode instead let a restrictive policy start with an open chain: schema 0.8 has no `enforcementMode` to set, since the schema rejects it written beside `egress`, so every 0.8 policy carried the default `capabilities` and would have gone unenforced while reporting success.  Only a policy that restricts nothing at all is skipped.

Outbound policies are enforced with parallel `iptables` and `ip6tables` chains scoped to the container's virtual ethernet (veth) interface:

| Policy | Implementation |
|--------|---------------|
| `defaultPolicy: "block"` | Final DROP rule in the container chain |
| `defaultPolicy: "allow"` | Final ACCEPT rule in the container chain |
| `allowedHosts` | ACCEPT rules for IP literals, CIDR blocks, or resolved hostnames |
| `blockedHosts` | DROP rules for IP literals, CIDR blocks, or resolved hostnames, emitted *before* the ACCEPT rules |

**A deny wins over an overlapping allow.** `iptables` evaluates a chain top to
bottom and stops at the first match, so precedence is decided purely by
emission order. All `blockedHosts` rules are emitted ahead of all
`allowedHosts` rules, which means a destination named by both lists is dropped.
Without that ordering an allow entry broad enough to cover a blocked
destination — `0.0.0.0/0`, or a CIDR containing the blocked address — silently
defeats the block, and the resulting chain looks fully populated while
filtering nothing.

Three limits on that guarantee are worth stating plainly, because "deny always
wins" is not true without them:

- **An already-established flow is exempt.** The base chain accepts
  `ESTABLISHED,RELATED` unconditionally and is installed ahead of the generated
  policy rules. A flow that conntrack already knows keeps matching that rule
  rather than its `blockedHosts` DROP, so the guarantee covers flows opened
  after the chain exists — not one opened during the window between container
  start and rule application, nor one surviving in the host's conntrack table
  from an earlier run of a container with the same name.
- **DNS is exempt.** The base chain accepts UDP and TCP destination port 53
  unconditionally and is installed ahead of the generated policy rules, so
  port-53 traffic to a blocked destination is accepted before its DROP rule is
  reached. Narrowing that rule needs to know which resolver addresses are
  legitimate, and no schema field carries them today. This exemption is
  legacy-only — schema 0.8 has a field for it and does not carry the exemption.
- **A hostname in both lists is resolved twice.** Each list entry is resolved
  independently, so a name behind round-robin DNS can return one address for
  the `blockedHosts` entry and a different one for the `allowedHosts` entry.
  The guarantee holds for *addresses*, not for names. Use literal IPs or CIDRs
  when a destination must be denied deterministically.

`allowedHosts` and `blockedHosts` entries may be bare IPv4/IPv6 literals, IPv4/IPv6 CIDR blocks, or hostnames. Hostnames are resolved to both A and AAAA records; IPv4 destinations are applied to the `iptables` chain and IPv6 destinations are applied to the `ip6tables` chain. Host-list rules match all ports and protocols. Port- and protocol-specific egress rules are a schema 0.8 feature, described below; the legacy host lists cannot express them.

An entry that resolves to nothing — an unknown hostname, or a CIDR prefix out
of range for its family — cannot be turned into a rule. What that costs
depends on the entry and on `defaultPolicy`:

| Entry | `defaultPolicy` | Behavior |
|-------|-----------------|----------|
| `allowedHosts` | either | Reported as unresolved and skipped. Failing to write an ACCEPT rule can only make the policy more restrictive |
| `blockedHosts` | `block` | Reported as unresolved and skipped. The closing DROP already denies the destination, so the unwritten rule was redundant |
| `blockedHosts` | `allow` | **Fails firewall setup.** The chain ends in ACCEPT, so the unwritten DROP was the only thing that would have denied that destination, and skipping it silently converts a deny into an allow |

One gap remains open and is not detected: under `defaultPolicy: "block"`, an
`allowedHosts` entry broad enough to cover a destination whose `blockedHosts`
rule went unwritten still reaches that destination. Detecting it would require
the address the failed entry was *meant* to resolve to, which is by definition
unavailable, so no check over the policy text can be complete — and a partial
check would imply a guarantee this code cannot make.

### Schema 0.8 egress rules

Schema 0.8 replaces the host lists with `network.egress`, which carries a
per-direction default and two rule lists. Peers are CIDRs only — the shape has
no hostname form, and the resolution failure modes tabulated above therefore
have no 0.8 equivalent.

| Field | Implementation |
|-------|---------------|
| `egress.default: "deny"` | Final DROP rule in the container chain |
| `egress.default: "allow"` | Final ACCEPT rule in the container chain |
| `egress.deny[]` | DROP rules, emitted *before* the allow rules |
| `egress.allow[]` | ACCEPT rules |
| `to[].cidr` | `-d <cidr>`, routed to the `iptables` or `ip6tables` chain by address family |
| `to[].except[]` | Carve-outs within the peer's CIDR |
| `ports[].protocol` | `-p tcp`, `-p udp`, or ICMP; `any` matches every protocol |
| `ports[].port`, `ports[].endPort` | `--dport <port>` or `--dport <port>:<endPort>` |

Omitting `to` selects every destination, and omitting `ports` selects every
port and protocol. Deny-before-allow ordering matches the host lists above, as
does the `ESTABLISHED,RELATED` exemption: the base chain accepts a flow that
conntrack already knows, ahead of the generated rules.

**DNS is not exempt here.** The unconditional port 53 accept is emitted only on
the legacy path. Schema 0.8 governs DNS with the same rules as every other
destination — a resolver the policy never allowed is a resolver the container
cannot reach, and reaching one takes an `egress.allow` rule naming its address.
That is the GA decision, not a local choice: [D3](../sandbox-policy/0.8.0/networking/networking.md)
states that DNS is not a first-class policy surface and that queries fail when
the rules do not allow the resolver's IP. Carrying the exemption into a
directional posture would accept port 53 to every destination ahead of the
generated rules, leaving an `egress.default: "deny"` container a standing
DNS-tunnel path — the same path the proxy posture refuses to open.

LXC's own bridge resolver is addressed to the bridge gateway and traverses
`INPUT` rather than this `FORWARD` chain; dropping the exemption does not reach
it. What a 0.8 container loses is the unasked-for route to an external
resolver.

Three points where one schema field does not map to one iptables rule:

- **`protocol: "any"` with a port expands to two rules**, one TCP and one UDP.
  `-p all --dport` is not a legal match, and ICMP is excluded from the
  expansion because it carries no port.
- **ICMP is named by address family.** A rule reaching the IPv4 chain matches
  `icmp` and the same rule reaching the IPv6 chain matches `icmpv6`, because
  `ip6tables` rejects `-p icmp` outright.
- **`except` takes the direction's default verdict.** The excepted range sits
  outside the rule that names it, so it receives whatever `egress.default`
  would have given it, emitted ahead of the rule it narrows. Nothing is emitted
  when the rule's own action already agrees with the default, because the range
  reaches the identical verdict at the closing rule. The case that makes this
  matter is a `deny` rule under `egress.default: allow`: the excepted range is
  the operator asking for addresses to be spared, and leaving it to the peer's
  DROP would block them.

Before programming the IPv6 chain, MXC probes `ip6tables` with a read-only `ip6tables -S` and classifies the result three ways:

| Classification | Condition | Behavior |
|----------------|-----------|----------|
| `Available` | The `ip6tables` probe succeeds | Programs the parallel `ip6tables` chain alongside the IPv4 chain |
| `KernelIpv6Disabled` | The probe fails **and** the host has no active IPv6 | Skips the IPv6 chain and logs that there is no IPv6 egress to filter — safe, because there is nothing to filter |
| `UnusableButIpv6Active` | The probe fails **and** the host has active IPv6 | **Fails firewall setup** rather than applying an IPv4-only policy that would silently leave IPv6 egress unfiltered |

Host IPv6 activity is read from `/proc/net/if_inet6`: a non-loopback interface with an IPv6 address counts as active, while loopback-only `::1` on `lo` (present even on IPv4-only hosts) does not. If that file cannot be read at all — as opposed to being absent, which means IPv6 is disabled — the state is treated as *unknown* rather than as a confirmed "IPv6 is off", so an unreadable IPv6 state fails closed instead of leaving IPv6 unfiltered.

The chains are hooked into `FORWARD` for container egress with **up to two
rules per family**, because the input interface `FORWARD` sees depends on how
the veth is attached:

| Attachment | Rule that matches |
|------------|-------------------|
| veth routed directly by the host | `-i <veth>` |
| veth attached to a bridge (the default LXC topology) | `-m physdev --physdev-in <veth>` |

The two are mutually exclusive for any given packet, so nothing is counted
twice. Installing only `-i <veth>` is what previously let a fully populated
deny-all chain sit in the ruleset filtering nothing on the default bridged
topology.

The `physdev` rule is required only on a bridged veth. On a directly routed
veth a host whose kernel lacks the `physdev` match logs a warning and
continues with the interface rule alone, which is the rule that matches there;
on a bridged veth the same failure is fatal, because `physdev` is the only
rule that could ever match.

A bridged veth additionally requires `br_netfilter` to be delivering bridged
packets to iptables. With `/proc/sys/net/bridge/bridge-nf-call-iptables` absent
or `0`, both hook rules install cleanly and neither ever fires. MXC reads that
file and **fails firewall setup** rather than reporting success for a chain
that could never be reached. When the IPv6 chain is programmed,
`/proc/sys/net/bridge/bridge-nf-call-ip6tables` is checked separately and to
the same standard.

If MXC cannot discover the container veth at all, firewall setup **fails** and
the partially created chains are rolled back. An unhooked chain is never
traversed, so reporting success would hand the caller a deny-all chain that
filters nothing — strictly worse than no firewall, because it looks enforced.
Installing the rules host-wide instead is not an option either: unscoped, they
would apply to every container and to the host's own traffic.

Egress firewall state is torn down automatically with best-effort removal of the `FORWARD` hooks and both per-container chains; there is no egress network-policy opt-out field, and `preservePolicy` does not currently keep the egress chains alive. Setup failures after partial creation are rolled back before returning an error, so retries do not trip over leftover chains.

### Inbound (ingress) policy

Inbound filtering is a separate chain from the egress chains above, and it lives **inside the container's own network namespace** rather than on the host. Every command is issued through `nsenter -t <init-pid> -n`, so the container's init PID is mandatory. When a firewall enforcement mode is requested and MXC cannot discover that PID, the run is aborted rather than started with inbound enforcement silently disabled. This is LXC-specific, and the Bubblewrap comparison is policy-dependent rather than absolute: Bubblewrap gives the sandbox its own network namespace via `--unshare-net` when the default policy is `block` with no `allowedHosts`, no `blockedHosts`, and no proxy, and shares the host's namespace otherwise. It installs no inbound chain in either case — under `--unshare-net` because nothing outside the sandbox can reach in, and when the namespace is shared because an inbound chain there would be host-wide.

Every `iptables`/`ip6tables` subprocess is spawned with `LC_ALL=C` and `LANG=C`. Teardown decides whether a non-zero exit means "already absent" by matching iptables' own diagnostic text, and that text is localized, so an unpinned locale would turn a benign already-absent result on a non-English host into a fatal error and abort every fresh install.

The rows below describe every run that reaches the firewall, which is every policy with something to enforce, in either schema. The ingress path takes the same gate as the egress chains. A policy that restricts nothing installs nothing at all, which leaves inbound unfiltered and accepts `allowLocalNetwork: true` rather than refusing it. Inbound default-deny is a property of the runs that reach the firewall, not of every LXC run.

Schema 0.8 states the same posture with `ingress.default` and `ingress.hostLoopback`. LXC has one inbound chain rather than two independent controls, and the mapping is lossless for the values it implements: `deny` on either field is served by the default-deny chain, and `allow` on either is refused by the not-yet-implemented error below. The field named in that error is whichever one the operator actually wrote.

| Policy (any config with something to enforce, in either schema) | Implementation |
|--------|---------------|
| `allowLocalNetwork: false` (default), or `ingress.default`/`ingress.hostLoopback` of `deny` | Container `INPUT` chain drops new inbound connections |
| `allowLocalNetwork: true`, or `ingress.default`/`ingress.hostLoopback` of `allow` | **Not yet implemented.** Firewall setup fails with an explicit not-yet-implemented error rather than falling back to an unenforced accept |

The chain uses an `MXCI-` prefix so it can never collide with, or be torn down for, the `MXC-` egress chain of the same container. Loopback, established and related traffic, and — for IPv6 — the ICMPv6 types required for Neighbor Discovery and Path MTU Discovery are permitted ahead of the terminal drop, so a default-deny container can still complete connections it initiated itself.

IPv6 is classified with the same three-way probe as egress, but against the *container* namespace rather than the host, and from a different signal. A host that reports IPv6 disabled says nothing about the namespace actually being filtered. `UnusableButIpv6Active` inside that namespace fails the run closed rather than enforcing an IPv4-only inbound policy that would leave inbound IPv6 open.

The signal differs because a container is not a long-running host. Egress reads the *contents* of `/proc/net/if_inet6` and treats loopback-only as inactive, which is a fair reading for a host that has been up for a while. A container has not been: `wait_for_network` returns on the first address of *any* family, so a container whose IPv6 address has not arrived yet presents exactly the same address-less file as one with IPv6 switched off. Inbound therefore keys on that file's *existence*, which is stable — the kernel never creates `/proc/<pid>/net/if_inet6` when IPv6 is disabled at boot. A present but address-less file counts as active, so an unusable `ip6tables` fails the run closed instead of installing IPv4-only enforcement that an IPv6 address arriving moments later would slip past. The trade is deliberate and one-directional: this can abort a run that the egress rule would have let proceed, never the reverse.

Inbound rules are installed after the container starts and after egress setup completes, so inbound is unfiltered for a short interval at container startup. The workload script is executed only after installation finishes, so no sandboxed code runs during that interval and the exposure is to external traffic only. Narrowing this interval is tracked separately.

Inbound default-deny is not a containment boundary against the sandboxed workload. Because the chain lives in the container's own network namespace, the workload can reach it: MXC creates containers from the stock `lxc-create -t download` template and never sets `lxc.cap.drop` or `lxc.cap.keep`, so LXC's defaults apply — the shared default drops only `mac_admin`, `mac_override`, `sys_time`, `sys_module`, and `sys_rawio`, and an unprivileged user-namespace container starts with a full capability set. `lxc-attach` is invoked without `-u` or `-g`, so the workload runs as container root and holds `CAP_NET_ADMIN` in the namespace the chain lives in, where it can flush or delete it. The egress chains are not exposed this way: they sit on the host and hook into `FORWARD` by the container's host-side veth, out of the workload's reach. The asymmetry follows from where each chain is installed. Inbound default-deny therefore closes off external reachability — including for services the workload itself starts — for any workload that does not deliberately tear it down, and does not survive one that does. Making inbound enforcement tamper-proof is tracked in issue #854.

Unlike egress, the inbound chain honors the lifecycle's `preservePolicy`: when it is set *and* installation succeeded, the chain is deliberately left in place after the run for inspection. A partially installed chain from a failed run is always torn down regardless of the setting.

### Cooperative proxy

`network.proxy` puts the container in a "deny all except the proxy" posture:
egress is restricted to the proxy endpoint, and `HTTP_PROXY`/`HTTPS_PROXY` are
injected so a cooperating client uses it. The env vars are the routing hint;
the firewall is the enforcement, so an application that ignores them cannot
reach the internet directly.

The chain is hooked into `FORWARD`, so what it governs is traffic the host
*routes* on the container's behalf. Traffic addressed to the bridge gateway
itself — where LXC's `dnsmasq` listens, and where a host-local proxy would run
— is delivered locally and traverses `INPUT`, which this chain does not hook.
Closing that path needs an INPUT hook and is tracked separately, so "reaches
nothing" is accurate for forwarded egress and not for host-local destinations.

Only the `{ "url": "http://proxy.example:8080" }` form is accepted. The LXC
container has its own network namespace, so `{ "localhost": <port> }` names the
*container's* loopback rather than the host's — the injected proxy would be
unreachable and the firewall rule would never match. `{ "builtinTestServer":
true }` is rejected for the same reason, as is a `url` whose host is a loopback
literal.

Two further constraints are enforced at parse time, both rejections rather than
silent corrections:

- **`enforcementMode` must be `firewall` or `both`.** Under the default
  `capabilities` mode no iptables rules are installed, so the proxy env vars
  would be injected while direct egress stayed open — a config that reads as
  deny-all-except-proxy and enforces neither half. MXC refuses it rather than
  auto-promoting the mode, so a stated enforcement level is never silently
  rewritten.
- **The `url` must not carry credentials.** LXC passes the proxy URL to
  `lxc-attach` as a `--set-var` argument, and process arguments are
  world-readable through `/proc/<pid>/cmdline`, so inline `user:pass@` would be
  visible to every local user for the lifetime of the command. Supply the
  credentials to the proxy itself instead.

The chain a proxied container gets differs from the ordinary one in four ways,
each of which would otherwise be a hole in the posture:

| Ordinary chain | Proxied chain | Why |
|----------------|---------------|-----|
| Terminal rule follows `defaultPolicy` | Terminal rule is always DROP | An ACCEPT terminal would make the proxy rule above it meaningless |
| Accepts UDP/TCP port 53 | No DNS rule | An unscoped port-53 accept is a standing DNS-tunnel exfil path through a deny-all posture |
| Accepts `-i lo` and `ESTABLISHED,RELATED` | Neither | Neither describes traffic this chain sees, and the conntrack rule would carry flows the proxy never brokered |
| Programs `allowedHosts` and `blockedHosts` | Programs neither | A block entry is redundant under the closing DROP, and an allow entry naming anything but the proxy contradicts the model |

The IPv6 chain of a proxied container carries its closing DROP and nothing
else, because the proxy rule is emitted with IPv4 `iptables` only. An IPv6
proxy endpoint is therefore rejected outright rather than silently discarded.

With DNS closed, a container handed a proxy URL naming a hostname has no
resolver to find it with. MXC resolves the proxy once, when it builds the
firewall rule, and writes that same mapping into the container's `/etc/hosts`
before the script runs — so the name resolves, and it resolves to an address
the chain allows. The URL itself is left alone: rewriting its host to an IP
literal would break SNI and certificate validation for an `https://` proxy.
Every address the proxy host resolved to is opened, since they all belong to
that same proxy. If the hosts entry cannot be written, execution **fails**
rather than running a container whose proxy is unreachable.

## Usage

### Command Line

```bash
# Run with config file
./lxc-exec config.json

# Run with base64-encoded config
./lxc-exec --config-base64 <base64-string>

# Run with debug output
./lxc-exec --debug config.json

# Delete a container
./lxc-exec --delete --containername my-sandbox
```

### SDK

```typescript
import { spawnSandbox, SandboxPolicy } from '@microsoft/mxc-sdk';

const policy: SandboxPolicy = {
    filesystem: {
        readwritePaths: ['/tmp/output'],
        readonlyPaths: ['/opt/tools'],
    },
    network: {
        allowOutbound: false,
    },
};

// On Linux, this automatically uses lxc-exec
const pty = spawnSandbox('echo hello', policy);
pty.onData((data) => console.log(data));
pty.onExit((e) => console.log('Exit:', e.exitCode));
```

## Building

```bash
# Full build (Rust + SDK)
./build.sh

# Debug build
./build.sh --debug

# Rust only
./build.sh --rust-only
```

## Comparison with Windows Backends

| Feature | AppContainer (Windows) | Sandbox (Windows) | LXC (Linux) |
|---------|----------------------|-------------------|-------------|
| Isolation level | Process | VM | Container |
| Startup time | Fast (~10ms) | Slow (~30s) | Medium (~1s) |
| Filesystem | BFS policy | VM filesystem | Bind mounts |
| Network | Windows Firewall | Guest agent | iptables/nftables |
| Privileges | Optional admin | Admin | Root (or unprivileged LXC) |
