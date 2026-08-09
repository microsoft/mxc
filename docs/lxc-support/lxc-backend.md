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

Network policies are enforced with parallel `iptables` and `ip6tables` chains scoped to the container's virtual ethernet (veth) interface:

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

Two limits on that guarantee are worth stating plainly, because "deny always
wins" is not true without them:

- **DNS is exempt.** The base chain accepts UDP and TCP destination port 53
  unconditionally and is installed ahead of the generated policy rules, so
  port-53 traffic to a blocked destination is accepted before its DROP rule is
  reached. Narrowing that rule needs to know which resolver addresses are
  legitimate, and no schema field carries them today.
- **A hostname in both lists is resolved twice.** Each list entry is resolved
  independently, so a name behind round-robin DNS can return one address for
  the `blockedHosts` entry and a different one for the `allowedHosts` entry.
  The guarantee holds for *addresses*, not for names. Use literal IPs or CIDRs
  when a destination must be denied deterministically.

`allowedHosts` and `blockedHosts` entries may be bare IPv4/IPv6 literals, IPv4/IPv6 CIDR blocks, or hostnames. Hostnames are resolved to both A and AAAA records; IPv4 destinations are applied to the `iptables` chain and IPv6 destinations are applied to the `ip6tables` chain. Host-list rules match all ports and protocols; port- and protocol-specific egress rules are not supported.

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
| veth enslaved to a bridge (the default LXC topology) | `-m physdev --physdev-in <veth>` |

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

Firewall state is torn down automatically with best-effort removal of the `FORWARD` hooks and both per-container chains; there is no network-policy opt-out field. Setup failures after partial creation are rolled back before returning an error, so retries do not trip over leftover chains.

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
