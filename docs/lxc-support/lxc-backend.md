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

Network policies are enforced via iptables/ip6tables rules in a per-container
chain (`MXC-<container>`), hooked on the container's host-side virtual ethernet
(veth) interface:

| Policy | Implementation |
|--------|---------------|
| `defaultPolicy: "block"` | Chain closes with DROP |
| `defaultPolicy: "allow"` | Chain closes with ACCEPT |
| `allowedHosts` | ACCEPT rules for specific IPs/CIDRs |
| `blockedHosts` | DROP rules for specific IPs/CIDRs |
| `proxy` | ACCEPT for the proxy endpoint only, then DROP |

Rules are automatically cleaned up when the container exits (if `removeRulesOnExit` is `true`).

**Hooked on `-i <veth>`, in both FORWARD and INPUT.** Container-originated
packets arrive at the host on the host-side veth, so egress matches by *input*
interface. FORWARD alone is not enough: netfilter routes packets addressed to the
host itself through INPUT and never through FORWARD, so a FORWARD-only hook would
leave the bridge gateway and every host service reachable from inside the
container. Both hooks share the chain, so a host-local proxy is still permitted by
its own ACCEPT rule. DHCP (`udp/67`, and `udp/547` for DHCPv6) is accepted ahead of
the INPUT jump so lease renewal against the bridge's dnsmasq keeps working.

**Deny wins.** Rules are emitted deny-list first, then the DNS carve-out, then the
allow-list, then the default. Under iptables' first-match-wins a destination named
in both lists is dropped.

**No conntrack exemption.** The chain has no `ESTABLISHED,RELATED` accept. Reply
traffic arrives on `-o <veth>` and never traverses the chain, so such a rule would
not help replies — it would only let flows opened *before* the chain was installed
keep running through a deny-all policy.

**DNS.** Outside proxy mode, `udp/tcp` port 53 is accepted so the container can
resolve the names in `allowedHosts` / `blockedHosts`. In proxy mode the proxy host
is resolved once on the host and the container is handed the literal address, so
it never needs a resolver and port 53 stays shut.

**IPv4 only for host lists.** Firewall mode resolves `allowedHosts` /
`blockedHosts` to IPv4 addresses only; AAAA (IPv6) records and IPv6 literals are
silently dropped. A host that has only AAAA records is effectively unreachable from
the sandbox under firewall mode. The parallel ip6tables chain still carries the
default stance, so IPv6 egress is dropped whenever IPv4 egress is.

**ip6tables is required when the policy denies by default.** If `ip6tables` cannot
be run but the host has a live IPv6 stack (`/proc/net/if_inet6` lists addresses),
startup fails rather than silently leaving IPv6 unfiltered. On a host with no IPv6
stack the v6 chain is skipped and the IPv4 policy is enforced alone.

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
