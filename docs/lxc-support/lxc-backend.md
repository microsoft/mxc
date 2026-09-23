# LXC Container Backend

The LXC backend provides Linux container isolation using [LXC (Linux Containers)](https://linuxcontainers.org/lxc/).

For exact `0.9.0-alpha`, networking is directional-only: use `network.egress`
and `network.ingress`. LXC rejects `runtimeConfig.networkProxy`, so a v0.9 LXC
request has no proxy surface at all — see [Proxy](#proxy) below.
Legacy host lists and enforcement-mode fields in older examples are not
accepted in v0.9. Preserve their original published contract when reproducing
legacy behavior; do not relabel an old request as v0.9 without migrating its
policy. See [the schema migration reference](../schema.md).

## Overview

Creates an LXC container to provide:

- **Process isolation** via Linux namespaces (PID, mount, network, user)
- **Filesystem isolation** via bind mounts with read-only/read-write/denied enforcement
- **Network isolation** via iptables rules inside the container's own network namespace

## Prerequisites

- Linux kernel >= 2.6.32, or >= 3.12 to run unprivileged
- LXC >= 5.0 installed (`liblxc-dev` for building, `lxc-utils` for runtime)
- Root privileges, or unprivileged LXC for a policy that asks for no network.
  Filtering egress or ingress installs iptables rules in the container's
  network namespace, which requires root.

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

Note the required field lxc.

```json
{
    "version": "0.8.0-alpha",
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
        "enforcementMode": "firewall",
        "allowedHosts": ["api.github.com"],
        "blockedHosts": ["notapi.example.com"]
    }
}
```

### LXC-Specific Options

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `distribution` | string | **Yes** | Linux distribution for the container rootfs (e.g., `"alpine"`, `"ubuntu"`) |
| `release` | string | **Yes** | Distribution release version (e.g., `"3.20"`, `"24.04"`) |

### Supported Distributions

Any combination that lxc-create supports.

### Preventing environment variables from leaking into LXC

If `process.env` has a value, `lxc-attach` is run with `--clear-env` so host
environment variables do not leak into the container.

### Default environment (schema 0.9+)

By default, the backend supplies `PATH`
(`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`), `TERM`
(`xterm-256color`), and — only when `process.cwd` resolves one — `HOME` (the
directory the child is started in).

| `process.env` | `inheritDefaultEnv` | Entries MXC supplies |
|---------------|---------------------|----------------------|
| omitted | — | the default block |
| `[]` | — | nothing |
| `["FOO=bar"]` | `false` (default) | `FOO` only |
| `["FOO=bar"]` | `true` | the default block plus `FOO`; a same-named entry wins |

This is what MXC passes to `lxc-attach`, not what the child observes: liblxc
adds a baseline `PATH` whenever MXC supplies none. So `[]` is observed as that
baseline `PATH` alone, and `["FOO=bar"]` as the baseline plus `FOO`. A `PATH`
in `process.env` replaces it.

> ⚠️ **`HOME` is only set when `process.cwd` is supplied.** MXC has no private
> directory it can guarantee otherwise: a policy grant can bind a host path over
> the container's `/tmp`, and a reused container keeps whatever its image left
> there. Pass `"HOME=…"` in `process.env` if your command needs it.

> ⚠️ **`HOME` is the working directory.** Dotfiles inside it — `.gitconfig`,
> `.npmrc`, `.curlrc`, `.config/*` — are therefore read as *user-level* tool
> configuration, not just project input. Pass `"HOME=…"` to point elsewhere
> when the workspace is untrusted.

Below 0.9 only `process.env` is passed through and `inheritDefaultEnv` is
rejected.

Shells like bash also have a fallback `PATH`, so a truly empty environment is
not reachable through `process.env`.

## Network Policy

A legacy deny-default policy that names `allowedHosts` opens port 53
unconditionally, so it cannot block DNS.  The directional `network.egress`
rules carry no such exemption and govern port 53 like any other destination.

`preservePolicy` leaves the inbound and outbound chains in place after the run.
The chains live in the container's network namespace, so they last only as long
as the container keeps running; stopping or destroying it takes them with it.  A
partially installed chain from a failed run is torn down regardless.

If using the legacy network shape, `enforcementMode` cannot be `capabilities`.

### Proxy

**LXC does not support proxied egress (`runtimeConfig.networkProxy`) today.**
A request carrying that field is rejected at validation, before any container is
created, with an error naming the field and the backend. The field exists only
in schema 0.8 and later; on 0.6 and 0.7 it is not part of the contract, so a
request carrying it is rejected earlier as an unknown field.

The field must name a loopback endpoint, and an LXC container has its own
network namespace, so `127.0.0.1` there is the container rather than the host.
MXC ships no component that relays a host loopback proxy into that namespace.

On schemas 0.6 through 0.8, LXC accepts the legacy `network.proxy.url` form
pointed at an address routable from inside the container, such as the bridge
address `http://10.0.3.1:3128`. The loopback spellings of that field are
rejected by the parser for the reason above: `network.proxy.localhost`,
`network.proxy.builtinTestServer`, and a `network.proxy.url` naming
`127.0.0.0/8`, `::1`, or `localhost`. Schema 0.9 removes the legacy
`network.proxy` property entirely, which leaves v0.9 with no proxy path.

The `url` must not carry credentials.

### No network at all

A request that permits nothing and names no proxy keeps its own loopback and reaches nothing else.

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

## Limitations

- **Default-deny is not a containment boundary against the workload.** Both the
  inbound and outbound chains live in the container's own network namespace, and
  container init keeps `CAP_NET_ADMIN` there, so a process running as root inside
  the container can flush or delete them. The command MXC runs is attached with
  `CAP_NET_ADMIN` dropped from its bounding set whenever chains are installed, so
  it cannot. Default-deny closes external reachability for a container that does
  not deliberately tear it down, including services the workload itself starts.
- **Raw sockets bypass egress filtering.** `CAP_NET_RAW` is retained so that an
  explicit `protocol: "icmp"` allow works. It also permits `AF_PACKET` sockets,
  which write link-layer frames straight to the interface without traversing the
  filter chain.
- **Policy is not in force while the container starts.** The chains are installed
  after the container has started and its address has settled, so container init
  and anything it starts run unfiltered in both directions for that interval. The
  requested command is attached afterwards. A connection opened during that window
  keeps working once the rules land, because the chains accept established flows.
- **A filtered container cannot renew a DHCP lease.** The chains permit loopback,
  established flows, and DNS, with no carve-out for DHCP. A container that
  outlives its lease loses its address; one that finishes within the lease period
  is unaffected.
- **A container that needs a network waits for an IPv4 address.** A dual-stack
  `lxcbr0` answers router solicitation seconds before its DHCP lease arrives, and
  the bridge NATs IPv4 only, so an IPv6 address alone does not mean the container
  can reach the destinations its policy names. A bridge that never provides an
  IPv4 address fails the run rather than starting a workload that reaches nothing.
- **IPv6 egress is not supported.** An `egress` rule naming an IPv6 destination
  installs and reports success, but no IPv6 traffic reaches that destination.
  Stock `lxcbr0` gives the container no IPv6 address, so this surfaces only on a
  host that provides one.
- **No proxied egress.** See [Proxy](#proxy).
- **No state-aware lifecycle.** LXC implements `ScriptRunner` only (one-shot),
  not `StatefulSandboxBackend`. A state-aware request is rejected.
