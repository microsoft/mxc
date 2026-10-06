# LXC Container Backend

> **Audience:** MXC consumers and developers

The LXC backend provides Linux container isolation using [LXC (Linux Containers)](https://linuxcontainers.org/lxc/).

For exact `0.9.0-alpha`, networking is directional-only: use `network.egress`
and `network.ingress`. LXC rejects `runtimeConfig.networkProxy`, so a v0.9 LXC
request has no proxy surface at all — see [Proxy](#proxy) below.
Legacy host lists and enforcement-mode fields in older examples are not
accepted. Do not relabel an old request as v0.9 without migrating its policy.
See [the schema migration reference](../../schema.md).

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
sudo dnf install lxc lxc-templates dnsmasq lxc-devel
```
RHEL needs EPEL enabled first, and a few more steps besides — see
[Red Hat Enterprise Linux setup](#red-hat-enterprise-linux-setup) for the whole
process.

**Arch Linux:**
```bash
sudo pacman -S lxc
```

### Container networking

A policy that permits any network needs `lxcbr0` to hand the container an IPv4
lease, so the bridge has to be up before a run: `sudo systemctl start lxc-net`.

On a host running firewalld, which is the default on Fedora and RHEL, the bridge
also has to sit in a zone that permits the traffic. The default zone rejects
IPv4 DHCP while permitting router advertisement, so the container configures
itself an IPv6 address, never receives a lease, and the run fails:

```bash
sudo firewall-cmd --zone=<ZONE> --change-interface=lxcbr0
```

## Configuration

Note the required field lxc.

```json
{
    "version": "0.9.0-alpha",
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
        "egress": {
            "default": "deny",
            "allow": [{
                "to": [{ "cidr": "140.82.112.0/20" }],
                "ports": [{ "protocol": "tcp", "port": 443 }]
            }]
        },
        "ingress": { "default": "deny", "hostLoopback": "deny" }
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

Directional `network.egress` rules govern port 53 like any other destination;
there is no implicit DNS exemption.

`preservePolicy` leaves the inbound and outbound chains in place after the run.
The chains live in the container's network namespace, so they last only as long
as the container keeps running; stopping or destroying it takes them with it.  A
partially installed chain from a failed run is torn down regardless.

### Proxy

**LXC does not support proxied egress (`runtimeConfig.networkProxy`) today.**
A request carrying that field is rejected at validation, before any container is
created, with an error naming the field and the backend.

The field must name a loopback endpoint, and an LXC container has its own
network namespace, so `127.0.0.1` there is the container rather than the host.
MXC ships no component that relays a host loopback proxy into that namespace.

The legacy `network.proxy` fields also have no supported exact contract.
Choose a backend that supports a loopback proxy if the workload needs one;
relabeling a retired LXC proxy request as v0.9 cannot make its policy enforceable.

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
import { spawn } from '@microsoft/mxc-sdk/v1';
import type { ContainerRequest } from '@microsoft/mxc-sdk/v1';

const request: ContainerRequest = {
    command: 'echo hello',
    containment: { type: 'lxc' },
    filesystem: {
        readwritePaths: ['/tmp/output'],
        readonlyPaths: ['/opt/tools'],
    },
    network: {
        egress:  { default: 'deny' },
        ingress: { default: 'deny', hostLoopback: 'deny' },
    },
};

const child = spawn(request);
child.standardOutput?.on('data', (data) => process.stdout.write(data));
try {
    const outcome = await child.wait();
    console.log('Exit:', outcome.exitCode);
} finally {
    child.dispose();
}
```

Select LXC explicitly: the default `process` intent resolves to Bubblewrap on
Linux. SDK execution uses the in-process native library, not `lxc-exec`.

## Streaming

LXC implements `SandboxBackend`, so `mxc_sdk::v1::spawn`, `mxc_sdk::v1::run`,
and every SDK built on `mxc_spawn_json` / `mxc_run_json` reach it
in-process. The handle serves live stdin, stdout, and stderr, plus `wait` and
`kill`.

Ordinary streaming uses pipes, so `isatty()` is false. `spawn_with_pty` returns
a caller-controlled terminal with merged output, writable input, resize, wait, and
kill. `StdioMode::Inherit` remains unsupported.

**`kill()` stops the container,** not just the workload: the workload runs under
container init, where nothing aimed at the host `lxc-attach` process reaches it.

**One live sandbox per container name, per process.** A second sandbox naming a
`containerId` this process already holds is refused rather than queued, because
LXC reads a run's network section only when the container starts. Omit
`containerId` for a generated name. The claim is released when the handle drops.

**Teardown is owed on every terminal path,** including a drop without `wait`:
the proxy pin and the network chains come down, and the container is released.
A teardown failure is reported through `Sandbox::warnings`, which a bare drop
leaves no handle to read.

**The container stays up for as long as the handle lives.** `lxc-exec` is
short-lived by comparison. Weigh that against the threat model before embedding
streaming in a long-lived service.

## Building

```bash
# Full build (Rust + SDK)
./build.sh

# Debug build
./build.sh --debug

# Rust only
./build.sh --rust-only
```

## Red Hat Enterprise Linux setup

1. **Enable EPEL.** LXC ships in EPEL.

   ```bash
   sudo subscription-manager repos --enable "codeready-builder-for-rhel-10-$(arch)-rpms"
   sudo dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm
   ```
   Substitute `9` for `10` on RHEL 9.

2. **Install LXC and the pieces it needs at runtime.**
   ```bash
   sudo dnf install -y lxc lxc-templates dnsmasq iptables
   ```

   Add `lxc-devel` as well if you are building MXC against liblxc rather than
   running a released binary.

3. **Start the bridge.**

   ```bash
   sudo systemctl enable --now lxc-net
   ip -4 addr show lxcbr0
   ```

4. **Move the bridge into a firewalld zone that permits its traffic.**
   firewalld is running by default on RHEL, and its default `public` zone
   admits `ssh`, `cockpit` and `dhcpv6-client` but not IPv4 DHCP. Containers
   therefore configure an IPv6 address from the router advertisement, never
   receive a lease, and every run that asks for network fails:

   ```bash
   sudo firewall-cmd --zone=<ZONE> --change-interface=lxcbr0
   ```

   `<ZONE>` has to admit DHCP and DNS from the bridge, since dnsmasq answers
   both on the bridge address.

   Add `--permanent` and reload to keep the assignment across reboots. 

### Verifying the host

```bash
sudo lxc-checkconfig
ip -4 addr show lxcbr0
sudo firewall-cmd --get-zone-of-interface=lxcbr0
```

The zone query should answer the zone you assigned.

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
- **No state-aware lifecycle.** LXC implements `ScriptRunner` (one-shot) and
  `SandboxBackend` (streaming over pipes or a caller-controlled PTY), not
  `StatefulSandboxBackend`. A
  state-aware request is rejected.
- **Inherited stdio is unavailable.** Use ordinary pipe streaming or
  `spawn_with_pty`; the in-process API never takes over the host application's
  own terminal. See [Streaming](#streaming).
