# LXC Container Backend

> **Audience:** MXC consumers and developers

The LXC backend provides Linux container isolation using [LXC (Linux Containers)](https://linuxcontainers.org/lxc/).

For every supported contract from `0.9.0-alpha` onward, networking is
directional-only: use `network.egress` and `network.ingress`, or route egress
through a host loopback proxy with `runtimeConfig.networkProxy` — see
[Proxy](#proxy) below.
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
- Root privileges, or [unprivileged LXC](#running-without-root) for a policy
  that asks for no network.
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
RHEL needs EPEL enabled first — see
[Red Hat Enterprise Linux setup](#red-hat-enterprise-linux-setup).

**Arch Linux:**
```bash
sudo pacman -S lxc
```

### Running without root

A config with no `network` section can run without sudo once the host is set up
for unprivileged LXC.  Everything else needs root.

1. Follow LXC's
   [Create Unprivileged Containers as a User](https://linuxcontainers.org/lxc/getting-started/#create-unprivileged-containers-as-a-user).
2. Let the container's root user reach its files under your home directory:
   `chmod o+x ~`.


### Container networking

Refer to your distribution's manual to configure networking for LXC
containers.  A config with a `network` section fails without it.

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

`runtimeConfig.networkProxy` names a proxy listening on the host's loopback.
The workload reaches it at the same address and port from inside the container.
`127.0.0.1` in the container is the container's own loopback, so MXC listens
there for the length of the run and carries each connection to the proxy on
the host.  Nothing else on the host becomes reachable through it.

MXC carries at most `MAX_RELAYED_CONNECTIONS` connections to the proxy at
once.  Connections over that limit are closed as soon as they open.  Check the
connection before using it.

The workload is handed `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and
`FTP_PROXY` (and their lower-case forms) set to the proxy URL, with `NO_PROXY`
empty.  Any proxy variables the caller put in `process.env` are replaced.

The proxy is the container's only way out:

- The host must be `localhost`, `127.0.0.1`, or `::1`.  A wildcard such as
  `0.0.0.0` or `::` is rejected.
- The URL must not carry credentials.  MXC hands the environment to
  `lxc-attach` on its command line, which other users of the host can read.
- `network.egress` must be omitted or `default: deny` with no rules.  The
  container gets no network interface unless `network.ingress` permits
  something, and then only the filtered interface ingress needs.

MXC carries proxy connections only while the run lasts, and says so in the log
when it starts.  With `destroyOnExit: false` the container outlives the run but
has no path to the proxy until a later run with `runtimeConfig.networkProxy`
reuses it.

`HTTP_PROXY` reaches only clients that honor it.  A client that ignores it gets
no network rather than a direct one.

The retired host-list, enforcement-mode, local-network, and `network.proxy`
fields are no longer representable in typed Rust requests.  Omitting
`network.egress` or `network.ingress` means default deny for that direction;
retired fields never supply a fallback.

### No network at all

A request that permits nothing keeps its own loopback and reaches nothing else.

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
the network chains come down, and the container is released. A reused container
also has any stale proxy address mapping in its hosts file cleared before its
new workload launches. MXC checks for marked lines inside the running
container using `lxc-attach` and removes them if present. A failed check
refuses to run the workload.
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

3. **Configure container networking.**  See
   [Container networking](#container-networking).

### Verifying the host

```bash
sudo lxc-checkconfig
```

## Limitations

- **The workload can send only ICMP Echo.** A `protocol: "icmp"` rule lets every
  ICMP type through the firewall, but the command MXC runs can originate only Echo
  requests, the ones `ping` sends.
- **The network restrictions bind only the command MXC runs and its children.**
  MXC takes away that command's ability to change the firewall or send raw
  packets, but the container's init process (PID 1) keeps both.  The command
  runs as root inside the container, so it can ask init to start a new process,
  for example with `systemd-run` on Ubuntu.  That process is not a child of the
  command, and it can change the firewall and send raw packets.
- **Network access stops after about an hour.** The stock `lxcbr0` hands out
  DHCP leases that last one hour, and MXC's firewall blocks the DHCP request the
  container sends to renew one.  When the lease expires the container loses its
  address and the workload can no longer reach the network.  A run that finishes
  within the hour is unaffected.
- **IPv6 egress is not supported.** An `egress` rule naming an IPv6 destination
  installs and reports success, but no IPv6 traffic reaches that destination.
  Stock `lxcbr0` gives the container no IPv6 address, so this surfaces only on a
  host that provides one.
- **A container reaches the proxy only while a run lasts.** See [Proxy](#proxy).
- **No container lifecycle operations.** LXC implements `ScriptRunner` (create-and-run execution) and
  `SandboxBackend` (streaming over pipes or a caller-controlled PTY), not
  `StatefulSandboxBackend`. A
  request for a container lifecycle operation is rejected.
- **Inherited stdio is unavailable.** Use ordinary pipe streaming or
  `spawn_with_pty`; the in-process API never takes over the host application's
  own terminal. See [Streaming](#streaming).
