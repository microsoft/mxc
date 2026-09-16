# LXC Container Backend

The LXC backend provides Linux container isolation using [LXC (Linux Containers)](https://linuxcontainers.org/lxc/).

For exact `0.9.0-alpha`, networking is directional-only: use `network.egress`
and `network.ingress`, with proxy runtime values under `runtimeConfig`.
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

## Network Policy

A legacy deny-default policy that names `allowedHosts` opens port 53
unconditionally, so it cannot block DNS.  The directional `network.egress`
rules carry no such exemption and govern port 53 like any other destination.

`preservePolicy` leaves the egress chains in place after the run.  The chains
live in the container's network namespace, so they last only as long as the
container keeps running; stopping or destroying it takes them with it.  A
partially installed chain from a failed run is torn down regardless.

If using the legacy network shape, `enforcementMode` cannot be `capabilities`.

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