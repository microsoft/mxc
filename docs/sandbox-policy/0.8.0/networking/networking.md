# MXC Network Configuration, GA

The `network.egress` and `network.ingress` sections described in this document
are planned for schema 0.8.0 but are not yet accepted by the current parser.
Schema 0.7 and earlier retain their legacy network configuration shape.

## Overview

The MXC network configuration describes what network access a sandboxed workload has. The schema is shared across all container types (process containers, WSLc, LXC, Bubblewrap, Seatbelt). Enforcement varies by backend and platform.

This document covers the GA scope for the General Availability release.

**GA Goal:** Reduce the network surface an AI agent can use to escape its sandbox or exfiltrate data. By default, all outbound traffic is dropped. The recommended path for GA is: localhost HTTP/S proxy for application traffic (API calls, package downloads). Direct outbound connections (raw sockets, SSH, custom TCP/UDP) are blocked by default and only allowed when explicitly permitted by IP/CIDR rules. This is a hard problem to solve across multiple platforms. GitHub Copilot expects sandboxes to behave consistently cross-platform, but each platform has different enforcement primitives. This document describes what MXC can enforce on each backend, where platform limitations exist.

### GA Commitments: What Traffic Goes Where

This document specifies the shared MXC networking schema and GA behavior for backends that support network configuration. Backend-specific support, enforcement differences, and unsupported modes are described in the GA Scope by Backend section.

#### Connectivity models

MXC defines three outbound connectivity models, listed in increasing order of
network restriction. Model 1 applies the configured L3/L4 filtering
(IP/CIDR/port/protocol allow/block rules). Direct egress allow and deny rules
do not apply when runtime proxy configuration selects model 2.

- **Direct internet + L3/L4 filtering, no proxy (least restrictive).** The sandbox reaches the internet directly over HTTP(S) (and other protocols), subject only to IP/CIDR/port/protocol allow/block rules. No proxy is configured, so there is no application-layer (domain/URL/content) inspection.
- **No direct internet + loopback HTTP(S) proxy (more restrictive).** The container has no direct internet path; the
  proxy is its only internet egress. Cooperating clients route HTTP(S) to the proxy, where the consumer can inspect
  and filter it. A client that ignores the proxy and tries to reach the internet directly is dropped. Backend-specific
  private-network behavior is described below.
- **No direct internet + no inbound (most restrictive):** This is the most
  restrictive model. External network traffic is dropped; backend-local
  intra-sandbox IPC is described separately below.

There was a fourth model that was looked at Direct internet + L3/L4 filtering + loopback HTTP(S) proxy. However, unlike model 2 which only allows traffic through a specific loopback port, direct internet access greatly decreases the ways to control egress and increases the opportunities for agent bypass. It is not a model we will have for GA.

**GA goal:** model 2 (recommended to MXC consumers) on every backend. Every backend blocks direct internet access and
configures cooperating HTTP(S) clients to use the proxy. Backend-specific private-network behavior is described below.

This loopback-only-plus-proxy-routing pattern is a well-established way to
confine sandboxed agent egress on macOS and Linux. The GA target enforces a
strict localhost-only egress restriction. See GA Scope by Backend for
per-backend details and compatibility limitations.

Throughout this document, the deny-all-except-proxy posture (the GA goal) refers to model 2.

#### Outbound Traffic Routing

**Default stance:** outbound is blocked by default. The paths below describe how allowed traffic flows.

**Proxy path (recommended for application traffic):**

- **Protocol:** HTTP and HTTPS only
- **Destination:** Localhost proxy only (e.g., 127.0.0.1, ::1)
- **Ports:** Any port within the 1 – 65535 range.
- **Routing mechanism:** This applies to HTTP(S) only, never to other protocols. The sandbox's outbound is restricted so
  the only reachable destination is the loopback proxy port. Cooperating clients are pointed at the proxy through
  `HTTP_PROXY`/`HTTPS_PROXY` on Linux and macOS. Windows uses both per-AppContainer WinHTTP configuration and proxy
  environment variables for non-WinHTTP clients. A client that ignores the proxy cannot reach the internet directly
  on an enforcing model-2 path because the egress restriction drops everything except the localhost proxy port. In
  model 1, such a client may instead egress directly, subject to the IP/CIDR/port/protocol rules.
- **What is NOT routed:** Non-HTTP traffic (raw TCP/UDP sockets, SSH, custom protocols, QUIC, WebRTC, etc.) is never
  redirected to the proxy. In model 2, direct internet traffic is blocked. On ProcessContainer, private-network
  traffic follows `ingress.default` because AppContainer exposes one bidirectional private-network capability. In
  model 1, non-HTTP traffic is subject to the IP/CIDR/port/protocol rules. Transparently routing this traffic through
  the proxy is a gap that requires further design and is out of scope for GA.

**Direct outbound path (model 1 only):**

- **When allowed:** Only when explicitly allowed by IP/CIDR + port + protocol rules in `egress.allow`. In model 2 there is no direct egress path, so these connections are not possible regardless of any allow rules.
- **Use case:** e.g. SSH to a specific dev server, a direct TCP connection to a database, UDP to a specific endpoint, ICMP for diagnostics.
- **Caveat (coarse filtering):** Rules match IP/CIDR + port + protocol, not the application protocol. A port number does not identify a service (DNS need not use 53; a database may listen on any port), so allowing or denying a port is a blunt control rather than service-level filtering.
- **Enforcement:** WFP filters (Windows process containers), network namespace + iptables (WSLc/LXC/Bubblewrap). Model 1 for macOS is not supported for GA. Seatbelt cannot filter arbitrary destinations and macOS packet filtering is not fine-grained enough for per-sandbox scenarios out of the box. Model 1 is **not yet enforced on Bubblewrap** — see "LXC and Bubblewrap: GA enforcement" below; a config requesting it on schema 0.8+ is rejected rather than silently unenforced.

**Example:**

| Consumer scenario | Which model they should use |
|---|---|
| HTTP/HTTPS API calls → localhost proxy (e.g., port 8080) | model 2 |
| SSH to 192.0.2.10:22 → explicit allow rule required | model 1 |
| DNS to 8.8.8.8:53 → explicit allow rule required (or blocked if resolver IP not allowed) | model 1 |
| Raw TCP to 140.82.112.0/20:443 → explicit allow rule required | model 1 |

#### Host Loopback and Inbound Policy

**Default stance:** Host-loopback and LAN/private-network inbound traffic are
blocked by default on backends that enforce the GA network policy.

On backends with private loopback, this does not affect intra-container
loopback. Processes inside the same sandbox may communicate over localhost /
127.0.0.1 / ::1. Seatbelt has the exception described below.

Ingress has two allow/deny controls and no rule arrays:

- `ingress.default` controls LAN/private-network inbound traffic where the
  backend supports it.
- `ingress.hostLoopback` controls host-loopback connectivity in both directions: container-to-host and
  host-to-container.

The specific `hostLoopback` value overrides `default` for the host-loopback
path. For example, `default: deny` with `hostLoopback: allow` permits
bidirectional host-loopback connectivity while denying other inbound traffic.
A backend that cannot enforce both directions must reject `hostLoopback: allow`
rather than accept it with partial enforcement.

**Scope:**

- Intra-container loopback: allowed on backends with private loopback;
  Seatbelt cannot separate it from host loopback
- Container-originated private-network traffic: controlled by `egress` on backends that cleanly separate
  private-network ingress from egress; backend-specific limitations are documented below
- Container-to-host-loopback and host-loopback-to-container traffic: controlled by `ingress.hostLoopback`
- LAN/private-network inbound: controlled by `ingress.default`, where supported
- WAN inbound: not enabled by the GA policy

**Use cases for `ingress.hostLoopback: allow`:**

- Caller-provided services or proxies listening on host loopback and accessed from the container
- MCP servers in SSE/WebSocket mode (server listens on a port for client connections from host)
- Language server daemons (e.g., TypeScript language server) accessed from host IDE
- Local dev servers (e.g., npm run dev on port 3000) accessed from host browser

#### Inter-Container Networking Policy

**GA stance:** Only Windows process containers support this today.

- **Windows process containers:** Two AppContainers can communicate over host loopback only if AppContainer loopback-exemption rules are installed for the pair. These rules are directional, so both directions must be granted. This allows pointed container to container communication over the loopback. MXC will allow this for GA.
- **WSLc / LXC / Bubblewrap:** Each sandbox has its own network namespace, so 127.0.0.1 is private to the sandbox and separate sandboxes cannot reach each other over loopback. Inter-container communication requires explicit virtual networking (veth/bridge/routing, a shared namespace, or a brokered host proxy/IPC path). LXC has mature primitives for this; Bubblewrap would require MXC to build the networking around it. This is out of scope for GA for all 3.
- **macOS (Seatbelt):** Seatbelt does not create a network namespace, so two Seatbelt-sandboxed processes share the host loopback and can communicate over 127.0.0.1 (or Unix sockets/XPC) if both profiles allow it. This is host-level IPC, not isolated container-to-container networking, and is not a GA commitment.

#### Intra-Container Networking Policy

Backends with private loopback allow loopback traffic within the same sandbox.
This enables multi-process applications, local IPC over localhost sockets, and
sandbox-local helper processes. Seatbelt shares the host network stack, so
`ingress.hostLoopback: deny` also prevents intra-sandbox TCP loopback; use
another permitted IPC mechanism when that posture is required.

On backends with private loopback, traffic between processes in the same
sandbox is not governed by outbound IP/CIDR rules or host-to-container inbound
policy.

## Proposed Schema

### Connectivity model 1 and 3

Direct internet, no proxy (least restrictive). OR no egress at all: default deny with no allow rules (most restrictive)

```json
{
  "network": { // Network policy
    "egress": {
      "default": "deny",
      "allow": [
        {
          "to": [ { "cidr": "140.82.112.0/20" } ],
          "ports": [ { "protocol": "tcp", "port": 443 } ]
        }
      ],
      "deny": []
    },
    "ingress": {
      "default": "deny",
      "hostLoopback": "deny"
    }
  }
}
```

### Connectivity model 2

No direct internet, loopback proxy only (more restrictive). Proxy

```json
{
  "runtimeConfig": { // runtime data passed to MXC (not policy)
    // http(s)://localhost:<port>, http(s)://127.0.0.1:<port>, or http(s)://[::1]:<port>
    "networkProxy": "http://127.0.0.1:8080"
  }
}
```

The omitted `network` block uses deny defaults. When `runtimeConfig.networkProxy` is present, cooperating HTTP(S)
clients are configured to use the proxy; clients that ignore the proxy settings are blocked from direct egress.
Without runtime proxy configuration, the deny defaults form model 3. Backend-specific proxy reachability requirements
are documented below.

This schema follows container-ecosystem conventions (CIDR peers, egress/ingress, to/ports), modeled loosely on
Kubernetes NetworkPolicy (the CNCF standard layered on CNI/OCI) rather than on platform firewall primitives. MXC keeps
an explicit deny list and a per-direction default, which are a deliberate extension over pure Kubernetes NetworkPolicy
(allow-only with `ipBlock.except`) to give an auditable default and block-precedence.

Egress peer and port fields (used in `egress.allow[]` / `egress.deny[]`; not shown in the minimal example above):

| Field | Type | Notes |
|---|---|---|
| `to[].cidr` | IPv4 / IPv6 CIDR, or 0.0.0.0/0 / ::/0 for any | Single CIDR string (CNI/Kubernetes style), replacing separate address + prefix length. |
| `to[].except` | list of CIDRs, optional | Exclusions within the peer's CIDR (Kubernetes `ipBlock.except` style). Expressible on Windows process containers (WFP) and the Linux backends (iptables) as additional deny rules; not supported on Seatbelt (no destination filtering). |
| `ports[].protocol` | tcp / udp / icmp / any | `any` matches all protocols. Enforced on Windows process containers (WFP) and the Linux backends (iptables); not supported on Seatbelt. |
| `ports[].port` | uint16, optional | Destination port. Omit `ports` to match all ports/protocols. |
| `ports[].endPort` | uint16, optional | End of a port range (Kubernetes `endPort` style); requires numeric port. Supported on Windows process containers (WFP) and the Linux backends (iptables); not supported on Seatbelt. |

`icmp` expands by destination address family. A rule containing IPv4 and IPv6 peers produces both ICMPv4 and ICMPv6
filters; a rule without `to` also produces both.

Ingress has no CIDR peers or port rules. `ingress.default` and
`ingress.hostLoopback` are the complete GA ingress surface.

## Design decisions

### D1: Default-deny outbound

**Decision:** Unlisted destinations are unreachable. A configuration that mentions nothing grants nothing.

**Why:** This ensures the configuration explicitly describes the sandbox's network permissions (auditable on enforcing backends). Forgotten rules fail closed (safer). The same configuration means the same thing on different hosts and container types (portable intent, though enforcement fidelity varies by platform).

**Limitation:** Enforcement requires an egress restriction at the OS level:
WFP on Windows process containers, a network namespace plus iptables on the
Linux backends, and a Seatbelt profile confining network-outbound to the
loopback proxy port on macOS. Rich IP/CIDR/port allow-lists are expressible on
Windows and the Linux backends but not on macOS, where Seatbelt restricts
egress to the proxy port rather than filtering arbitrary destinations.
Backend-specific docs identify temporary compatibility behaviors whose
enforcement is intentionally coarser. Outside those documented exceptions, a
backend rejects configurations it cannot enforce.

### D2: Inbound and host-loopback connectivity are blocked by default

**Decision:** GA defines outbound configuration and inbound control.
`ingress.default: deny` blocks LAN/private-network inbound traffic, and
`ingress.hostLoopback: deny` separately blocks host-loopback connectivity in both directions. The host-loopback value
overrides `default` for that path.
Intra-container loopback is allowed on backends with private loopback.
Seatbelt has the caveat described below.

**Why inbound and host-loopback connectivity are blocked by default:**

- **Attack surface:** Host-loopback access can expose host services to contained code and container listeners to the
  host. For agentic workloads, either direction can create command-and-control, exfiltration, or lateral-movement paths.
- **Opt-in model:** Customers must explicitly set `ingress.hostLoopback: allow` when either direction is required.
- **GA enforcement:** Windows process containers use loopback exemption rules
  scoped to the AppContainer SID. WSLc/LXC/Bubblewrap require paired routing
  and filtering for both directions across their private network namespaces.
  Seatbelt maps `ingress.default` to its existing
  `(allow network-inbound (local ip))` behavior but cannot enforce an
  independent `hostLoopback` posture.

**Seatbelt caveat:** On Seatbelt there is no private loopback, so `ingress.hostLoopback: deny` also blocks
intra-sandbox TCP loopback, breaking loopback servers used by processes in the same sandbox. For intra-sandbox IPC on
macOS, Unix-domain sockets in a sandbox-private path rather than TCP loopback could be used. That said, Unix-domain
sockets come with their own security questions and should be outlined in a separate macOS doc if necessary.

**Elevation caveat:** Installing these filters (WFP on Windows, iptables on the Linux backends) generally requires elevation. Elevating on every sandbox launch is out of the question, so MXC applies them through a privileged broker/service rather than from the unelevated launch path. A per-platform, per-technology elevation story must be defined in a separate MXC elevation design doc and is a prerequisite for this enforcement.

### D3: IP literals and CIDRs only (no DNS names)

**Decision:** Rule addresses must be IPv4/IPv6 literals or CIDRs. DNS names are rejected at validation time. The backend does not resolve names on behalf of callers.

**Why:** Names are bypassable and non-deterministic. A container that resolves DNS itself can map a blocked name to an IP and connect directly. These results can change between config-time and runtime (TOCTOU) and vary by resolver/TTL/cache. IP/CIDR literals are deterministic and auditable.

**GA DNS behavior:** GA does not implement domain-based DNS policy. DNS is not a first-class policy surface. If firewall rules block the DNS resolver IP, DNS queries fail. If rules allow the resolver IP, the sandbox can resolve any domain.

**Secure domain allow-listing:** For HTTP(S) routed to the proxy, the proxy can inspect the domain on each CONNECT request in the HTTP header, and then choose to allow or deny by domain. The proxy resolves the hostname on the sandbox's behalf and enforces the domain allow-list before connecting. DNS resolution security at this point is on the proxy and not MXC.

### D4: Explicit deny takes precedence over explicit allow

**Decision:** When a connection matches both an `egress.allow` rule and an `egress.deny` rule, the deny wins. With `egress.default: "deny"`, no matching allow means no outbound access. With `egress.default: "allow"`, no matching deny means unrestricted outbound.

**Why:** Fail-closed security posture. Deny rules act as overrides for broader allow rules (e.g., allow 0.0.0.0/0 but deny specific malicious IPs).

### D5: Proxy is HTTP/S via platform-native APIs; localhost only for GA

**Decision:** For GA, proxy routing covers HTTP and HTTPS traffic routed through the platform's native proxy surface. The proxy must be on localhost (same-machine loopback) for GA. Remote proxies are out of scope for GA.

**Platform-specific enforcement:**

| Platform | Enforcement Mechanism |
|---|---|
| Windows (Process Containers) | Enforcing BaseContainer path: per-AppContainer WinHTTP proxy configuration and scoped proxy-only access. AppContainer fallback: cooperative routing only. |
| WSLc | VM-level network policy permits only the translated proxy endpoint. Proxy variables are routing hints. |
| Linux (LXC, Bubblewrap) | iptables permits only the proxy endpoint; proxy variables are routing hints. |
| macOS (Seatbelt) | Seatbelt profile confines network-outbound to the loopback proxy port. MXC-set `HTTP_PROXY`/`HTTPS_PROXY` env variables are an advisory routing hint; a client that ignores the variables is denied by the profile (only the proxy port is reachable), so it is dropped, not bypassed. |

**Why localhost only:** Remote proxies introduce trust boundary issues (proxy on different machine = different security context). Localhost proxy simplifies GA implementation and ensures proxy is under the same administrative control as the sandbox.

**Proxy environment-variable hygiene (all backends):** The sandbox starts with all HTTP(S)-related proxy environment variables cleared to empty (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `FTP_PROXY`, `NO_PROXY`, and their lowercase variants). The sandbox never inherits host or stale proxy settings. MXC sets these variables explicitly, and only to the configured loopback proxy, when a proxy is in use (model 2); in model 1 they remain empty.

**Consumer-provided proxy (all backends):** MXC does not provide, launch, or manage the proxy, and knows nothing about it beyond the host:port in the configuration. The consumer must start their proxy listening before launching the workload. MXC restricts the sandbox's egress to that endpoint and points the proxy variables at it. Making the proxy reachable from inside the sandbox is MXC's responsibility and is backend-specific.

What is and is not routed through the proxy is described under Outbound Traffic Routing.

### D6: Per-sandbox scoping

**Decision:** Every configuration is scoped to one sandbox instance. Two concurrent sandboxes from different clients (e.g., gh-copilot and vscode) have independent configurations. One sandbox's configuration cannot affect another's network access.

**Why:** Isolation between sandboxes prevents cross-sandbox interference and ensures configuration changes in one sandbox do not weaken another.

**Implementation:** The sandbox identity used for scoping is backend-specific (AppContainer SID on Windows process containers, network namespace on WSLc/LXC, Seatbelt profile).

### D7: Schema is container-type-agnostic; enforcement is backend-specific

**Decision:** The network schema block is shared across all container types. The same JSON configuration means the same thing whether the backend is a Windows process container, a WSLc container, or Seatbelt on macOS.

**Why:** Portable intent across platforms. Customers write one configuration that expresses their security policy; MXC maps it to backend-specific enforcement.

**Reality:** Enforcement fidelity varies. A capability available on one backend (e.g., per-AppContainer WFP filters) may not have an equivalent on another. Cooperation-dependent routing (e.g., honoring proxy env vars) is allowed only as an optimization above an enforcing layer that already blocks non-cooperative traffic; it is never the enforcement mechanism itself.

Backends that cleanly separate private-network ingress from egress apply both directions independently. Windows
AppContainer requires the bidirectional `privateNetworkClientServer` capability before private-network traffic can
flow in either direction. ProcessContainer therefore requires `ingress.default: "allow"` for outbound private-network
access, after which `egress` rules apply to both public and private outbound destinations.

### D8: Delegation from the invoking user

**Decision:** Like the filesystem configuration, the network configuration is a delegation: the contained code receives no more network access than the invoking user could exercise themselves.

**Why:** The sandbox can only be more restricted, never less. A sandboxed process cannot reach a network destination that the invoking user's own process could not reach. Host-level firewalls, VPN configuration, and similar environmental controls still apply on top of this.

## GA Scope by Backend

GA includes all backends for their respective isolation capabilities. Network
configuration enforcement varies by backend. This section describes the GA
target for each backend; it does not claim that unfinished roadmap work is
already implemented.

### Process containers (Windows): GA target and compatibility behavior

The model-2 guarantees below apply to ProcessContainer paths with OS-scoped
proxy enforcement. The AppContainer compatibility fallback is cooperative and
does not satisfy model 2; see the implementation doc for its limitations.

**Connectivity models:**

- **Model 2 (recommended):** Grants no `internetClient`, so direct internet traffic is blocked. Any packaged proxy,
  with or without AppContainer isolation, uses its Package Family Name in `allowedProxyPeer`; an unpackaged
  AppContainer proxy uses its profile name. The MXC client requires `ingress.default: "allow"` to grant
  `privateNetworkClientServer`. That capability permits private-network client and server traffic by Windows design.
- **Model 1:** Grants `internetClient`, allowing direct internet egress under WFP IP/CIDR/port/protocol rules.
  Private-network outbound also requires `ingress.default: "allow"` and remains subject to the same `egress` rules.
- **Model 3:** Grants no `internetClient`, private-network capability, or loopback exemptions.

**Enforcement:**

| Configuration concept | Enforcement mechanism | Notes |
|---|---|---|
| IP/CIDR allow/block | IPv4/IPv6 WFP filters scoped to AppContainer SID | Public and private destinations |
| Port filtering | Port filtering via WFP | Port ranges supported. |
| Protocol filtering | Protocol filtering via WFP | Schema values are `tcp`, `udp`, `icmp`, and `any`; WFP maps ICMP by address family. |
| Default-deny | WFP block-all baseline filter at lower precedence than explicit allows. AppContainer has no internetClient capability. | |
| Proxy (HTTP/S only) | Per-AppContainer WinHTTP configuration | Private network follows `ingress.default` |
| Per-sandbox scoping | AppContainer SID, unique per sandbox instance | |
| Private network | `privateNetworkClientServer` via `ingress.default` | Capability gate; `egress` filters outbound |
| Inbound | Capabilities and loopback rules | Private network uses `ingress.default`; loopback is separate |
| DNS | DNS queries follow same IP/CIDR allow/block rules as other traffic. No domain-based filtering. | If DNS resolver IP is blocked, DNS fails. If allowed, sandbox can resolve any domain. **For HTTP(S) via the proxy, DNS resolution happens in the proxy.** |
| Bypass resistance | High. Kernel-enforced WFP filters. Bypass requires kernel compromise or AppContainer escape (elevation). | |

**Implementation doc:** [Process Container Networking Configuration, GA](../../../process-container/networking.md)

### WSLc: GA enforcement

**Default stance:** Deny all outbound through the VM-level network policy API.

**Connectivity model:** The VM-level network policy API enforces all three models. For model 2, MXC translates the
caller's loopback proxy to a VM-reachable endpoint and permits only that endpoint. The original loopback address is not
reachable directly from the WSL2 VM.

**Recommended path:** Localhost proxy (HTTP/S via env vars) with no direct
egress allow-list.

**Enforcement:**

| Configuration concept | Enforcement mechanism | Notes |
|---|---|---|
| IP/CIDR allow/block | VM-level network policy API | IPv4 + IPv6 at GA |
| Port filtering | VM-level network policy API | Port ranges supported |
| Protocol filtering | VM-level network policy API | tcp, udp, icmp |
| Default-deny | VM-level network policy API | |
| Proxy (HTTP/S only) | Proxy variables plus VM-level allow for the translated endpoint | Direct bypass is blocked |
| Per-container scoping | VM and container identity | |
| Inbound and host loopback | VM-level policy applies `ingress.default` and bidirectional `ingress.hostLoopback` | |
| DNS | DNS queries follow same IP/CIDR allow/block rules as other traffic. No domain-based filtering. | If DNS resolver IP is blocked, DNS fails. If allowed, sandbox can resolve any domain. **For HTTP(S) via the proxy, DNS resolution happens in the proxy.** |
| Bypass resistance | Medium. Depends on VM-level enforcement and correct per-container scoping. | |

### LXC and Bubblewrap: GA enforcement

LXC and Bubblewrap use iptables/nftables on the container network path. Their INPUT policy applies `ingress.default`
and the host-to-container half of `ingress.hostLoopback`; routing and output policy enforce its container-to-host half.
Model 2 permits only the proxy endpoint.

> **Implementation status (Bubblewrap).** The above is the GA target, not
> current behavior. Unprivileged Bubblewrap has no host-side veth, so an
> iptables chain cannot be hooked into `FORWARD`; the chain is built and never
> attached. Rather than report success having enforced nothing, MXC **rejects**
> `network.enforcementMode` of `firewall` or `both` on schema 0.8+ (schema
> 0.6/0.7 keeps the previous warn-and-continue behavior). Model 2 — the proxy
> endpoint — is the enforced path today. Delivering the chain described above
> requires moving filtered mode into the sandbox's own network namespace and
> filtering on `OUTPUT` instead of `FORWARD`; `ingress.hostLoopback` is
> likewise parsed but not yet enforced. LXC is unaffected: it has a veth and
> runs privileged, and enforces as described.

### macOS (Seatbelt): GA enforcement

**Default stance:** Egress is confined to the loopback proxy port by the Seatbelt profile.

**Connectivity model:** Model 2 and 3 only. Model 1 (direct egress under IP/CIDR rules) is not supported because Seatbelt cannot enforce arbitrary destination policy. It can deny network entirely or allow only the localhost proxy path, but not general IP/CIDR, hostname, port, or protocol allow-lists.

**Recommended path:** Loopback proxy with the Seatbelt localhost egress restriction and proxy variables.

**Enforcement:**

| Configuration concept | Enforcement mechanism | Notes |
|---|---|---|
| Egress restriction (model 2) | Seatbelt profile: (deny default) then allow network-outbound only to `localhost:<proxyPort>`. All other outbound (direct internet, raw sockets, direct DNS) is denied by the profile. | Confines egress to the proxy port; does not filter arbitrary destinations. |
| Proxy routing (HTTP/S) | `HTTP_PROXY`/`HTTPS_PROXY` set to the loopback proxy; cooperating clients route there. | A minority of clients ignore the variables; their traffic is dropped by the egress restriction, not bypassed. |
| IP/CIDR / port / protocol allow-lists | Not supported. | |
| Per-sandbox scoping | Seatbelt profile per sandbox-exec invocation | |
| Inbound | Seatbelt `network-inbound (local ip)` rule | Preserves current `allowLocalNetwork` behavior through `ingress.default`; differing `default` and `hostLoopback` values are rejected with `policy_validation`. |
| DNS | Direct outbound DNS to an external resolver is blocked (egress confined to the proxy port); cooperating clients pass hostnames to the proxy, which resolves them. All others would be blocked. | |
| Bypass resistance | Medium. Egress is profile-restricted to the proxy port, so raw-socket and direct-DNS attempts are denied. Weaker than a separate network namespace (Seatbelt shares the host network stack) and depends on a correct profile. | |

### Other backends

- **Windows Sandbox:** Guest-side firewall only, with hardcoded rules. In GA for development/testing scenarios where network isolation is not critical.
- **Isolation Session:** No network filtering or denial is possible — outbound is open and a process inside can listen
  on a localhost-reachable port. Schema 0.7 requires the unrestricted-network acknowledgment
  (`network.defaultPolicy=allow` + `network.allowLocalNetwork=true`). Schema 0.8 has the same behavior and accepts only
  the equivalent unrestricted posture: `egress.default=allow`, `ingress.default=allow`, and
  `ingress.hostLoopback=allow`, with no egress rules or runtime proxy. Every other network/proxy policy is rejected.
  In GA for process isolation only (identity, lifecycle).
- **Hyperlight, Nanvix:** Not in this GA scope doc. Additional follow up is needed to confirm their capabilities and whether they align with this doc.

## Gaps and limitations

**What GA cannot do:**

- **DNS domain filtering:** The IP/CIDR schema cannot distinguish hostnames that resolve to the same IP. Domain allow/deny requires either deeper platform support or the proxy inspecting the CONNECT/request host plus blocking direct DNS egress (see D3).
- **Inter-container networking:** Containers cannot communicate with each other (except Windows process containers).
- **macOS direct-egress models:** Seatbelt cannot filter arbitrary remote destinations, so model 1 (direct egress under IP/CIDR/port/protocol rules) is not available on macOS; macOS supports model 2 (proxy-only).
- **Proxy arbitrary network traffic:** GA MXC configures proxies for HTTP/S traffic only. On Windows, only clients that
  use the WinHTTP stack or correctly query the platform proxy configuration are proxied. Many libraries on all three
  platforms use proxy environment variables as their configuration mechanism. On Linux and macOS these are the
  standard way to apply proxy configurations; however, it is advisory only and not a full RFC standard. Libraries and
  applications that honor them use the proxy; those that ignore them do not have their traffic directed to the proxy
  and instead have their egress blocked.
