# MXC Containment Policy Spec v0.9.0-alpha

> **Audience:** MXC consumers

`0.9.0-alpha` is the oldest **supported** configuration contract. Its
published [schema](../../../schemas/stable/mxc-config.schema.0.9.0-alpha.json)
is immutable. High-level [V1 SDK authoring](../README.md#authoring-a-policy)
targets `1.0.0`; use raw configuration to select this exact published
contract.

## Policy behavior

| Section | Policy and configuration |
|---|---|
| `filesystem` | `readwritePaths`, `readonlyPaths`, and `deniedPaths` grant or deny listed paths; each backend also provides its documented baseline access. |
| `network.egress` | Defaults to `deny`. `allow` and `deny` rules match numeric IP/CIDR destinations (`to[].cidr`, optional `except`) and optional protocol/port ranges; explicit deny wins. |
| `network.ingress` | `default` controls private-network inbound traffic; `hostLoopback` controls host-loopback connectivity in both directions. Both independently default to `deny`. |
| `runtimeConfig.networkProxy` | Specifies a runtime HTTP/S proxy endpoint. ProcessContainer, Bubblewrap, and Seatbelt use deny-default egress with empty direct rule lists. WSLC uses all-allow bridged networking and a cooperative proxy. See the [WSLC network guide](../../backends/wslc/wsl-container-getting-started.md#network-proxy-cooperative-unprivileged). |
| `ui` | `disable`, `clipboard` (`none`, `read`, `write`, or `all`), and `injection`. The selected backend's guide describes which UI restrictions it enforces. |
| `fallback.allowDaclMutation` | Allows Windows host-DACL mutation as a filesystem fallback; defaults to `true`. Set to `false` to refuse this fallback. |
| `lifecycle` | `destroyOnExit` and `preservePolicy` control cleanup and retained policy. |
| `process` | `cwd`, `env` (`KEY=VALUE` entries), `inheritDefaultEnv`, and `timeout` (milliseconds). The default environment applies when `env` is absent; supplied `env` (including `[]`) replaces it, and `inheritDefaultEnv: true` layers supplied entries over it. |

Backend-specific settings belong under their matching section, such as
`processContainer`, `wslc`, `lxc`, or `seatbelt`. In particular,
`processContainer.filesystem.enumeratePaths` requires a BaseContainer host
with PSEC enumeration support. Exact-contract acceptance defines the request
shape; a backend may apply, reject, or ignore an accepted field. Check the
[schema guide](../../schema.md#ui-policy) and the selected backend's guide
to confirm which restrictions it enforces before relying on them.

The directional network rule semantics and backend support summary in the
[1.0.0 policy](../1.0.0/policy.md#directional-network-policy) also apply
to this contract.

## State-aware policy

This contract supports IsolationSession and WSLC lifecycle operations.
IsolationSession uses unrestricted networking. One-shot and provision
requests supply `network` with `egress.default`, `ingress.default`, and
`ingress.hostLoopback` explicitly set to `allow`, matching the example below.
For the public API and phase order, see the
[container lifecycle guide](../../container-lifecycle.md); backend guides
describe phase-specific policy support. Raw JSON callers can also consult
the [wire contract](../../development/architecture/container-lifecycle.md#7-wire-contract).

## Moving to 1.0.0

Use [the 1.0.0 contract](../1.0.0/policy.md) for stable raw config and new
high-level SDK authoring. To migrate, use canonical containment and backend
section names, then set `version` to `1.0.0` once the request matches that
contract.

## Raw JSON authoring

Raw one-shot requests require `"version": "0.9.0-alpha"` and a non-empty
`process.commandLine`. The default `containment` selects the abstract `process`
intent: `processcontainer` on Windows, `bubblewrap` on Linux, and `seatbelt`
on macOS. Supported selections are `process`, `processcontainer`, `lxc`,
`bubblewrap`, `seatbelt`, `isolation_session`, and `wslc`. This contract also
accepts the `appcontainer` and `macos_sandbox` containment aliases
and `appContainer` and `macos_sandbox` backend-section spellings; use the
canonical names for new requests. Supply backend settings under the section
for the selected backend.

```json
{
  "version": "0.9.0-alpha",
  "containment": "processcontainer",
  "process": { "commandLine": "cmd.exe /c echo hello" },
  "network": {
    "egress": { "default": "deny" },
    "ingress": { "default": "deny", "hostLoopback": "deny" }
  }
}
```

State-aware requests select a closed `provision`, `start`, `exec`, `stop`, or
`deprovision` root with `phase`. Provision supplies
`containment`; later phases use the returned `sandboxId`. Exec requires a
`process` with a non-empty `commandLine`. An IsolationSession provision
request must describe its unrestricted network posture:

```json
{
  "version": "0.9.0-alpha",
  "phase": "provision",
  "containment": "isolation_session",
  "network": {
    "egress": { "default": "allow" },
    "ingress": { "default": "allow", "hostLoopback": "allow" }
  }
}
```
