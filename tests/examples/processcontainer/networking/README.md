# ProcessContainer networking examples

> **Versioning:** Schema 0.7.0 and earlier retain their existing JSON shape,
> but proxy bring-up now follows the same packaged or unpackaged proxy-host
> requirements as 0.8. Only 0.8 names the single peer through
> `processContainer.network.allowedPeer`. The examples in this directory
> describe the additive schema 0.8 networking surface and remain exempt from
> schema validation until that surface lands.

## Examples

| File | Demonstrates |
|---|---|
| [`egress-allow-https.json`](egress-allow-https.json) | Deny-by-default egress with one IPv4 TCP/443 allow |
| [`egress-allow-with-exceptions.json`](egress-allow-with-exceptions.json) | CIDR exceptions, multiple protocols, and a narrower explicit deny |
| [`proxy.json`](proxy.json) | Deny direct egress and use one loopback proxy peer |

After schema 0.8 support lands:

```powershell
src\target\x86_64-pc-windows-msvc\debug\wxc-exec.exe `
  --experimental `
  --config tests\examples\processcontainer\networking\egress-allow-https.json
```

## Proxy contract

MXC configures the BaseContainer client. It does **not** create, authorize, or
start the proxy.

| Requirement | Value |
|---|---|
| Client capability | `privateNetworkClientServer` (added by MXC) |
| Proxy capabilities | `privateNetworkClientServer`; also `internetClient` for external destinations |
| Proxy endpoint | Loopback URL matching `runtimeConfig.networkProxy` |
| Peer identity | Schema 0.8 names exactly one `processContainer.network.allowedPeer`; 0.7 keeps its legacy config shape |
| Firewall | Inbound authorization for the proxy executable |
| Lifetime | Start proxy first; keep it alive until the BaseContainer exits |
| Policy | Proxy mode cannot include direct egress allow/deny rules |

The peer rule and `privateNetworkClientServer` capability are not sufficient by
themselves. Without inbound firewall authorization, Windows Firewall blocks the
BaseContainer-to-proxy loopback connection.

## Supported proxy setups

| Setup | Schema 0.8 `allowedPeer` | Firewall authorization | Setup authority |
|---|---|---|---|
| Unpackaged AppContainer proxy | AppContainer profile name | Administrator-installed inbound application rule for the proxy executable | App owner / installer |
| Packaged proxy | Package family name | Package manifest `windows.firewallRules` declaration | Package |

### Unpackaged AppContainer

1. Create the proxy with `CreateAppContainerProfile`.
2. Give the proxy `privateNetworkClientServer`.
3. Add `internetClient` if the proxy connects externally.
4. Install an inbound firewall rule for the proxy executable.
5. For schema 0.8, set `allowedPeer` to the AppContainer profile name.

Example firewall rule:

```powershell
New-NetFirewallRule `
  -DisplayName "MXC AppContainer proxy" `
  -Direction Inbound `
  -Action Allow `
  -Program "C:\path\to\proxy.exe" `
  -Protocol TCP
```

Remove the rule when the proxy is uninstalled.

### Packaged proxy

1. Package or loosely register the proxy.
2. Declare `privateNetworkClientServer` and, when needed, `internetClient`.
3. Declare an inbound TCP `windows.firewallRules` rule for the executable.
4. Start the packaged proxy and obtain its loopback port.
5. For schema 0.8, set `allowedPeer` to the package family name.
6. Set `runtimeConfig.networkProxy` to the proxy loopback URL.

Get the package family name with:

```powershell
(Get-AppxPackage -Name <IdentityName>).PackageFamilyName
```

## Test package manifest

The complete runnable manifest is
[`AppContainerProxyPackage/AppxManifest.xml`](../../../scripts/AppContainerProxyPackage/AppxManifest.xml).
It uses one shared PNG for all required logo fields.

| Manifest declaration | Why it is present |
|---|---|
| `Identity`, `Properties`, `Resources`, `Dependencies` | Required package metadata |
| `uap:VisualElements` | Required application registration metadata; `AppListEntry="none"` hides the test app |
| `privateNetworkClientServer` | Allows the proxy side of the scoped loopback connection |
| `internetClient` | Allows the proxy to reach permitted external destinations |
| `runFullTrust` | Required by manifest validation when declaring the desktop firewall extension; the app still uses AppContainer trust |
| `uap10:RuntimeBehavior="packagedClassicApp"` + `uap10:TrustLevel="appContainer"` | Runs the executable as a packaged AppContainer process |
| `desktop2:windows.firewallRules` | Authorizes inbound TCP to the proxy executable |
| `uap5:windows.appExecutionAlias` | Test-only launch path that passes arguments without a C# or COM shim |

The firewall portion is:

```xml
<desktop2:Extension Category="windows.firewallRules">
  <desktop2:FirewallRules Executable="proxy.exe">
    <desktop2:Rule Direction="in" IPProtocol="TCP" Profile="all" />
  </desktop2:FirewallRules>
</desktop2:Extension>
```

A loose package requires Developer Mode or trusted developer-package policy.
A normally deployed MSIX must satisfy the usual signing and trust requirements.

## Run the repository test

```powershell
tests\scripts\run_base_container_network_tests.ps1
```

The script is a thin launcher for the Rust E2E test. The Rust test:

- runs the legacy schema 0.7 cases;
- registers and starts the packaged proxy;
- removes the package during cleanup; and
- runs the schema 0.8 direct and B1-B6 proxy matrix when schema support exists.
