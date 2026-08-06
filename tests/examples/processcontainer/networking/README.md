# ProcessContainer networking examples

These examples use the schema 0.8 ProcessContainer networking model:

- [`egress-allow-https.json`](egress-allow-https.json) allows one IPv4
  destination on TCP/443 and denies all other egress.
- [`egress-allow-with-exceptions.json`](egress-allow-with-exceptions.json)
  demonstrates multiple protocols, CIDR exceptions, and an explicit deny that
  narrows a broader allow.
- [`proxy.json`](proxy.json) denies direct egress and permits HTTP/S traffic
  only through one loopback AppContainer proxy.

Run an egress example after building `wxc-exec.exe`:

```powershell
src\target\x86_64-pc-windows-msvc\debug\wxc-exec.exe `
  --experimental `
  --config tests\examples\processcontainer\networking\egress-allow-https.json
```

## Proxy prerequisites

MXC configures the BaseContainer client, but it does not create or start the
proxy. Start the proxy before `wxc-exec.exe` and keep it alive for the complete
client lifetime.

The client and proxy must satisfy all of these requirements:

1. Both AppContainers have the `privateNetworkClientServer` capability. MXC
   adds it to the BaseContainer client. The proxy package or profile must
   declare it explicitly.
2. The proxy has `internetClient` if it connects to external destinations.
3. The proxy listens on the loopback address and port used by
   `runtimeConfig.networkProxy`.
4. `processContainer.network.allowedPeer` is the proxy's single AppContainer
   identity. For a packaged proxy, use its package family name.
5. Windows Firewall authorizes inbound TCP traffic to the proxy executable.
   Scoped AppContainer loopback rules do not bypass the firewall's
   block-inbound-to-non-allowed-apps policy.

Proxy mode and direct `network.egress.allow` or `network.egress.deny` rules are
mutually exclusive.

## Minimal packaged proxy

An MSIX or loosely registered AppX package can own the proxy's inbound firewall
authorization. The important manifest declarations are:

```xml
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap10="http://schemas.microsoft.com/appx/manifest/uap/windows10/10"
  xmlns:desktop2="http://schemas.microsoft.com/appx/manifest/desktop/windows10/2"
  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
  IgnorableNamespaces="uap10 desktop2 rescap">
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
    <Capability Name="internetClient" />
    <Capability Name="privateNetworkClientServer" />
  </Capabilities>
  <Applications>
    <Application
      Id="Proxy"
      Executable="proxy.exe"
      EntryPoint="Windows.PartialTrustApplication"
      uap10:RuntimeBehavior="packagedClassicApp"
      uap10:TrustLevel="appContainer" />
  </Applications>
  <Extensions>
    <desktop2:Extension Category="windows.firewallRules">
      <desktop2:FirewallRules Executable="proxy.exe">
        <desktop2:Rule Direction="in" IPProtocol="TCP" Profile="all" />
      </desktop2:FirewallRules>
    </desktop2:Extension>
  </Extensions>
</Package>
```

The `runFullTrust` restricted capability is required by manifest validation for
the firewall extension; the application still runs with
`TrustLevel="appContainer"`. A loose package requires Developer Mode or trusted
developer-package policy. A normally deployed MSIX must satisfy the usual
signing and trust requirements.

After installing or registering the package:

1. Activate `<PackageFamilyName>!Proxy` and pass the proxy's listen/allowlist
   arguments.
2. Read the selected loopback port from the proxy or assign a fixed port.
3. Get the identity with
   `(Get-AppxPackage -Name <IdentityName>).PackageFamilyName`.
4. Replace the port and placeholder `allowedPeer` in [`proxy.json`](proxy.json).
5. Run the config with `wxc-exec.exe --experimental --config ...`.

The repository's runnable test implementation is
[`run_base_container_network_tests.ps1`](../../../scripts/run_base_container_network_tests.ps1).
Its minimal package manifest is under
[`AppContainerProxyPackage`](../../../scripts/AppContainerProxyPackage/).

## Unpackaged AppContainer proxy

An unpackaged proxy created with `CreateAppContainerProfile` can also work.
Give its profile and token `privateNetworkClientServer`, give it
`internetClient` when external egress is needed, and set `allowedPeer` to the
profile name. Because it has no package-owned firewall declaration, an
administrator must install an inbound application rule for the proxy
executable, for example:

```powershell
New-NetFirewallRule `
  -DisplayName "MXC AppContainer proxy" `
  -Direction Inbound `
  -Action Allow `
  -Program "C:\path\to\proxy.exe" `
  -Protocol TCP
```

Remove that rule when the proxy is uninstalled.
