# MXC Playground — Known Limitations & Compatibility

> For a per-release policy-support matrix (filesystem, network, and UI
> restrictions across Windows 11 23H2 / 24H2 / 25H2 / 25H2+), see
> [Windows OS-version policy support](./process-container/os-version-support.md).

## Platform Support

| Feature | Windows 24H2 (build 26100) | Windows 25H2+ (build 26600+) | Linux |
|---------|---------------------------|------------------------------|-------|
| AppContainer (v0.4.0) | ✅ Works | ✅ Works | N/A |
| BaseContainer (v0.5.0) | ❌ No processmodel.dll | ✅ Works when the BaseContainer feature is enabled; otherwise falls back to AppContainer+DACL | N/A |
| BFS filesystem brokering | ❌ Broker helper not available | ⚠️ Disabled (`tier2_bfs` off; `bfscfg.exe` risks host hang) | N/A |
| Proxy (AppContainer) | ✅ Works (needs admin for shim) | ✅ Works | N/A |
| Proxy (BaseContainer) | N/A | ⚠️ WinHTTP only, see below | N/A |
| LXC containers | N/A | N/A | ✅ Works |

## Shell Compatibility in Containers

| Shell | AppContainer (v0.4.0) | BaseContainer (v0.5.0) default UI | BaseContainer with relaxed UI |
|-------|----------------------|-----------------------------------|-------------------------------|
| cmd.exe | ✅ Works | ✅ Works (even with Win32k disabled) | ✅ Works |
| powershell.exe (5.1) | ✅ Works | ❌ DLL_INIT_FAILED (ui_restrictions=0x03FF) | ✅ Works (set isolation=desktop) |
| pwsh.exe (7+) | ✅ Works (if installed system-wide) | ❌ Same as PS 5.1 | ✅ Works (set isolation=desktop) |
| python.exe | ⚠️ Needs ALL APPLICATION PACKAGES ACL | ❌ Same as PS 5.1 | Untested |
| curl.exe | ✅ Works | ✅ Works (no Win32k needed) | ✅ Works |

### PowerShell in BaseContainer

PowerShell (both 5.1 and 7+) fails with `STATUS_DLL_INIT_FAILED` (0xC0000142) when
BaseContainer uses default UI restrictions (`ui_restrictions=0x03FF`). This is because the
default-deny policy sets all UILIMIT flags, and PowerShell's DLL initialization requires
access to desktop handles.

**Workaround:** Set `appContainer.ui.isolation` to `"desktop"` in the ContainerConfig to
relax handle/atoms restrictions. This allows PowerShell to initialize while still enforcing
other restrictions (clipboard, injection, etc.).

### Python in AppContainers

Per-user Python installs (`AppData\Local\Python\`) cannot be executed inside AppContainers
because they lack `ALL APPLICATION PACKAGES` ACL. System-wide Python installs (`C:\Python*`)
work if the ACL is set:

```
icacls C:\Python314 /grant "ALL APPLICATION PACKAGES:(OI)(CI)(RX)" /T
```

This is a Windows security model limitation, not an MXC bug.

## Network Limitations

### DNS Resolution

| Method | AppContainer | BaseContainer |
|--------|-------------|---------------|
| PowerShell `Invoke-WebRequest` | ❌ DNS fails (uses .NET, not WinHTTP) | ❌ Same |
| WinHTTP COM (`WinHttp.WinHttpRequest.5.1`) | ⚠️ See below | ⚠️ See below |
| curl.exe | ✅ Works with proxy shim (0.4.0) | ❌ Doesn't use WinHTTP auto-proxy |

### PowerShell `Invoke-WebRequest` DNS Issue

`Invoke-WebRequest` uses .NET's `HttpClient` which performs DNS resolution in-process.
Inside an AppContainer without DNS access, this fails even when `internetClient` capability
is granted. `internetClient` enables TCP connections but does not grant DNS resolution
for .NET's resolver.

**Workaround:** Use WinHTTP-based tools (curl.exe with proxy shim, or WinHTTP COM object)
instead of `Invoke-WebRequest` for network tests.

### Proxy Routing

**AppContainer (v0.4.0):** The SDK uses `winhttp-proxy-shim.exe` (requires admin/elevation)
to set per-AppContainer WinHTTP proxy policy via the DNS cache service. Tools that use
WinHTTP with `WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY` (like curl.exe) respect this policy.
Tools that use their own DNS resolution (.NET HttpClient, PowerShell) do not.

**BaseContainer (v0.5.0):** The proxy URL is passed in the FlatBuffer spec to
`CreateProcessInSandbox`. The OS-level `appinfosvc` configures WinHTTP proxy for the
container. System-level WinHTTP sessions (Windows telemetry) use the proxy. App-created
WinHTTP sessions may or may not pick it up depending on how they're initialized.

### Admin Requirements

| Feature | Needs Admin? |
|---------|-------------|
| Basic AppContainer execution | No |
| BFS filesystem brokering | No |
| Network (capabilities only) | No |
| Network (firewall rules) | Yes — `netsh advfirewall` |
| Proxy shim (v0.4.0) | Yes — elevated winhttp-proxy-shim |
| Proxy (v0.5.0 BaseContainer) | No — handled by OS |

## UI Restrictions (BaseContainer)

### Default UI Restrictions Bitmask

When `ui.disable=false` (UI enabled) with default settings, all sub-restrictions are applied:

| Flag | Value | Default | Effect |
|------|-------|---------|--------|
| HANDLES | 0x0001 | ON | Blocks access to window handles |
| READCLIPBOARD | 0x0002 | ON | Blocks clipboard read |
| WRITECLIPBOARD | 0x0004 | ON | Blocks clipboard write |
| SYSTEMPARAMETERS | 0x0008 | ON | Blocks system parameter changes |
| DISPLAYSETTINGS | 0x0010 | ON | Blocks display setting changes |
| GLOBALATOMS | 0x0020 | ON | Blocks global atom access |
| DESKTOP | 0x0040 | ON | Blocks desktop switching |
| EXITWINDOWS | 0x0080 | ON | Blocks shutdown/logoff |
| IME | 0x0100 | ON | Blocks IME |
| INJECTION | 0x0200 | ON | Blocks input injection |

**Total default: 0x03FF** (all flags on)

This is by design (least-privilege). Applications that need desktop access must explicitly
configure relaxed UI settings via the advanced API (`createConfigFromPolicy` +
`spawnSandboxFromConfig`) with appropriate `appContainer.ui` settings.

### Win32k Disabled (`ui.disable=true`)

When `disallowWin32kSystemCalls=true`:
- Only `GLOBALATOMS` (0x0020) is set as a UI restriction
- The Win32k filter driver blocks all Win32k system calls
- `cmd.exe` may still work (doesn't use Win32k)
- PowerShell, GUI apps, and most Windows executables will fail

## Filesystem (BFS)

### Trailing Backslash

Paths ending in `\` (e.g., `C:\`) are handled correctly. The SDK's filesystem-broker argument
builder only quotes paths containing spaces, avoiding the `"C:\"` escaping issue.

### Short Paths (8.3)

BFS brokers paths using long path names. If `os.tmpdir()` returns a short path like
`C:\Users\ADMINU~1\...`, use `fs.realpathSync.native()` to resolve it before passing
to the SDK.

## Version Compatibility

| Policy Version | Schema | Backend | Status |
|---------------|--------|---------|--------|
| 0.6.0-alpha | Stable (minimum supported) | ProcessContainer (BaseContainer when the host supports it, else AppContainer) | Production |
| 0.7.0-alpha | Stable (current) | ProcessContainer (capability-resolved) | Production |
| 0.8.0-alpha | Dev | ProcessContainer (capability-resolved) | Experimental |

The SDK and Rust parser accept `>=0.6, <=0.8`. As of Phase 3a the schema version no longer selects the Windows backend — BaseContainer vs AppContainer is resolved at runtime by host capability.
