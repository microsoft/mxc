# MXC Playground — Known Limitations & Compatibility

> For a per-release policy-support matrix (filesystem, network, and UI
> restrictions across Windows 11 23H2 / 24H2 / 25H2 / 25H2+), see
> [Windows OS-version policy support](./process-container/os-version-support.md).

## Platform Support

| Feature | Windows 24H2 (build 26100) | Current prerelease and later Windows | Linux |
|---------|---------------------------|--------------------------------------|-------|
| ProcessContainer | ❌ Native PSEC contract unavailable | ✅ When PSEC runtime probing succeeds | N/A |
| Proxy (ProcessContainer) | N/A | ✅ PSEC | N/A |
| LXC containers | N/A | N/A | ✅ Works |

## Shell Compatibility in Containers

| Shell | BaseContainer default UI | BaseContainer with relaxed UI |
|-------|--------------------------|-------------------------------|
| cmd.exe | ✅ Works | ✅ Works |
| powershell.exe (5.1) | ❌ DLL_INIT_FAILED with full UI lockdown | ✅ Works (set isolation=desktop) |
| pwsh.exe (7+) | ❌ Same as PS 5.1 | ✅ Works (set isolation=desktop) |
| python.exe | ❌ Same as PS 5.1 | Untested |
| curl.exe | ✅ Works | ✅ Works |

### PowerShell in BaseContainer

PowerShell (both 5.1 and 7+) fails with `STATUS_DLL_INIT_FAILED` (0xC0000142) when
BaseContainer uses default UI restrictions (`ui_restrictions=0x03FF`). This is because the
default-deny policy sets all UILIMIT flags, and PowerShell's DLL initialization requires
access to desktop handles.

**Workaround:** Set `appContainer.ui.isolation` to `"desktop"` in the ContainerConfig to
relax handle/atoms restrictions. This allows PowerShell to initialize while still enforcing
other restrictions (clipboard, injection, etc.).


## Network Limitations

### DNS Resolution

| Method | ProcessContainer |
|--------|------------------|
| PowerShell `Invoke-WebRequest` | ❌ DNS fails (uses .NET, not WinHTTP) |
| WinHTTP COM (`WinHttp.WinHttpRequest.5.1`) | ⚠️ See below |
| curl.exe | ❌ Doesn't use WinHTTP auto-proxy |

### PowerShell `Invoke-WebRequest` DNS Issue

`Invoke-WebRequest` uses .NET's `HttpClient` which performs DNS resolution in-process.
Inside ProcessContainer without DNS access, this fails because .NET performs
DNS resolution in-process.

**Workaround:** Use WinHTTP-based tools (curl.exe with proxy shim, or WinHTTP COM object)
instead of `Invoke-WebRequest` for network tests.

### Proxy Routing

The proxy URL is passed in the PSEC specification. The OS-level `appinfosvc`
configures WinHTTP proxy for the container. System-level WinHTTP sessions use
the proxy; app-created sessions may depend on how they are initialized.

### Admin Requirements

| Feature | Needs Admin? |
|---------|-------------|
| Basic AppContainer execution | No |
| BFS filesystem brokering | No |
| Network (capabilities only) | No |
| Network (firewall rules) | Yes — `netsh advfirewall` |
| SBOX proxy shim | Yes — elevated winhttp-proxy-shim |
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
| 0.7.0-alpha | Stable | ProcessContainer (capability-resolved) | Production |
| 0.8.0-alpha | Stable | ProcessContainer (capability-resolved) | Production |
| 0.9.0-alpha | Stable (current) | ProcessContainer (capability-resolved), IsolationSession, WSLC | Production |
| 0.10.0-alpha | Dev | ProcessContainer and development backends | Development |

The SDK and Rust parser accept only the exact registered versions
`0.6.0-alpha`, `0.7.0-alpha`, `0.8.0-alpha`, `0.9.0-alpha`, and
`0.10.0-alpha`; an unregistered spelling such as `0.6.1-alpha` is rejected.
The schema version does not select the Windows ProcessContainer tier —
BaseContainer versus AppContainer is resolved at runtime by host capability.
