# Changelog

All notable changes to `@microsoft/mxc-sdk` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `getPlatformSupport()` now reports `uiCapabilities` on Windows when the
  native probe can determine which UI restrictions the host can enforce.

## [0.7.0]

### ⚠️ Breaking changes

- **`usePty` now defaults to `false`.** `spawnSandboxFromConfig` and
  `spawnSandboxAsync` spawn via `child_process` (pipe mode) unless called with
  `usePty: true`, so the default path no longer requires the optional `node-pty`
  peer dependency. `spawnSandboxFromConfig` therefore returns a `ChildProcess` by
  default (and `IPty` only when `usePty: true`); `spawnSandboxAsync` now returns
  real, separated `stdout`/`stderr` on the default path. `spawnSandbox` and
  `execInSandbox` are unchanged — they always use PTY and require `node-pty`.
- **`node-pty` moved from `dependencies` to an optional `peerDependency`.**
  Pipe-only consumers no longer pull it in transitively; consumers that use PTY
  mode must install `node-pty` themselves. `loadPty()` surfaces an actionable
  error when PTY mode is requested but the peer dependency is missing.

### Changed

- `node-pty` is loaded lazily, only when a PTY is actually spawned. Importing the
  SDK and spawning in pipe mode never evaluates `node-pty` or loads its native
  addon.
- The SDK's public PTY types (`IPty`, `IPtyForkOptions`, etc.) are now vendored
  and exported from the package itself. Consumers no longer need `node-pty`
  installed to type-check against the SDK (previously this failed with
  `TS2307: Cannot find module 'node-pty'`).

## [0.3.0]

### ⚠️ Breaking changes

- **Network policy is now deny-by-default.** `wxc-exec` is the trust boundary
  and falls back to `block` whenever `network.defaultPolicy` is omitted,
  regardless of the declared schema version. Callers that previously relied on
  the implicit `allow` default must now set `defaultPolicy: 'allow'`
  explicitly (or accept the deny default and grant specific hosts via
  `allowedHosts`).
- The new `0.6.0-alpha` schema documents the new default; `0.5.0-alpha` and
  the stable `0.4.0-alpha` schemas are unchanged, but the Rust parser still
  applies deny-by-default to them at the trust boundary.

## [0.2.0]

### ⚠️ Breaking changes

- **Pure ESM.** The package is now published as ECMAScript Modules only
  (`"type": "module"` with an `exports` map and no CommonJS build).
  - CommonJS consumers can no longer use synchronous `require('@microsoft/mxc-sdk')`.
    Switch to `await import('@microsoft/mxc-sdk')` from a CJS context, or move
    your project to ESM.
  - TypeScript consumers should set `"module": "NodeNext"` (or `"ESNext"`) and
    `"moduleResolution": "NodeNext"` (or `"Bundler"`) to resolve the package's
    types via the `exports` conditions map.
- **Minimum Node.js version raised to 18.0.0.** Node 16 reached end-of-life in
  September 2023 and is no longer supported.
- The redundant `"main"` field has been removed from `package.json`. Resolution
  goes through the `"exports"` map.

### Added

- `"exports"` map exposing the package root and `./package.json` (the latter
  required for tooling that does `require.resolve('@microsoft/mxc-sdk/package.json')`).
- Source maps and declaration maps are now shipped alongside the JavaScript
  output for better consumer debugging and go-to-definition.

## [0.1.8]

Last CommonJS release. See git history for prior changes.
