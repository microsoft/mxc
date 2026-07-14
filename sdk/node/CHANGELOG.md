# Changelog

All notable changes to `@microsoft/mxc-sdk` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `getPlatformSupport()` now reports `uiCapabilities` on Windows when the
  native probe can determine which UI restrictions the host can enforce.

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
