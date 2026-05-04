# Changelog

All notable changes to `@microsoft/mxc-sdk` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
