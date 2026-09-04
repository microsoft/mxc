# MXC UniFFI Node prototype

This prototype loads `mxc_uniffi` directly into Node through the generic `@ubjs/node` N-API runtime. It has no
MXC-specific C++, native addon, subprocess, daemon, RPC layer, or WebAssembly module.

## Regenerate

From the repository root:

```powershell
scripts\generate-uniffi-bindings.ps1
```

The script builds `src/ffi/mxc_uniffi` and regenerates this directory's `generated/` files from UniFFI metadata.
Do not edit files under `generated/`.

## Test

```powershell
cd sdk\node\prototype
npm install
npm test
```

The tests bundle the generated TypeScript, copy the debug Rust library beside it, and exercise the real in-process
implementation.

## Temporary upstream shim

`types/ubjs-node.d.ts` supplies declarations for `FfiType` and `resolveLibPath`. `@ubjs/node` 0.31.0-5 exports both
values from JavaScript but omits them from its declaration file. Remove the shim after the upstream package includes
those declarations.
