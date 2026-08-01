# @microsoft/mxc-sdk-nanvix-win32-x64

Opt-in NanVix MicroVM runtime for
[`@microsoft/mxc-sdk`](https://www.npmjs.com/package/@microsoft/mxc-sdk),
targeting **win32-x64**.

Install this package explicitly when using `containment: "microvm"`:

```shell
npm install @microsoft/mxc-sdk @microsoft/mxc-sdk-nanvix-win32-x64
```

The package contains a compatible `wxc-exec.exe` together with the NanVix
daemon, root filesystem, kernel, initrd, and warm-start snapshots. The SDK
selects this executor for MicroVM requests so the runtime payload remains
co-located with it.

The native binaries are staged at build time and published from CI; they are
not committed to the repository.
