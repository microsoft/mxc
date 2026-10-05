// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * MXC SDK - TypeScript SDK for Microsoft eXecution Containers
 *
 * This package provides a Node.js interface for spawning sandboxed containers.
 * For direct Windows ProcessContainer configs, set
 * `processContainer.learningMode: true` to enable deny-and-record learning
 * mode. Learning-mode capability names are reserved and must not be supplied
 * directly in `processContainer.capabilities`.
 * On Linux, `getPlatformSupport()` reports failures for individual backends
 * through `PlatformSupport.unavailableReasons`, including when none is usable.
 *
 * V1 request APIs live in `@microsoft/mxc-sdk/v1` and use directional
 * `network.egress` / `network.ingress`; explicit legacy network inputs produce
 * migration errors. The versioned V1 request and execution APIs are available
 * from `@microsoft/mxc-sdk/v1`.
 * One-shot proxy authoring uses `network.runtimeConfig.networkProxy`; WSLC
 * state-aware exec uses the same authoring path and maps it to the unchanged
 * top-level wire `runtimeConfig`. IsolationSession provision requires
 * directional egress, ingress, and host-loopback defaults set to `allow`.
 *
 * @example
 * ```typescript
 * import { getPlatformSupport } from '@microsoft/mxc-sdk/v1';
 * import { runAsync } from '@microsoft/mxc-sdk/v1';
 *
 * if (getPlatformSupport().isSupported) {
 *   const output = await runAsync({
 *     network: { egress: { default: 'allow' } },
 *     command: 'python -c "print(\'Hello from sandbox\')"',
 *   });
 *   console.log('Execution output:', output.stdout);
 *   console.log('Exit code:', output.exitCode);
 * }
 * ```
 *
 * @packageDocumentation
 */

export {};
