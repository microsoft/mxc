// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Learning mode — Box 2 of the learning-mode architecture.
 *
 * OS-agnostic orchestration on top of the {@link ../denial-channel}
 * box:
 *
 * - {@link ./policy-regen | `./policy-regen`} — turn a list of
 *   `DeniedResource` events into a regenerated `SandboxPolicy`.
 * - {@link ./spawn-with-retry | `./spawn-with-retry`} — drive the
 *   retry loop: spawn → parse stream → call `onDenied` → regen
 *   policy → respawn.
 *
 * Re-exported by the package root so external callers can write
 * `import { spawnSandboxWithRetry } from '@microsoft/mxc-sdk'`;
 * this file exists to make the subdirectory a coherent unit for
 * internal callers.
 */

export * from './policy-regen.js';
export * from './spawn-with-retry.js';
