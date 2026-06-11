// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createRequire } from 'node:module';
import type { NodePty } from './pty-types.js';

const require = createRequire(import.meta.url);

let cached: NodePty | undefined;

/**
 * Lazily loads the `node-pty` native addon.
 *
 * `node-pty` loads its native binary during module evaluation, so a top-level
 * `import` would force every consumer of the SDK to ship and load the addon —
 * even those that only ever spawn in pipe mode (`usePty: false`). Deferring the
 * require keeps the `usePty: false` path from ever touching `node-pty`.
 *
 * The return type is the vendored {@link NodePty} shape rather than node-pty's
 * own module type so the generated `.d.ts` stays self-contained and consumers
 * without the optional peer dependency can still type-check.
 *
 * Uses `createRequire` because `node-pty` is CommonJS and the call sites are
 * synchronous.
 */
export function loadPty(): NodePty {
  if (cached) {
    return cached;
  }
  try {
    cached = require('node-pty') as NodePty;
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e?.code === 'MODULE_NOT_FOUND' && /'node-pty'/.test(e.message)) {
      throw new Error(
        "PTY mode requires the optional peer dependency 'node-pty', which is not " +
          'installed. Install it (e.g. `npm install node-pty`) or spawn with `usePty: false`.',
      );
    }
    throw err;
  }
  return cached;
}
