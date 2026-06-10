// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let cached: typeof import('node-pty') | undefined;

/**
 * Lazily loads the `node-pty` native addon.
 *
 * `node-pty` loads its native binary during module evaluation, so a top-level
 * `import` would force every consumer of the SDK to ship and load the addon —
 * even those that only ever spawn in pipe mode (`usePty: false`). Deferring the
 * require keeps the `usePty: false` path from ever touching `node-pty`.
 *
 * Uses `createRequire` because `node-pty` is CommonJS and the call sites are
 * synchronous.
 */
export function loadPty(): typeof import('node-pty') {
  if (cached) {
    return cached;
  }
  try {
    cached = require('node-pty') as typeof import('node-pty');
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
