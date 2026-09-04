// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

let addon: object | undefined;

/**
 * Locates the compiled Node-API module. Operation declarations deliberately
 * live in generated code; this module only owns addon discovery and caching.
 */
export function loadAddon(): object {
  if (addon !== undefined) {
    return addon;
  }

  const configured = process.env.MXC_NODE_ADDON;
  const candidates = configured === undefined
    ? [
      join(packageRoot, 'build', 'Release', 'mxc_node_ffi.node'),
      join(packageRoot, 'build', 'Debug', 'mxc_node_ffi.node'),
    ]
    : [configured];

  let lastError: unknown;
  for (const candidate of candidates) {
    try {
      addon = require(candidate) as object;
      return addon;
    } catch (error) {
      lastError = error;
    }
  }

  throw new Error(
    `Could not load the MXC Node-API prototype addon from ${candidates.join(', ')}.`,
    { cause: lastError },
  );
}
