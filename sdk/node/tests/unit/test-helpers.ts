// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { SandboxSpawnOptions } from '../../src/sandbox.js';
import { getPlatformSupport } from '../../src/platform.js';

// Skip marker for describes that hit the binary resolver: undefined when MXC
// is supported on this host, an error string when it isn't.
export const platformSkip: string | false = !getPlatformSupport().isSupported
  ? 'MXC not supported on this machine'
  : false;

/** Options preset for unit tests that route through mxc_ffi instead of the executor. */
export function ffiTestOptions(extra?: Partial<SandboxSpawnOptions>): SandboxSpawnOptions {
  return { experimental: true, ...extra };
}
