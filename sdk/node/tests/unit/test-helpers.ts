// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  _resetPlatformSupportCache,
  _setAvailableBackendsProbe,
  getPlatformSupport,
} from '../../src/platform.js';

// Unit tests exercise binary argument construction, not native discovery.
// Supply a deterministic Linux snapshot so importing this helper never loads
// an unavailable libmxc_ffi.so.
_setAvailableBackendsProbe(() => [
  { backend: 'bubblewrap', capabilities: [], warnings: [] },
]);
export const platformSkip: string | false = !getPlatformSupport().isSupported
  ? 'MXC not supported on this machine'
  : false;
_setAvailableBackendsProbe();
_resetPlatformSupportCache();
