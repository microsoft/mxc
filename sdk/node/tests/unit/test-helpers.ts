// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { getPlatformSupport } from '../../src/platform.js';

// Skip marker for describes that hit the binary resolver: undefined when MXC
// is supported on this host, an error string when it isn't.
export const platformSkip: string | false = !getPlatformSupport().isSupported
  ? 'MXC not supported on this machine'
  : false;
