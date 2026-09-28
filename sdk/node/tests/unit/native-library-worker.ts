// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { isMainThread, parentPort } from 'node:worker_threads';
import { getAvailableBackends } from '../../src/index.js';

assert.strictEqual(isMainThread, false);
assert.ok(parentPort, 'native library fixture must run in a worker isolate');
parentPort.postMessage({
  isMainThread,
  backends: getAvailableBackends(),
});
