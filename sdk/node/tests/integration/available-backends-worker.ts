// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import { isMainThread, parentPort } from 'node:worker_threads';
import { getAvailableBackends } from '@microsoft/mxc-sdk';

assert.strictEqual(isMainThread, false);
assert.ok(parentPort, 'backend discovery fixture must run in a worker isolate');
parentPort.postMessage({
  isMainThread,
  backends: getAvailableBackends(),
});
