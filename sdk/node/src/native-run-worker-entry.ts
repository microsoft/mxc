// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { parentPort, workerData } from 'node:worker_threads';
import { MxcError } from './errors.js';
import { runNativeRequest } from './native-run.js';
import type {
  NativeRunWorkerData,
  NativeRunWorkerMessage,
} from './native-run-worker.js';

function serializeError(error: unknown) {
  if (error instanceof MxcError) {
    return {
      code: error.code,
      message: error.message,
      operation: error.operation,
      nativeCode: error.nativeCode,
      remediation: error.remediation,
      details: error.details,
    };
  }
  return {
    code: 'backend_error' as const,
    message: error instanceof Error ? error.message : String(error),
  };
}

const data = workerData as NativeRunWorkerData;
let message: NativeRunWorkerMessage;
try {
  message = { ok: true, result: runNativeRequest(data.requestJson) };
} catch (error) {
  message = { ok: false, error: serializeError(error) };
}
parentPort!.postMessage(message);
