// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Worker-thread entry point for one-shot execution. It performs the blocking
// native call and sends a structured result or error back to the main thread.

import { parentPort, workerData } from 'node:worker_threads';
import { MxcError } from '../errors.js';
import { runBindingRequest } from './run.js';
import type {
  BindingRunWorkerData,
  BindingRunWorkerMessage,
} from './run-worker.js';

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

const data = workerData as BindingRunWorkerData;
let message: BindingRunWorkerMessage;
try {
  message = { ok: true, result: runBindingRequest(data.request) };
} catch (error) {
  message = { ok: false, error: serializeError(error) };
}
parentPort!.postMessage(message);
