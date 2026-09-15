// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Worker-thread entry point for a blocking state-aware lifecycle call. It
// returns the native response or a serialized error to the main thread.

import { parentPort, workerData } from 'node:worker_threads';
import { MxcError } from '../errors.js';
import { runBindingStateAwareRequest } from './state-aware.js';
import type {
  BindingStateAwareWorkerData,
  BindingStateAwareWorkerMessage,
} from './state-aware-worker.js';

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

const data = workerData as BindingStateAwareWorkerData;
let message: BindingStateAwareWorkerMessage;
try {
  message = { ok: true, responseJson: runBindingStateAwareRequest(data.request) };
} catch (error) {
  message = { ok: false, error: serializeError(error) };
}
parentPort!.postMessage(message);
