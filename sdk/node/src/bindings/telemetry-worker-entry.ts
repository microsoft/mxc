// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Worker-thread entry point for blocking telemetry persistence operations.

import { parentPort, workerData } from 'node:worker_threads';
import { MxcError } from '../errors.js';
import {
  readTelemetryConsentSnapshot,
  requestTelemetryConsentJson,
  withdrawTelemetryConsentJson,
} from './telemetry.js';
import type {
  TelemetryWorkerData,
  TelemetryWorkerMessage,
} from './telemetry-worker.js';

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

const data = workerData as TelemetryWorkerData;
let message: TelemetryWorkerMessage;
try {
  switch (data.operation) {
    case 'query':
      message = { kind: 'snapshot', snapshot: readTelemetryConsentSnapshot() };
      break;
    case 'withdraw':
      message = { kind: 'payload', payload: withdrawTelemetryConsentJson() };
      break;
    case 'request': {
      const decision = new Int32Array(data.decisionShared);
      message = {
        kind: 'payload',
        payload: requestTelemetryConsentJson(data.locale, (promptJson) => {
          Atomics.store(decision, 0, 0);
          Atomics.store(decision, 1, 0);
          parentPort!.postMessage({ kind: 'present', promptJson } satisfies TelemetryWorkerMessage);
          Atomics.wait(decision, 0, 0);
          return Atomics.load(decision, 1);
        }),
      };
      break;
    }
  }
} catch (error) {
  message = { kind: 'error', error: serializeError(error) };
}
parentPort!.postMessage(message);
