// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  runJson,
  spawnJson,
  spawnWithPtyJson,
  provisionContainerJson,
  type JsonOptions,
  type PtyJsonOptions,
  type CreationJsonOptions,
  type PolicyFailures,
  parsePolicyFailures,
  serializePolicyFailures,
  policyFailuresFromError,
  policyFailureResourceText,
} from '@microsoft/mxc-sdk/v1/dev';
import type { ExecutionResult, MxcProcess, MxcPtyProcess } from '@microsoft/mxc-sdk/v1';

export function verifyPackedDevSignatures(
  json: string,
  options: JsonOptions,
  ptyOptions: PtyJsonOptions,
): [Promise<ExecutionResult>, Promise<MxcPtyProcess>, Promise<string>] {
  return [
    runJson(json, options),
    spawnWithPtyJson(json, ptyOptions),
    provisionContainerJson(json, options),
  ];
}

export function verifyPackedPolicyFeedbackSignatures(
  json: string,
  feedback: PolicyFailures,
  error: unknown,
): [Promise<ExecutionResult>, Promise<MxcProcess>, PolicyFailures | undefined, string | undefined] {
  const restored = parsePolicyFailures(serializePolicyFailures(feedback));
  const options: CreationJsonOptions = { policyFailures: restored };
  const detail = restored.results[0]?.details[0];
  return [
    runJson(json, options),
    spawnJson(json, options),
    policyFailuresFromError(error),
    detail === undefined ? undefined : policyFailureResourceText(detail),
  ];
}
