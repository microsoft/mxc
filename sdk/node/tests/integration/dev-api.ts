// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  runJson,
  spawnJson,
  spawnWithPtyJson,
  provisionContainerJson,
  type JsonOptions,
  type PtyJsonOptions,
  type PolicyPreparationOptions,
  type PreparedPolicyRequest,
  type PolicyFailures,
  parsePolicyFailures,
  serializePolicyFailures,
  mergePolicyFailures,
  preparePolicyJson,
  parsePreparedPolicyRequest,
  serializePreparedPolicyRequest,
  policyFailuresFromError,
  policyFailureResourceText,
} from '@microsoft/mxc-sdk/v1/dev';
import type { ExecutionResult, MxcProcess, MxcPtyProcess } from '@microsoft/mxc-sdk/v1';

export function verifyPackedDevSignatures(
  json: string,
  options: JsonOptions,
  ptyOptions: PtyJsonOptions,
): [Promise<ExecutionResult>, Promise<MxcProcess>, Promise<MxcPtyProcess>, Promise<string>] {
  return [
    runJson(json, options),
    spawnJson(json, options),
    spawnWithPtyJson(json, ptyOptions),
    provisionContainerJson(json, options),
  ];
}

export function verifyPackedPolicyPreparationSignatures(
  json: string,
  failures: PolicyFailures,
  error: unknown,
  options: PolicyPreparationOptions,
): [Promise<PreparedPolicyRequest>, PolicyFailures | undefined, string | undefined] {
  const restored = parsePolicyFailures(serializePolicyFailures(failures));
  const observed = policyFailuresFromError(error);
  const merged = observed === undefined ? restored : mergePolicyFailures(restored, observed);
  const detail = restored.results[0]?.details[0];
  return [
    preparePolicyJson(json, merged, options),
    observed,
    detail === undefined ? undefined : policyFailureResourceText(detail),
  ];
}

export async function prepareAndRunIfAccepted(
  requestJson: string,
  failures: PolicyFailures,
  accept: (candidate: PreparedPolicyRequest) => boolean | Promise<boolean>,
): Promise<ExecutionResult | undefined> {
  const prepared = await preparePolicyJson(requestJson, failures);
  const candidate = parsePreparedPolicyRequest(serializePreparedPolicyRequest(prepared));
  if (!await accept(candidate)) return undefined;
  return runJson(candidate.requestJson);
}
