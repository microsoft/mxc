// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  runJson,
  spawnWithPtyJson,
  provisionContainerJson,
  type JsonOptions,
  type PtyJsonOptions,
} from '@microsoft/mxc-sdk/v1/dev';
import type { ExecutionResult, MxcPtyProcess } from '@microsoft/mxc-sdk/v1';

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
