// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import type { SandboxPolicy } from './types.js';

export interface NativeRunInput {
  script: string;
  policy: SandboxPolicy;
  workingDirectory?: string;
  containerName?: string;
  environment?: { [key: string]: string | undefined };
  experimental?: boolean;
}

type BindingPolicy = Omit<SandboxPolicy, 'runtimeConfig' | 'processContainer'> & {
  network?: NonNullable<SandboxPolicy['network']> & {
    runtimeConfig?: SandboxPolicy['runtimeConfig'];
  };
};

export function inProcessUnsupportedReason(policy: SandboxPolicy): string | null {
  if (policy.processContainer !== undefined) {
    return 'processContainer policy requires the executor path';
  }
  if (policy.network?.proxy !== undefined && 'builtinTestServer' in policy.network.proxy) {
    return 'network.proxy.builtinTestServer requires the executor testing-feature gate';
  }
  return null;
}

export function serializeNativeRunRequest(input: NativeRunInput): string {
  const unsupported = inProcessUnsupportedReason(input.policy);
  if (unsupported !== null) {
    throw new Error(unsupported);
  }

  const { runtimeConfig, processContainer: _, ...sharedPolicy } = input.policy;
  const policy: BindingPolicy = {
    ...sharedPolicy,
    network: runtimeConfig === undefined
      ? sharedPolicy.network
      : { ...sharedPolicy.network, runtimeConfig },
  };
  const environment = Object.fromEntries(
    Object.entries(input.environment ?? {}).filter((entry): entry is [string, string] =>
      entry[1] !== undefined),
  );

  return JSON.stringify({
    policy,
    command: input.script,
    containment: { type: 'process' },
    containerName: input.containerName,
    workingDirectory: input.workingDirectory,
    environment,
    experimental: input.experimental ?? false,
  });
}
