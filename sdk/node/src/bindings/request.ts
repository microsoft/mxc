// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import type { SandboxContainment, SandboxPolicy } from '../types.js';

export interface BindingRunInput {
  script: string;
  policy: SandboxPolicy;
  workingDirectory?: string;
  containerName?: string;
  environment?: { [key: string]: string | undefined };
  experimental?: boolean;
  containment?: SandboxContainment;
}

/**
 * Policy projection accepted by the current `mxc_ffi::RequestSpec`.
 * Runtime network values move under `network`; backend-specific policy moves
 * onto the tagged containment value instead of remaining on shared policy.
 */
export type BindingPolicy = Omit<SandboxPolicy, 'runtimeConfig' | 'processContainer'> & {
  network?: NonNullable<SandboxPolicy['network']> & {
    runtimeConfig?: SandboxPolicy['runtimeConfig'];
  };
};

/**
 * Containment variants currently reachable from the one-shot Node API.
 * This mirrors the tagged JSON contract consumed by `mxc_ffi::RequestSpec`.
 */
export type BindingContainment = SandboxContainment;

export interface BindingSandboxRequest {
  policy: BindingPolicy;
  command: string;
  containment: BindingContainment;
  containerName?: string;
  workingDirectory?: string;
  environment: Record<string, string>;
  experimental: boolean;
}

export function bindingRequestUnsupportedReason(policy: SandboxPolicy): string | null {
  if (policy.network?.proxy !== undefined && 'builtinTestServer' in policy.network.proxy) {
    return 'network.proxy.builtinTestServer requires the executor testing-feature gate';
  }
  return null;
}

/**
 * Builds the private, co-versioned request object consumed by `mxc_ffi`.
 * JSON serialization belongs in the Koffi binding, mirroring the .NET SDK.
 */
export function prepareBindingSandboxRequest(
  input: BindingRunInput,
): BindingSandboxRequest {
  const unsupported = bindingRequestUnsupportedReason(input.policy);
  if (unsupported !== null) {
    throw new Error(unsupported);
  }

  const { runtimeConfig, processContainer, ...sharedPolicy } = input.policy;
  const policy: BindingPolicy = runtimeConfig === undefined
    ? sharedPolicy
    : {
        ...sharedPolicy,
        network: { ...sharedPolicy.network, runtimeConfig },
      };
  const environment = Object.fromEntries(
    Object.entries(input.environment ?? {}).filter((entry): entry is [string, string] =>
      entry[1] !== undefined),
  );

  const { name: _legacyName, ...processContainerContainment } = processContainer ?? {};
  const containment: BindingContainment = input.containment
    ?? (processContainer === undefined
      ? { type: 'process' }
      : { type: 'processContainer', ...processContainerContainment });

  return {
    policy,
    command: input.script,
    containment,
    containerName: input.containerName,
    workingDirectory: input.workingDirectory,
    environment,
    experimental: input.experimental ?? false,
  };
}
