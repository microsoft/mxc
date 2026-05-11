// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  FilesystemConfig,
  ProcessConfig,
  SandboxingMethod,
} from './types.js';

/**
 * Lifecycle phase in a state-aware sandbox request.
 */
export type Phase = 'provision' | 'start' | 'exec' | 'stop' | 'deprovision';

/**
 * Subset of `SandboxingMethod` whose backends participate in the state-aware
 * lifecycle. Extended as more backends opt in.
 */
export type StateAwareSandboxingMethod = Extract<SandboxingMethod, 'isolation_session'>;

/**
 * Branded sandbox identifier returned by `provisionSandbox` and routed back
 * to the same backend by subsequent phases. The runtime value is a plain
 * string; the brand exists at compile time only — TypeScript prevents
 * callers from passing a bare string, or a `SandboxId` from one backend
 * where one for a different backend is expected.
 */
export type SandboxId<C extends StateAwareSandboxingMethod> =
  string & { readonly __mxcBrand: 'SandboxId'; readonly __mxcBackend: C };

// IsolationSession per-(backend, phase) Configs. Each declares only
// the fields the SDK currently exposes at that phase — scoped to
// what the backend honors per the policy honor matrix and currently
// implements. TypeScript rejects passing fields outside this set.

export interface IsolationSessionProvisionConfig {
  /** Schema version (semver). When omitted, the SDK fills in its own SUPPORTED_VERSION. */
  version?: string;
  filesystem?: FilesystemConfig;
}

export interface IsolationSessionStartConfig {
  /** Schema version (semver). */
  version?: string;
  /**
   * Selected IsoSession size profile. Unknown values are warned and
   * downgraded to `'composable'` on the Rust side.
   */
  configurationId?: 'small' | 'medium' | 'large' | 'composable';
}

export interface IsolationSessionExecConfig {
  /** Schema version (semver). */
  version?: string;
  process: ProcessConfig;
}

export interface IsolationSessionStopConfig {
  /** Schema version (semver). */
  version?: string;
}

export interface IsolationSessionDeprovisionConfig {
  /** Schema version (semver). */
  version?: string;
}

/**
 * IsolationSession's provision-phase metadata: the per-instance agent user
 * account name minted for this sandbox.
 */
export interface IsolationSessionProvisionMetadata {
  agentUserName: string;
}

/**
 * Per-backend per-phase typed Config bundle. Selects the correct Config
 * bundle for the backend type parameter.
 */
export type ConfigsForBackend<C extends StateAwareSandboxingMethod> =
  C extends 'isolation_session'
    ? {
        provision: IsolationSessionProvisionConfig;
        start: IsolationSessionStartConfig;
        exec: IsolationSessionExecConfig;
        stop: IsolationSessionStopConfig;
        deprovision: IsolationSessionDeprovisionConfig;
      }
    : never;

export type ProvisionConfigFor<C extends StateAwareSandboxingMethod> =
  ConfigsForBackend<C>['provision'];
export type StartConfigFor<C extends StateAwareSandboxingMethod> =
  ConfigsForBackend<C>['start'];
export type ExecConfigFor<C extends StateAwareSandboxingMethod> =
  ConfigsForBackend<C>['exec'];
export type StopConfigFor<C extends StateAwareSandboxingMethod> =
  ConfigsForBackend<C>['stop'];
export type DeprovisionConfigFor<C extends StateAwareSandboxingMethod> =
  ConfigsForBackend<C>['deprovision'];

/**
 * Per-backend per-phase metadata bundle. Backends that don't return
 * metadata for a given phase omit that key.
 */
export interface StateAwareMetadata {
  isolation_session?: {
    provision?: IsolationSessionProvisionMetadata;
    // IsolationSession returns no metadata for start, stop, or deprovision.
  };
  // Future state-aware-capable backends add typed entries here.
}

type MetadataForPhase<C extends StateAwareSandboxingMethod, Phase extends string> =
  Phase extends keyof NonNullable<StateAwareMetadata[C]>
    ? NonNullable<StateAwareMetadata[C]>[Phase]
    : undefined;

export type ProvisionMetadataFor<C extends StateAwareSandboxingMethod> = MetadataForPhase<C, 'provision'>;
export type StartMetadataFor<C extends StateAwareSandboxingMethod> = MetadataForPhase<C, 'start'>;
export type StopMetadataFor<C extends StateAwareSandboxingMethod> = MetadataForPhase<C, 'stop'>;
export type DeprovisionMetadataFor<C extends StateAwareSandboxingMethod> = MetadataForPhase<C, 'deprovision'>;

export interface ProvisionResult<C extends StateAwareSandboxingMethod> {
  sandboxId: SandboxId<C>;
  metadata?: ProvisionMetadataFor<C>;
}

export interface StartResult<C extends StateAwareSandboxingMethod> {
  metadata?: StartMetadataFor<C>;
}

export interface StopResult<C extends StateAwareSandboxingMethod> {
  metadata?: StopMetadataFor<C>;
}

export interface DeprovisionResult<C extends StateAwareSandboxingMethod> {
  metadata?: DeprovisionMetadataFor<C>;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}
