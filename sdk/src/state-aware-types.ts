// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  FilesystemConfig,
  NetworkConfig,
  ProcessConfig,
  SandboxingMethod,
  UiConfig,
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

// IsolationSession per-(backend, phase) Configs. Each declares only the
// fields valid for the IsolationSession backend at that phase. Cross-cutting
// fields appear inline at the Config root, only in phases where the backend
// honors them per its policy honor matrix; phases with no backend-specific
// or cross-cutting fields declare a Config carrying only `version?` —
// explicit and minimal.

export interface IsolationSessionProvisionConfig {
  /** Schema version (semver). When omitted, the SDK fills in its own SUPPORTED_VERSION. */
  version?: string;
  filesystem?: FilesystemConfig;
  network?: NetworkConfig;
  ui?: UiConfig;
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

export type ProvisionMetadataFor<C extends StateAwareSandboxingMethod> =
  'provision' extends keyof NonNullable<StateAwareMetadata[C]>
    ? NonNullable<StateAwareMetadata[C]>['provision']
    : undefined;
export type StartMetadataFor<C extends StateAwareSandboxingMethod> =
  'start' extends keyof NonNullable<StateAwareMetadata[C]>
    ? NonNullable<StateAwareMetadata[C]>['start']
    : undefined;
export type StopMetadataFor<C extends StateAwareSandboxingMethod> =
  'stop' extends keyof NonNullable<StateAwareMetadata[C]>
    ? NonNullable<StateAwareMetadata[C]>['stop']
    : undefined;
export type DeprovisionMetadataFor<C extends StateAwareSandboxingMethod> =
  'deprovision' extends keyof NonNullable<StateAwareMetadata[C]>
    ? NonNullable<StateAwareMetadata[C]>['deprovision']
    : undefined;

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
