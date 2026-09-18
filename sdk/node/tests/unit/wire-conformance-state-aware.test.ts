// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Lifecycle operation and sandbox identity are API arguments, not wire fields.
// This oracle verifies that lifecycle configs reuse the operation-neutral 0.9
// request's field types and direct backend configuration objects.

import { test } from 'node:test';

import type { ProcessConfig } from '../../src/types.js';
import type {
  IsolationSessionProvisionConfig,
  IsolationSessionStartConfig,
  IsolationSessionExecConfig,
  IsolationSessionStopConfig,
  IsolationSessionDeprovisionConfig,
  WslcProvisionConfig,
  WslcStartConfig,
  WslcExecConfig,
  WslcStopConfig,
  WslcDeprovisionConfig,
} from '../../src/state-aware-types.js';
import type {
  IsolationSession as WireIsolationSession,
  OneShotWslc as WireWslc,
  Request as WireRequest,
} from '../../src/generated/v0_9_0_alpha/wire.js';
import type { AssertTrue, Equivalent } from './conformance-helpers.js';

type LiftedKey = 'version' | 'process' | 'network' | 'runtimeConfig' | 'filesystem' | 'telemetry';
type BackendKeys<C> = Exclude<keyof C, LiftedKey>;
type FieldValues<C, K extends PropertyKey = keyof C> = {
  [P in K]: P extends keyof C ? NonNullable<C[P]> : never;
};

type _ExactWslcNetwork = AssertTrue<
  Equivalent<NonNullable<WslcProvisionConfig['network']>, NonNullable<WireRequest['network']>>
>;
type _ExactExecRuntime = AssertTrue<
  Equivalent<NonNullable<WslcExecConfig['runtimeConfig']>, NonNullable<WireRequest['runtimeConfig']>>
>;
type _ExecProcessReuse = AssertTrue<
  Equivalent<IsolationSessionExecConfig['process'], ProcessConfig>
>;
type _WslcExecProcessReuse = AssertTrue<Equivalent<WslcExecConfig['process'], ProcessConfig>>;

type IsoBackendFields = Pick<IsolationSessionProvisionConfig, BackendKeys<IsolationSessionProvisionConfig>>;
type _IsoProvisionFields = AssertTrue<
  Equivalent<FieldValues<IsoBackendFields>, FieldValues<WireIsolationSession>>
>;

type WireWslcProvision = Pick<WireWslc, 'image' | 'imageTarPath'>;
type WslcBackendFields = Pick<WslcProvisionConfig, BackendKeys<WslcProvisionConfig>>;
type _WslcProvisionFields = AssertTrue<
  Equivalent<FieldValues<WslcBackendFields>, FieldValues<WireWslcProvision>>
>;

type _IsoStartNoBackendFields = AssertTrue<Equivalent<BackendKeys<IsolationSessionStartConfig>, never>>;
type _IsoExecNoBackendFields = AssertTrue<Equivalent<BackendKeys<IsolationSessionExecConfig>, never>>;
type _IsoStopNoBackendFields = AssertTrue<Equivalent<BackendKeys<IsolationSessionStopConfig>, never>>;
type _IsoDeprovisionNoBackendFields = AssertTrue<
  Equivalent<BackendKeys<IsolationSessionDeprovisionConfig>, never>
>;
type _WslcStartNoBackendFields = AssertTrue<Equivalent<BackendKeys<WslcStartConfig>, never>>;
type _WslcExecNoBackendFields = AssertTrue<Equivalent<BackendKeys<WslcExecConfig>, never>>;
type _WslcStopNoBackendFields = AssertTrue<Equivalent<BackendKeys<WslcStopConfig>, never>>;
type _WslcDeprovisionNoBackendFields = AssertTrue<
  Equivalent<BackendKeys<WslcDeprovisionConfig>, never>
>;

export type StateAwareWireConformanceAssertions = [
  _ExactWslcNetwork,
  _ExactExecRuntime,
  _ExecProcessReuse,
  _WslcExecProcessReuse,
  _IsoProvisionFields,
  _WslcProvisionFields,
  _IsoStartNoBackendFields,
  _IsoExecNoBackendFields,
  _IsoStopNoBackendFields,
  _IsoDeprovisionNoBackendFields,
  _WslcStartNoBackendFields,
  _WslcExecNoBackendFields,
  _WslcStopNoBackendFields,
  _WslcDeprovisionNoBackendFields,
];

test('public lifecycle SDK types conform to the operation-neutral wire schema', () => {
  // Compile-time assertions above provide the coverage.
});
