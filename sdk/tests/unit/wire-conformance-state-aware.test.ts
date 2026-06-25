// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// State-aware wire-type conformance oracle (Phase 2.5).
//
// The one-shot oracle (`wire-conformance.test.ts`) asserts that
// `sdk/src/types.ts` conforms to the generated wire types. This companion does
// the same for the STATE-AWARE lifecycle public types in
// `sdk/src/state-aware-types.ts`, against the generated wire state-aware defs
// (`Phase`, `IsolationConfigurationId`, `IsolationUser`, `IsolationSessionPhase`).
// Without it, a wire-model change to the state-aware surface — a new sizing
// profile, a field added to the Entra user bundle, a `Phase` change — would
// regenerate `wire.ts`, pass the codegen gate, and still leave the SDK silently
// lagging with no CI signal.
//
// Mapping note (why this is a separate file, not part of the one-shot oracle):
// the public per-phase call configs do NOT map 1:1 to a single wire type. Each
// mixes SDK-level / top-level wire fields with `IsolationSessionPhase` fields:
//
//   public field                          wire location
//   ------------------------------------  --------------------------------------
//   *Config.version                       top-level `version` (SDK fills default)
//   ProvisionConfig.filesystem            top-level `Filesystem`
//   ExecConfig.process                    top-level `Process`
//   StartConfig.configurationId           IsolationSessionPhase.configurationId
//   {Provision,Start}Config.user          IsolationSessionPhase.user / IsolationUser
//
// The top-level fields are already covered by the one-shot oracle; here we (a)
// assert the per-phase configs REUSE those same public leaf types (so the
// delegation is real, not a re-derived shape that could escape the one-shot
// oracle), and (b) directly check the genuinely state-aware shapes (the phase
// enum, the sizing-profile enum, the user bundle, and the `IsolationSessionPhase`
// field set). The runtime body is a no-op; the guarantee is enforced at `tsc`
// time.

import { test } from 'node:test';

import type { ProcessConfig, FilesystemConfig } from '../../src/types.js';

import type {
  Phase,
  IsolationSessionUserConfig,
  IsolationSessionProvisionConfig,
  IsolationSessionStartConfig,
  IsolationSessionExecConfig,
  IsolationSessionStopConfig,
  IsolationSessionDeprovisionConfig,
} from '../../src/state-aware-types.js';

import type {
  Phase as WirePhase,
  IsolationUser as WireIsolationUser,
  IsolationConfigurationId as WireIsolationConfigurationId,
  IsolationSessionPhase as WireIsolationSessionPhase,
} from '../../src/generated/wire.js';

import type {
  AssertTrue,
  StripIndex,
  OnlyInPublic,
  OnlyInWire,
  Equivalent,
} from './conformance-helpers.js';

// --- enum conformance ------------------------------------------------------

// The lifecycle phase enum must be value-for-value identical to the wire `Phase`.
type _Phase = AssertTrue<Equivalent<Phase, WirePhase>>;

// Sizing profile: the SDK exposes it inline on `startSandbox`. This is the exact
// drift case — a new wire `IsolationConfigurationId` value would otherwise be
// unrequestable through the SDK with no CI signal.
type _ConfigurationId = AssertTrue<
  Equivalent<NonNullable<IsolationSessionStartConfig['configurationId']>, WireIsolationConfigurationId>
>;

// --- user bundle conformance ----------------------------------------------

// `IsolationSessionUserConfig` is a class; compare its DATA shape (the symbol
// inspect method is not part of the wire contract) to wire `IsolationUser`.
// Value equivalence alone misses a NEW OPTIONAL wire field (an optional addition
// does not break mutual assignability), so the key sets are also pinned in both
// directions: a new wire credential field (optional or required) fails
// `_UserBundleWireKeys`, and a public-only field fails `_UserBundlePublicKeys`.
type PublicUserData = Pick<IsolationSessionUserConfig, 'upn' | 'wamToken'>;
type _UserBundleVals = AssertTrue<Equivalent<PublicUserData, WireIsolationUser>>;
type _UserBundleWireKeys = AssertTrue<Equivalent<OnlyInWire<PublicUserData, WireIsolationUser>, never>>;
type _UserBundlePublicKeys = AssertTrue<Equivalent<OnlyInPublic<PublicUserData, WireIsolationUser>, never>>;

// Both phases that accept a user bundle must reuse the SAME public type, so the
// bundle check above covers them transitively.
type _ProvisionUserReuse = AssertTrue<
  Equivalent<NonNullable<IsolationSessionProvisionConfig['user']>, IsolationSessionUserConfig>
>;
type _StartUserReuse = AssertTrue<
  Equivalent<NonNullable<IsolationSessionStartConfig['user']>, IsolationSessionUserConfig>
>;

// --- IsolationSessionPhase field-set conformance ---------------------------

// The per-phase wire surface is DERIVED from the real public phase configs, not
// hand-restated, so a newly exposed public phase field cannot bypass the oracle
// (review finding F2). Each phase config splits into "lifted" fields that map to
// top-level wire locations (`version` is SDK metadata; `filesystem` → top-level
// `Filesystem`; `process` → top-level `Process`, all covered elsewhere) and
// backend-specific fields that map onto the wire `IsolationSessionPhase` object.
// `PublicPhaseKeys` is the union of those backend-specific keys across all five
// phase configs.
type LiftedPhaseKey = 'version' | 'filesystem' | 'process';
type PublicPhaseKeys = Exclude<
  | keyof IsolationSessionProvisionConfig
  | keyof IsolationSessionStartConfig
  | keyof IsolationSessionExecConfig
  | keyof IsolationSessionStopConfig
  | keyof IsolationSessionDeprovisionConfig,
  LiftedPhaseKey
>;
type WirePhaseKeys = keyof StripIndex<WireIsolationSessionPhase>;

// A public phase field with no wire `IsolationSessionPhase` counterpart fails
// (the SDK exposes a field the wire model does not define).
type _PhasePublicKeys = AssertTrue<Equivalent<Exclude<PublicPhaseKeys, WirePhaseKeys>, never>>;
// A wire `IsolationSessionPhase` field no phase config exposes fails (the wire
// model gained a per-phase field the SDK forgot to surface).
type _PhaseWireKeys = AssertTrue<Equivalent<Exclude<WirePhaseKeys, PublicPhaseKeys>, never>>;
// The per-field VALUES of the two backend-specific phase fields are pinned
// individually above: `configurationId` by `_ConfigurationId` and `user` by the
// `_UserBundle*` checks.

// --- delegation to the one-shot oracle (documented, asserted) --------------

// The per-phase configs must REUSE the public one-shot leaf types for their
// top-level fields, so the one-shot oracle already pins those shapes. If a config
// re-declared an inline shape instead, it would escape that coverage — these
// assertions fail if that ever happens.
type _ExecProcessReuse = AssertTrue<Equivalent<IsolationSessionExecConfig['process'], ProcessConfig>>;
type _ProvisionFilesystemReuse = AssertTrue<
  Equivalent<NonNullable<IsolationSessionProvisionConfig['filesystem']>, FilesystemConfig>
>;

// Reference the assertion aliases so they read as intentionally load-bearing.
export type StateAwareWireConformanceAssertions = [
  _Phase,
  _ConfigurationId,
  _UserBundleVals,
  _UserBundleWireKeys,
  _UserBundlePublicKeys,
  _ProvisionUserReuse,
  _StartUserReuse,
  _PhaseWireKeys,
  _PhasePublicKeys,
  _ExecProcessReuse,
  _ProvisionFilesystemReuse,
];

test('public state-aware SDK types conform to the generated wire schema (compile-time)', () => {
  // Intentionally empty: the guarantee is enforced by the type aliases above at
  // `tsc` time. If they fail to compile, `npm run build:test-unit` fails before
  // this test ever runs.
});
