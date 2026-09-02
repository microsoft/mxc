// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// State-aware wire-type conformance oracle (Phase 2.5).
//
// The one-shot oracle (`wire-conformance.test.ts`) asserts that
// `sdk/src/types.ts` conforms to the generated wire types. This companion does
// the same for the STATE-AWARE lifecycle public types in
// `sdk/src/state-aware-types.ts`, against the generated wire state-aware defs
// (`Phase`, `IsolationSessionProvisionPhase`).
// Without it, a wire-model change to the state-aware surface — a field added to
// a phase object, a `Phase` change — would
// regenerate `wire.ts`, pass the codegen gate, and still leave the SDK silently
// lagging with no CI signal.
//
// Mapping note (why this is a separate file, not part of the one-shot oracle):
// the public per-phase call configs do NOT map 1:1 to a single wire type. Each
// mixes SDK-level / top-level wire fields with per-phase wire fields:
//
//   public field                          wire location
//   ------------------------------------  --------------------------------------
//   *Config.version                       top-level `version` (SDK fills default)
//   ExecConfig.process                    top-level `Process`
//   ProvisionConfig.appId                 IsolationSessionProvisionPhase.appId
//
// The top-level fields are already covered by the one-shot oracle; here we (a)
// assert the per-phase configs REUSE those same public leaf types (so the
// delegation is real, not a re-derived shape that could escape the one-shot
// oracle), and (b) directly check the genuinely state-aware shapes (the phase
// enum and the per-phase field sets). The runtime
// body is a no-op; the guarantee is enforced at `tsc` time.

import { test } from 'node:test';

import type { ProcessConfig } from '../../src/types.js';

import type {
  Phase,
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
  Phase as WirePhase,
  IsolationSessionProvisionPhase as WireProvisionPhase,
  WslcProvisionPhase as WireWslcProvisionPhase,
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

// --- per-phase wire field-set conformance ----------------------------------

// The per-phase wire surface is DERIVED from the real public phase configs, not
// hand-restated, so a newly exposed public phase field cannot bypass the oracle
// (review finding F2). Each phase config splits into "lifted" fields that map to
// top-level wire locations (`version` is SDK metadata; `process` → top-level
// `Process`, both covered elsewhere) and backend-specific fields that map onto
// that phase's wire object.
//
// The wire model declares a SEPARATE type per phase, so the comparison is
// per-phase rather than a single pooled key set. That is strictly stronger: a
// field legal only on provision cannot satisfy the oracle by appearing
// on the start config, or vice versa.
//
// `filesystem` and `telemetry` are lifted top-level wire fields (like `network`):
// phase configs surface them publicly but they map to the envelope top level,
// not under `experimental.<backend>.<phase>`. Listing them here keeps the
// backend-key set limited to genuinely per-phase wire fields.
type LiftedPhaseKey = 'version' | 'process' | 'network' | 'filesystem' | 'telemetry';

type BackendKeys<C> = Exclude<keyof C, LiftedPhaseKey>;
type WireKeys<W> = keyof StripIndex<W>;

type PublicFieldValues<C, K extends PropertyKey = BackendKeys<C>> = {
  [P in K]: P extends keyof C ? NonNullable<C[P]> : never;
};
type WireFieldValues<W, K extends PropertyKey = WireKeys<W>> = {
  [P in K]: P extends keyof StripIndex<W> ? NonNullable<StripIndex<W>[P]> : never;
};

// provision: a public field with no wire counterpart, or a wire field the SDK
// forgot to surface, fails. Matching names must carry matching value types.
type _ProvisionPublicKeys = AssertTrue<
  Equivalent<Exclude<BackendKeys<IsolationSessionProvisionConfig>, WireKeys<WireProvisionPhase>>, never>
>;
type _ProvisionWireKeys = AssertTrue<
  Equivalent<Exclude<WireKeys<WireProvisionPhase>, BackendKeys<IsolationSessionProvisionConfig>>, never>
>;
type _ProvisionFieldValueTypes = AssertTrue<
  Equivalent<
    PublicFieldValues<IsolationSessionProvisionConfig>,
    WireFieldValues<WireProvisionPhase>
  >
>;

// start / exec / stop / deprovision take no per-phase wire object at all (their
// Rust associated types are `()`), so they must expose no backend-specific field.
type _StartNoBackendKeys = AssertTrue<Equivalent<BackendKeys<IsolationSessionStartConfig>, never>>;
type _ExecNoBackendKeys = AssertTrue<Equivalent<BackendKeys<IsolationSessionExecConfig>, never>>;
type _StopNoBackendKeys = AssertTrue<Equivalent<BackendKeys<IsolationSessionStopConfig>, never>>;
type _DeprovisionNoBackendKeys = AssertTrue<
  Equivalent<BackendKeys<IsolationSessionDeprovisionConfig>, never>
>;

// Non-vacuity guard. Every assertion above is of the form
// `Exclude<A, B> extends never`, which passes trivially if `A` resolves to
// `never` — so a mistake in the derivation would silently disable the oracle
// rather than fail it. Pin the derived key sets to their expected contents:
// adding a backend-specific field to the provision config must be a deliberate
// edit here, not a silent widening.
type _ProvisionKeysNonVacuous = AssertTrue<
  Equivalent<BackendKeys<IsolationSessionProvisionConfig>, 'appId'>
>;
type _ProvisionWireKeysNonVacuous = AssertTrue<
  Equivalent<WireKeys<WireProvisionPhase>, 'appId'>
>;

// --- WSLc per-phase wire field-set conformance -----------------------------

// WSLc is the second state-aware backend, so the oracle must cover it too or a
// wire-model change to the WSLc surface would regenerate `wire.ts`, pass the
// codegen gate, and leave the SDK silently lagging with no CI signal. WSLc's
// only per-phase wire object is provision (`image` / `imageTarPath`); start,
// exec, stop, and deprovision have wire associated type `()` and must expose no
// backend-specific field. `filesystem` and `network` are lifted top-level wire
// fields (see `LiftedPhaseKey`), so they are excluded from the backend-key sets.
type _WslcProvisionPublicKeys = AssertTrue<
  Equivalent<Exclude<BackendKeys<WslcProvisionConfig>, WireKeys<WireWslcProvisionPhase>>, never>
>;
type _WslcProvisionWireKeys = AssertTrue<
  Equivalent<Exclude<WireKeys<WireWslcProvisionPhase>, BackendKeys<WslcProvisionConfig>>, never>
>;
type _WslcProvisionFieldValueTypes = AssertTrue<
  Equivalent<
    PublicFieldValues<WslcProvisionConfig>,
    WireFieldValues<WireWslcProvisionPhase>
  >
>;

type _WslcStartNoBackendKeys = AssertTrue<Equivalent<BackendKeys<WslcStartConfig>, never>>;
type _WslcExecNoBackendKeys = AssertTrue<Equivalent<BackendKeys<WslcExecConfig>, never>>;
type _WslcStopNoBackendKeys = AssertTrue<Equivalent<BackendKeys<WslcStopConfig>, never>>;
type _WslcDeprovisionNoBackendKeys = AssertTrue<
  Equivalent<BackendKeys<WslcDeprovisionConfig>, never>
>;

// Non-vacuity guards (see the isolation_session pins above): pin the derived key
// sets so a derivation bug fails the oracle rather than silently disabling it.
type _WslcProvisionKeysNonVacuous = AssertTrue<
  Equivalent<BackendKeys<WslcProvisionConfig>, 'image' | 'imageTarPath'>
>;
type _WslcProvisionWireKeysNonVacuous = AssertTrue<
  Equivalent<WireKeys<WireWslcProvisionPhase>, 'image' | 'imageTarPath'>
>;

// --- delegation to the one-shot oracle (documented, asserted) --------------

// The per-phase configs must REUSE the public one-shot leaf types for their
// top-level fields, so the one-shot oracle already pins those shapes. If a config
// re-declared an inline shape instead, it would escape that coverage — these
// assertions fail if that ever happens.
type _ExecProcessReuse = AssertTrue<Equivalent<IsolationSessionExecConfig['process'], ProcessConfig>>;
type _WslcExecProcessReuse = AssertTrue<Equivalent<WslcExecConfig['process'], ProcessConfig>>;

// Reference the assertion aliases so they read as intentionally load-bearing.
export type StateAwareWireConformanceAssertions = [
  _Phase,
  _ProvisionPublicKeys,
  _ProvisionWireKeys,
  _ProvisionFieldValueTypes,
  _StartNoBackendKeys,
  _ExecNoBackendKeys,
  _StopNoBackendKeys,
  _DeprovisionNoBackendKeys,
  _ProvisionKeysNonVacuous,
  _ProvisionWireKeysNonVacuous,
  _ExecProcessReuse,
  _WslcProvisionPublicKeys,
  _WslcProvisionWireKeys,
  _WslcProvisionFieldValueTypes,
  _WslcStartNoBackendKeys,
  _WslcExecNoBackendKeys,
  _WslcStopNoBackendKeys,
  _WslcDeprovisionNoBackendKeys,
  _WslcProvisionKeysNonVacuous,
  _WslcProvisionWireKeysNonVacuous,
  _WslcExecProcessReuse,
];

test('public state-aware SDK types conform to the generated wire schema (compile-time)', () => {
  // Intentionally empty: the guarantee is enforced by the type aliases above at
  // `tsc` time. If they fail to compile, `npm run build:test-unit` fails before
  // this test ever runs.
});
