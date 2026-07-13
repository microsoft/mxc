// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Shared compile-time type-assertion helpers for the wire-conformance oracles
// (`wire-conformance.test.ts` for the one-shot surface and
// `wire-conformance-state-aware.test.ts` for the state-aware surface). These are
// type-only; the emitted `.js` is empty, so this module is never run by the test
// runner — it exists to keep the two oracles' helpers identical.

/** Compiles only when `T` is exactly `true`. */
export type AssertTrue<T extends true> = T;

/** Drop the `[k: string]: unknown` index signature the emitter writes on open objects. */
export type StripIndex<T> = { [K in keyof T as string extends K ? never : K]: T[K] };

/**
 * Recursively drop index signatures (open objects nest: e.g. `experimental.wslc`
 * and the `IsolationSession*` objects), so structural assignment is not tripped
 * by an emitted `[k: string]: unknown` at any depth. Modifiers (`?`) are
 * preserved because the mapped type is homomorphic over `keyof T`.
 */
export type DeepStripIndex<T> = T extends (infer E)[]
  ? DeepStripIndex<E>[]
  : T extends object
    ? { [K in keyof T as string extends K ? never : K]: DeepStripIndex<T[K]> }
    : T;

/** `true` iff every value of `A` is assignable to `B` (index signatures stripped, recursively). */
export type Assignable<A, B> = [A] extends [DeepStripIndex<B>] ? true : false;

/**
 * Keys present on the public type but absent from the wire type. `StripIndex`
 * drops the `[k: string]: unknown` on open generated objects; without it
 * `keyof Wire` would include `string` and `Exclude` would collapse to `never`,
 * making public-only key checks vacuous for open objects.
 */
export type OnlyInPublic<Pub, Wire> = Exclude<keyof Pub, keyof StripIndex<Wire>>;

/**
 * Keys present on the wire type but absent from the public type. Because every
 * generated wire field is optional, `Public extends Wire` stays true when the
 * SDK simply forgets a new wire field, so the value/`OnlyInPublic` checks alone
 * do NOT catch a wire-only ADDITION. This closes that direction. `StripIndex`
 * drops the `[k: string]: unknown` so the open objects don't make `keyof`
 * collapse to `string`.
 */
export type OnlyInWire<Pub, Wire> = Exclude<keyof StripIndex<Wire>, keyof Pub>;

/** `true` iff `A` and `B` are mutually assignable (same value set). */
export type Equivalent<A, B> = [A] extends [B]
  ? [B] extends [A]
    ? true
    : false
  : false;
