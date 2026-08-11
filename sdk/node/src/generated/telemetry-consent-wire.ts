// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/* eslint-disable */
/**
 * GENERATED FILE — DO NOT EDIT BY HAND.
 *
 * Emitted from the generated JSON Schema (itself generated from the Rust wire
 * model `wxc_common::wire`) by the `mxc_schema_gen --ts` TypeScript emitter
 * (`wxc_common::ts_emit`). This is a drift oracle, not public API: it is never
 * exported from the SDK. The conformance test asserts the hand-written public
 * types in `../types.ts` still match these. CI gate:
 * `scripts/versioning/check-sdk-types-codegen.js`.
 *
 * Regenerate with:
 *   cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- --ts sdk/node/src/generated/wire.ts
 */
/**
 * Telemetry-consent maintenance action.
 */
export type TelemetryConsentAction = "request" | "withdraw" | "status";

/**
 * Fixed telemetry-consent maintenance command discriminator.
 */
export type TelemetryConsentCommand = "telemetryConsent";

/**
 * Typed decision returned by a consent presenter.
 */
export type TelemetryConsentDecision = "yes" | "no" | "dismissed";

/**
 * Telemetry-consent maintenance request.
 * 
 * This is a separate contract from [`MxcConfig`], even though executors use the same JSON input loader for both. Its explicit `command` discriminator lets the loader route maintenance without widening the execution schema.
 */
export interface TelemetryConsentMaintenanceRequest {
  /**
   * Optional JSON Schema reference for editor validation.
   */
  $schema?: string | null;
  /**
   * Consent operation to perform.
   */
  action: unknown;
  /**
   * Fixed maintenance discriminator. Must be `"telemetryConsent"`.
   */
  command: unknown;
  /**
   * Preferred BCP 47 locale for the canonical prompt. Unsupported locales fall back to `en-US`. Used only by `request`.
   */
  locale?: string | null;
}

/**
 * Typed telemetry-consent maintenance response.
 */
export interface TelemetryConsentMaintenanceResponse {
  action: TelemetryConsentAction;
  /**
   * Opaque, single-request challenge for the private SDK presenter handshake. Never persisted.
   */
  challenge?: string | null;
  effectiveState: TelemetryConsentState;
  needsPrompt: boolean;
  policy: TelemetryConsentPolicyState;
  /**
   * Present only during the private SDK presenter handshake.
   */
  prompt?: TelemetryConsentPrompt | null;
  reason?: TelemetryConsentStatusReason | null;
  result: TelemetryConsentResult;
  storedState: TelemetryConsentState;
}

/**
 * One canonical prompt message.
 */
export interface TelemetryConsentMessage {
  id: string;
  text: string;
}

/**
 * Stable policy-state strings used by maintenance responses.
 */
export type TelemetryConsentPolicyState = "unrestricted" | "allowed" | "blocked" | "not-applicable";

/**
 * Private, session-bound presenter response consumed by the same executor process that emitted the challenge.
 */
export interface TelemetryConsentPresenterResponse {
  challenge: string;
  decision: TelemetryConsentDecision;
  resourceVersion: number;
}

/**
 * Canonical prompt data supplied to an SDK presenter.
 */
export interface TelemetryConsentPrompt {
  affirmativeLabel: TelemetryConsentMessage;
  body: TelemetryConsentMessage;
  learnMoreLabel: TelemetryConsentMessage;
  learnMoreUrl: string;
  locale: string;
  negativeLabel: TelemetryConsentMessage;
  resourceVersion: number;
  title: TelemetryConsentMessage;
}

/**
 * Typed result of a telemetry-consent maintenance action.
 */
export type TelemetryConsentResult = "status" | "presentationRequired" | "granted" | "denied" | "dismissed" | "withdrawn" | "alreadyGranted" | "policyBlocked" | "presentationUnavailable" | "notApplicable";

/**
 * Stable consent-state strings used by maintenance responses.
 */
export type TelemetryConsentState = "granted" | "denied" | "undetermined" | "not-applicable";

/**
 * Why persisted consent is not currently effective.
 */
export type TelemetryConsentStatusReason = "no-record" | "store-unreadable" | "store-malformed" | "consent-schema-unsupported" | "prompt-version-missing" | "prompt-version-unsupported" | "policy-blocked" | "presentation-unavailable" | "not-applicable";

export interface MXCConfiguration {
  presenter_response: TelemetryConsentPresenterResponse;
  request: TelemetryConsentMaintenanceRequest;
  response: TelemetryConsentMaintenanceResponse;
  [k: string]: unknown;
}

