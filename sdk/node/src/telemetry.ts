// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { execFileSync } from 'child_process';
import { findWxcExecutable } from './platform.js';

/**
 * The user's persisted telemetry consent decision.
 *
 * See `docs/telemetry/telemetry-consent-design.md` for the full design: MXC
 * only ever collects telemetry on Windows, and only when this flag is
 * `'granted'`. It is stored per-user by MXC itself
 * (`%LOCALAPPDATA%\mxc\telemetry-consent.json`) and is never derived from, or
 * synchronized with, any Windows-level diagnostics/consent setting (e.g.
 * Settings → Privacy → Diagnostics & feedback).
 */
export type TelemetryConsentState = 'granted' | 'denied' | 'undetermined' | 'not-applicable';

/**
 * Optional, free-form provenance recorded alongside a consent decision for
 * support/debugging only. Never transmitted anywhere.
 */
export type TelemetryConsentSource = 'prompt' | 'settings-toggle' | 'cli' | 'sdk' | (string & {});

/**
 * The administrative (MDM / Group Policy) telemetry decision for this machine.
 *
 * See `docs/telemetry/telemetry-policy.md`. An administrator can disable MXC
 * telemetry machine-wide via Intune, another MDM, or Group Policy. The policy
 * is a *ceiling, never a grant*: `'allowed'` does not mean telemetry is on,
 * only that an administrator has not forbidden it — an explicit user consent
 * grant is still required.
 *
 * `'blocked'` also covers "the policy could not be determined", so a host
 * should word its UI as "telemetry is unavailable on this device" rather than
 * asserting that an administrator is responsible.
 */
export type TelemetryPolicyState = 'unrestricted' | 'allowed' | 'blocked' | 'not-applicable';

/**
 * Runner injection seam: spawns `wxc-exec` with the given telemetry-consent
 * flags and returns its stdout. Replaceable in unit tests via
 * {@link _setTelemetryConsentRunner} so tests don't require a built
 * `wxc-exec.exe` or touch the real consent store.
 */
type ConsentRunner = (args: readonly string[]) => string;

function defaultConsentRunner(args: readonly string[]): string {
  const wxcPath = findWxcExecutable();
  if (!wxcPath) {
    // Only reachable on Windows: every public entry point returns early on
    // other platforms, so a missing executable here means a broken install,
    // not a non-Windows host. Throw rather than synthesising 'not-applicable',
    // which would tell the host that this machine never collects telemetry and
    // hide the broken install instead of reporting it.
    throw new Error('wxc-exec was not found; the MXC native binary is missing from this installation');
  }
  return execFileSync(wxcPath, args, {
    timeout: 5000,
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

let consentRunner: ConsentRunner = defaultConsentRunner;

/** @internal Test-only: override the consent CLI runner. */
export function _setTelemetryConsentRunner(runner: ConsentRunner | null): void {
  consentRunner = runner ?? defaultConsentRunner;
}

let platformOverride: NodeJS.Platform | null = null;

/**
 * @internal Test-only: pretend to be running on the given platform, so the
 * Windows-only guards can be exercised from a non-Windows CI machine.
 */
export function _setTelemetryPlatform(platform: NodeJS.Platform | null): void {
  platformOverride = platform;
}

function isWindows(): boolean {
  return (platformOverride ?? process.platform) === 'win32';
}

function isConsentState(value: unknown): value is TelemetryConsentState {
  return value === 'granted' || value === 'denied' || value === 'undetermined' || value === 'not-applicable';
}

function isPolicyState(value: unknown): value is TelemetryPolicyState {
  return value === 'unrestricted' || value === 'allowed' || value === 'blocked' || value === 'not-applicable';
}

/**
 * The parsed `--telemetry-consent-status` payload. `needsPrompt` and `policy`
 * are produced by Rust (`consent::needs_consent_prompt` and
 * `policy::get_policy`) rather than derived here, so the "should the host ask
 * the user?" and "has an administrator disabled this?" policies each have
 * exactly one implementation across the Rust, C#, and Node SDKs and the CLI.
 */
interface ParsedConsentOutput {
  state: TelemetryConsentState;
  needsPrompt: boolean;
  policy: TelemetryPolicyState;
  /**
   * Set when the output could not be fully understood, and omitted entirely
   * when it could.
   *
   * The parser is the only thing that knows whether a value was genuinely
   * read or substituted by a fail-closed default, so it reports that directly
   * rather than leaving the caller to re-derive it by inspecting the raw
   * stdout. A returned `'undetermined'` is otherwise indistinguishable from a
   * genuine "user has not decided yet".
   */
  error?: string;
}

function parseConsentOutput(stdout: string): ParsedConsentOutput {
  // Fail closed: any unexpected output (malformed JSON, unrecognised value)
  // is treated as "no consent", never "granted".
  const unreadable = (reason: string): ParsedConsentOutput => ({
    state: 'undetermined',
    needsPrompt: false,
    policy: 'blocked',
    error: `${reason}: ${stdout.trim().slice(0, 200)}`,
  });

  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return unreadable('unrecognised telemetry consent output');
  }
  if (parsed === null || typeof parsed !== 'object') {
    return unreadable('unrecognised telemetry consent output');
  }

  const record = parsed as Record<string, unknown>;
  if (!isConsentState(record.consent)) {
    return unreadable('unrecognised telemetry consent output');
  }
  const state = record.consent;

  // Fail closed: an unrecognised or absent policy field reports 'blocked',
  // never the permissive 'unrestricted'. This is a real fault (the SDK
  // resolves its own bundled binary, so a missing field means a broken or
  // mismatched install) and is reported as such rather than silently
  // downgraded — the consent value alone would still look perfectly valid.
  if (!isPolicyState(record.policy)) {
    return {
      state,
      needsPrompt: false,
      policy: 'blocked',
      error: `unrecognised telemetry policy state: ${stdout.trim().slice(0, 200)}`,
    };
  }
  const policy = record.policy;

  return {
    state,
    // Fail closed if the field is absent (a wxc-exec older than this SDK):
    // never prompt on a guess. A blocked policy also suppresses the prompt
    // unconditionally — the native layer already does this, but passing a
    // contradictory pair through would have the host prompt for a decision
    // that cannot take effect.
    needsPrompt: record.needsPrompt === true && policy !== 'blocked',
    policy,
  };
}

/**
 * The result of a telemetry-consent query, including *why* the state is what
 * it is.
 *
 * `getTelemetryConsent()` deliberately collapses every failure into
 * `'undetermined'` so a status read can never throw. That is the right
 * default, but it means a host cannot distinguish "the user has genuinely not
 * decided yet" (show the prompt) from "we could not reach `wxc-exec`" (a
 * broken install — prompting the user will not help, and the prompt's answer
 * cannot be persisted either). Use this when you need to tell those apart,
 * e.g. to log a diagnostic or suppress a prompt that is doomed to fail.
 */
export interface TelemetryConsentQuery {
  /** The consent state, using the same fail-closed rules as {@link getTelemetryConsent}. */
  state: TelemetryConsentState;
  /**
   * Whether the host should offer its own consent prompt. Reported by the
   * native layer (Rust `ConsentState::needs_prompt`), not derived from
   * `state` here, so the policy is identical across the Rust, C#, and Node
   * SDKs. Always `false` off Windows, and `false` whenever the state was
   * forced by a failure.
   */
  needsPrompt: boolean;
  /**
   * The administrative (MDM / Group Policy) ceiling. Reported by the native
   * layer, not derived here. `'blocked'` means nothing is collected regardless
   * of `state`, and `needsPrompt` will be `false`. Always `'not-applicable'`
   * off Windows, and `'blocked'` whenever the query failed.
   */
  policy: TelemetryPolicyState;
  /**
   * Present only when `state` was forced to `'undetermined'` by a failure
   * rather than read from the store. Human-readable, for diagnostics only —
   * do not parse it or branch on its contents.
   */
  error?: string;
}

/**
 * Report a failure that was swallowed to keep a privacy gate fail-closed.
 *
 * These paths deliberately return a safe value instead of throwing, which would
 * otherwise make a broken install completely silent: the three convenience
 * getters discard the {@link TelemetryConsentQuery.error} field entirely.
 *
 * Reported once per distinct failure per process — a host may poll these
 * getters (e.g. to render a settings toggle), and warning on every call would
 * be noise rather than signal.
 *
 * Never throws: it is called from the fail-closed paths whose whole purpose is
 * to guarantee the caller cannot crash.
 */
const reportedFailures = new Set<string>();

function reportFailClosed(operation: string, safeResult: string, detail: string): void {
  try {
    const message = `mxc-sdk: ${operation} failed and is reporting '${safeResult}' to stay fail-closed: ${detail}`;
    if (reportedFailures.has(message)) {
      return;
    }
    reportedFailures.add(message);
    console.warn(message);
  } catch {
    // Diagnostics must never be able to break the caller.
  }
}

/** @internal Test-only: forget which failures have already been reported. */
export function _resetTelemetryFailureReporting(): void {
  reportedFailures.clear();
}

/**
 * Read the persisted telemetry consent state, along with any error that
 * forced a fail-closed result. See {@link TelemetryConsentQuery}.
 *
 * Always succeeds — never throws.
 */
export function queryTelemetryConsent(): TelemetryConsentQuery {
  // Windows-only by design: MXC never collects telemetry on other platforms,
  // so there is nothing to consent to and hosts must not be told a decision
  // is pending. This guard must come first — without it, any runner failure
  // on macOS/Linux would surface as 'undetermined' and drive hosts into a
  // consent prompt they must never show.
  if (!isWindows()) {
    return { state: 'not-applicable', needsPrompt: false, policy: 'not-applicable' };
  }
  let stdout: string;
  try {
    stdout = consentRunner(['--telemetry-consent-status']);
  } catch (e) {
    // Fail closed: a spawn failure (missing binary, timeout, non-zero exit)
    // must not throw out of a "read-only status" query — treat it the same
    // as "no decision yet".
    const detail = e instanceof Error ? e.message : String(e);
    reportFailClosed('queryTelemetryConsent', 'undetermined', detail);
    return {
      state: 'undetermined',
      needsPrompt: false,
      policy: 'blocked',
      error: `failed to read telemetry consent: ${detail}`,
    };
  }
  const { state, needsPrompt, policy, error } = parseConsentOutput(stdout);
  if (error !== undefined) {
    reportFailClosed('queryTelemetryConsent', state, error);
    return { state, needsPrompt, policy, error };
  }
  return { state, needsPrompt, policy };
}

/**
 * Read the persisted telemetry consent state.
 *
 * Always succeeds — never throws for "no decision yet" or "not on Windows";
 * both are ordinary return values (`'undetermined'` and `'not-applicable'`
 * respectively). Use {@link queryTelemetryConsent} if you need to know
 * whether an `'undetermined'` result came from the store or from a failure.
 *
 * Each call spawns `wxc-exec` once. If you need more than one of the consent
 * state, the prompt flag, and the policy — as a startup path typically does —
 * call {@link queryTelemetryConsent} instead and read all three off the single
 * result, rather than calling these convenience getters in sequence.
 */
export function getTelemetryConsent(): TelemetryConsentState {
  return queryTelemetryConsent().state;
}

/**
 * Whether the hosting application should show its own first-run telemetry
 * consent prompt: `true` only on Windows, when no decision has been recorded
 * yet. MXC does not ship a consent UI itself — a hosting agent/SDK consumer
 * calls this once (e.g. right before its first `spawnSandbox` call), and if
 * it returns `true`, shows its own prompt and then calls
 * {@link setTelemetryConsent} with the user's choice.
 *
 * The answer comes from the native layer (Rust `ConsentState::needs_prompt`)
 * rather than being derived from {@link getTelemetryConsent} here, so the
 * policy is identical across the Rust, C#, and Node SDKs and the CLI.
 *
 * Always `false` when an administrator has blocked telemetry: there is no
 * decision left for the user to make. Spawns `wxc-exec` once per call; prefer
 * {@link queryTelemetryConsent} when you also need the consent state or the
 * policy.
 */
export function needsTelemetryConsentPrompt(): boolean {
  return queryTelemetryConsent().needsPrompt;
}

/**
 * Read the administrative (MDM / Group Policy) telemetry policy for this
 * machine. See {@link TelemetryPolicyState}.
 *
 * Use this to distinguish "the user has not opted in" from "telemetry is
 * unavailable on this device" so a settings surface can explain the
 * difference instead of rendering a toggle that silently does nothing.
 *
 * The policy is a ceiling, never a grant: a `'allowed'` result still requires
 * an explicit user consent grant before anything is collected.
 *
 * Always succeeds — never throws. Fails closed to `'blocked'`.
 *
 * Spawns `wxc-exec` once per call; prefer {@link queryTelemetryConsent} when
 * you also need the consent state or the prompt flag.
 */
export function getTelemetryPolicy(): TelemetryPolicyState {
  return queryTelemetryConsent().policy;
}

/**
 * Grant or revoke telemetry consent and persist the decision.
 *
 * @param granted `true` to grant, `false` to revoke/deny.
 * @param source Optional, free-form provenance for support/debugging (e.g.
 *   `'prompt'`, `'settings-toggle'`). Never transmitted anywhere. Defaults to
 *   `'sdk'`.
 * @throws {Error} if the decision could not be persisted — always the case
 *   on non-Windows hosts, since MXC must not collect, and therefore must not
 *   offer consent for, telemetry there.
 */
export function setTelemetryConsent(granted: boolean, source: TelemetryConsentSource = 'sdk'): void {
  if (!isWindows()) {
    throw new Error(
      'failed to persist telemetry consent: MXC only collects telemetry, and therefore only offers consent, on Windows',
    );
  }
  const args = [granted ? '--telemetry-consent-grant' : '--telemetry-consent-revoke', '--telemetry-consent-source', source];
  let stdout: string;
  try {
    stdout = consentRunner(args);
  } catch (e) {
    throw new Error(
      `failed to persist telemetry consent (MXC only collects telemetry, and only offers consent, on Windows): ${
        e instanceof Error ? e.message : String(e)
      }`,
    );
  }
  const { state } = parseConsentOutput(stdout);
  const expected: TelemetryConsentState = granted ? 'granted' : 'denied';
  if (state !== expected) {
    throw new Error(
      `failed to persist telemetry consent (MXC only collects telemetry, and only offers consent, on Windows); reported state: ${state}`,
    );
  }
}
