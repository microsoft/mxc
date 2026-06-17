// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * `policy-regen` — derive an expanded `SandboxPolicy` from a base
 * policy + a list of `DeniedResource`s the user has approved.
 *
 * This is the post-capture, pre-retry step that makes the
 * captureDenials feature actionable:
 *
 *   1. The SDK runs the workload with `captureDenials: true` and
 *      collects denials via {@link parseDenialStream}.
 *   2. The application UX asks the user which denials to approve
 *      (which paths the workload should be allowed to access).
 *   3. `regenerateSandboxPolicy()` produces a new
 *      {@link SandboxPolicy} that augments the base policy with the
 *      approved paths.
 *   4. The SDK re-spawns the workload with the new policy.
 *
 * Scope: filesystem/registry-style file resources only — matches the
 * one resource kind {@link DeniedResource} currently carries. When
 * network denials are added, this module will need a parallel branch
 * for network grants.
 */

import type { SandboxPolicy } from './types.js';
import type { DeniedResource } from './denial-stream.js';
import { stripNtPrefix } from './denial-stream.js';

/**
 * Paths that the regen step refuses to grant even when the user
 * approves them. Granting these would punch holes in OS-level
 * security boundaries (e.g. handing the workload write access to
 * SYSTEM hives or `kernel32.dll`).
 *
 * These overlap with the `defaultDenialFilters` in
 * {@link parseDenialStream}, but the two serve different goals:
 *
 * - `defaultDenialFilters` hides the noise from the prompt UI so
 *   the user only sees actionable denials.
 * - `SYSTEM_CRITICAL_PATTERNS` enforces the "never grant" rule even
 *   if a noisy denial somehow made it past the filters and the user
 *   clicked approve. Defense-in-depth.
 */
const SYSTEM_CRITICAL_PATTERNS: readonly RegExp[] = [
  // Windows registry hives.
  /^\\REGISTRY\\/i,
  // Windows system directories (System32, SysWOW64, WinSxS).
  /^C:\\Windows\\(?:System32|SysWOW64|WinSxS)\\/i,
  // Critical system files at the root of C:\Windows.
  /^C:\\Windows\\(?:ntoskrnl|hal|win32k|csrss)\.exe$/i,
  // Boot files.
  /^C:\\(?:bootmgr|BOOTNXT|pagefile\.sys|hiberfil\.sys|swapfile\.sys)$/i,
];

/**
 * Input to {@link regenerateSandboxPolicy}.
 */
export interface RegenInput {
  /**
   * The policy the workload was originally run with. The regen
   * result extends this — it never *removes* an existing grant, only
   * adds. If the base policy already grants a path, the matching
   * approval is recorded under `skipped` with reason
   * `already-granted`.
   */
  basePolicy: SandboxPolicy;

  /**
   * The denials the user explicitly approved. Order is preserved in
   * the result so callers can correlate `added` / `skipped` entries
   * back to their UX rows.
   */
  approvedDenials: readonly DeniedResource[];

  /**
   * When a denial has `accessType: 'write'` and this is true, grant
   * read-write access to the path. When false (the default), grant
   * only read access regardless of the denied access kind — the
   * conservative choice when the UX doesn't surface the distinction.
   */
  upgradeWritesToReadwrite?: boolean;
}

/**
 * Outcome of a {@link regenerateSandboxPolicy} call.
 *
 * `policy` is the regenerated policy ready to hand back to
 * `spawnSandbox`. `added` / `skipped` together account for every
 * entry in `approvedDenials` so the UX can render an audit trail of
 * what the regen step actually did.
 */
export interface RegenResult {
  /** The expanded policy. */
  policy: SandboxPolicy;
  /** Paths that were added to the policy by this regen call. */
  added: ReadonlyArray<{
    kind: 'readonly' | 'readwrite';
    path: string;
  }>;
  /** Approvals that didn't translate into a new grant, with cause. */
  skipped: ReadonlyArray<{
    path: string;
    reason:
      | 'already-granted'
      | 'system-critical'
      | 'unsupported-kind'
      | 'invalid-path';
  }>;
}

/**
 * Derive an expanded `SandboxPolicy` from a base policy + a list of
 * `DeniedResource`s the user has approved.
 *
 * Properties of the result:
 *
 * - **Additive only.** Never removes existing grants.
 * - **Idempotent.** Re-running with the same approvals yields the
 *   same policy (already-granted approvals land in `skipped`).
 * - **Path-normalised.** Approvals carrying `\??\C:\…` are stripped
 *   to `C:\…` so the resulting policy matches what the user
 *   authored.
 * - **Defense-in-depth.** Anything matching {@link SYSTEM_CRITICAL_PATTERNS}
 *   is refused even if approved.
 *
 * The base policy is *not* mutated; the returned `policy` is a new
 * object with new array references for the touched fields.
 */
export function regenerateSandboxPolicy(input: RegenInput): RegenResult {
  const { basePolicy, approvedDenials, upgradeWritesToReadwrite = false } = input;

  // Snapshot existing grants for both idempotence checks and as the
  // starting point for the new arrays. We deduplicate using sets,
  // keyed on the case-insensitive normalised path so the same path
  // approved twice (or already in the base policy) doesn't appear
  // twice in the result.
  const existingReadonly = new Set(
    (basePolicy.filesystem?.readonlyPaths ?? []).map(normaliseKey),
  );
  const existingReadwrite = new Set(
    (basePolicy.filesystem?.readwritePaths ?? []).map(normaliseKey),
  );

  const newReadonly: string[] = [...(basePolicy.filesystem?.readonlyPaths ?? [])];
  const newReadwrite: string[] = [...(basePolicy.filesystem?.readwritePaths ?? [])];

  const added: { kind: 'readonly' | 'readwrite'; path: string }[] = [];
  const skipped: RegenResult['skipped'][number][] = [];

  for (const denial of approvedDenials) {
    if (denial.kind !== 'file') {
      skipped.push({ path: '<non-file>', reason: 'unsupported-kind' });
      continue;
    }

    const normalisedPath = stripNtPrefix(denial.path);
    if (!normalisedPath || normalisedPath.trim().length === 0) {
      skipped.push({ path: denial.path, reason: 'invalid-path' });
      continue;
    }

    if (isSystemCritical(normalisedPath)) {
      skipped.push({ path: normalisedPath, reason: 'system-critical' });
      continue;
    }

    const grantKind: 'readonly' | 'readwrite' =
      upgradeWritesToReadwrite && denial.accessType === 'write'
        ? 'readwrite'
        : 'readonly';

    const key = normaliseKey(normalisedPath);

    // Idempotence: if either bucket already covers the path, skip.
    // Readwrite implies read, so an existing readwrite grant
    // satisfies a new readonly approval too.
    if (existingReadwrite.has(key)) {
      skipped.push({ path: normalisedPath, reason: 'already-granted' });
      continue;
    }
    if (grantKind === 'readonly' && existingReadonly.has(key)) {
      skipped.push({ path: normalisedPath, reason: 'already-granted' });
      continue;
    }
    // Special case: upgrading a previously-readonly path to readwrite.
    // Drop it from readonly so we don't double-grant the same path
    // under both buckets (which the native parser would treat as a
    // configuration error on stricter schema versions).
    if (grantKind === 'readwrite' && existingReadonly.has(key)) {
      const idx = newReadonly.findIndex((p) => normaliseKey(p) === key);
      if (idx >= 0) newReadonly.splice(idx, 1);
      existingReadonly.delete(key);
    }

    if (grantKind === 'readonly') {
      newReadonly.push(normalisedPath);
      existingReadonly.add(key);
    } else {
      newReadwrite.push(normalisedPath);
      existingReadwrite.add(key);
    }
    added.push({ kind: grantKind, path: normalisedPath });
  }

  const policy: SandboxPolicy = {
    ...basePolicy,
    filesystem: {
      ...(basePolicy.filesystem ?? {}),
      readonlyPaths: newReadonly,
      readwritePaths: newReadwrite,
    },
  };

  return { policy, added, skipped };
}

/**
 * True when `path` matches a hard-coded list of OS-critical
 * locations the regen step refuses to grant.
 */
export function isSystemCritical(path: string): boolean {
  for (const pat of SYSTEM_CRITICAL_PATTERNS) {
    if (pat.test(path)) return true;
  }
  return false;
}

/**
 * Normalise a path into the key used for set membership / dedupe.
 * Windows paths are case-insensitive, so we lowercase. Trailing
 * separators are folded out so `C:\foo\` and `C:\foo` are the same
 * key.
 */
function normaliseKey(path: string): string {
  return path.toLowerCase().replace(/[\\/]+$/, '');
}
