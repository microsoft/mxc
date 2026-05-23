// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { gt as semverGt, gte as semverGte, parse as semverParse } from 'semver';

/**
 * Semver string, e.g. `"0.6.0-alpha"`. Validated by callers via
 * `validatePolicyVersion`; the registry helpers below are permissive and
 * skip version-conditional checks when given an unparsable value.
 */
export type SemverString = string;

/**
 * Per-value metadata describing how a field value relates to the schema
 * versions the SDK supports. One entry per value the schemas have ever
 * accepted — canonical names and legacy aliases alike.
 *
 * When adding a value: set `addedIn` to the schema version that first
 * accepted it. When renaming a value: leave the legacy entry in place with
 * `deprecatedSince`, `renamedTo`, and (optionally) `removeIn` set, and add
 * a fresh entry for the canonical name with `addedIn` = the rename
 * version.
 */
export interface RegistryEntry {
    /** First schema version that accepted this value. */
    addedIn: SemverString;
    /** Schema version where this value was deprecated. Aliases are still accepted. */
    deprecatedSince?: SemverString;
    /** Canonical replacement value when `deprecatedSince` is set. */
    renamedTo?: string;
    /** Future schema version where this value will be rejected outright. */
    removeIn?: SemverString;
    /** True when the value requires `--experimental` in versions where it is current. */
    experimental?: boolean;
    /**
     * True for abstract intents (e.g. `"process"`, `"vm"`) that the native
     * binary resolves to a concrete backend at run time.
     */
    abstract?: boolean;
}

/** A registry keyed by field value. */
export type FieldRegistry = Readonly<Partial<Record<string, RegistryEntry>>>;

/**
 * Containment-field registry. Single source of truth for legacy aliases,
 * experimental gating, and abstract-intent recognition.
 *
 * The native binary (wxc-exec / lxc-exec / mxc-exec-mac) is the
 * authoritative validator of the wire payload; this registry mirrors
 * what the schemas say so the SDK can reject obviously-wrong configs
 * early and emit useful deprecation messages.
 */
export const ContainmentRegistry: FieldRegistry = {
    // Stable since the earliest supported schema.
    lxc:                { addedIn: '0.4.0-alpha' },

    // Renamed in 0.6: appcontainer → processcontainer.
    appcontainer:       { addedIn: '0.4.0-alpha', deprecatedSince: '0.6.0-alpha', renamedTo: 'processcontainer' },
    processcontainer:   { addedIn: '0.6.0-alpha' },

    // Added in 0.5.
    windows_sandbox:    { addedIn: '0.5.0-alpha', experimental: true },
    microvm:            { addedIn: '0.5.0-alpha', experimental: true },
    wslc:               { addedIn: '0.5.0-alpha', experimental: true },

    // Renamed in 0.6: macos_sandbox → seatbelt.
    macos_sandbox:      { addedIn: '0.5.0-alpha', deprecatedSince: '0.6.0-alpha', renamedTo: 'seatbelt', experimental: true },
    seatbelt:           { addedIn: '0.6.0-alpha', experimental: true },

    // Added in 0.6.
    isolation_session:  { addedIn: '0.6.0-alpha', experimental: true },
    bubblewrap:         { addedIn: '0.6.0-alpha', experimental: true },
    hyperlight:         { addedIn: '0.6.0-alpha', experimental: true },

    // Abstract intents.
    process:            { addedIn: '0.6.0-alpha', abstract: true },
    vm:                 { addedIn: '0.4.0-alpha', abstract: true },
};

/**
 * Verdict returned by {@link judge}. Conveys the version-aware decision
 * a caller should make about a given (field, value, declaredVersion)
 * triple. `canonical` is the value that downstream code should treat as
 * authoritative (the rename target when deprecated, otherwise the raw
 * value).
 */
export type Verdict =
    | { kind: 'ok'; canonical: string; entry: RegistryEntry }
    | { kind: 'ok-deprecated'; canonical: string; entry: RegistryEntry; deprecatedSince: SemverString; removeIn?: SemverString }
    | { kind: 'unknown'; rawValue: string }
    | { kind: 'too-new'; canonical: string; entry: RegistryEntry; addedIn: SemverString }
    | { kind: 'removed'; canonical: string; entry: RegistryEntry; removedIn: SemverString };

/**
 * Evaluate a value against a declared schema version.
 *
 * Pure function. No side effects. The caller decides what to do with each
 * verdict kind; see `helper.ts` for the one-shot containment consumer.
 *
 * `'unknown'` is returned for values that are not in the registry. Callers
 * should treat that as "no version-aware information; fall back to the
 * static TS union as the entry gate" — the registry is additive, not
 * replacing the TS union.
 *
 * `'too-new'` (anachronism) is plumbed through but not enforced by any
 * caller today. The verdict carries the metadata to flip to rejection
 * later without changing the registry shape.
 */
export function judge(reg: FieldRegistry, value: string, declaredVersion?: SemverString): Verdict {
    const entry = reg[value];
    if (!entry) {
        return { kind: 'unknown', rawValue: value };
    }

    const canonicalName = entry.renamedTo ?? value;
    const canonicalEntry = entry.renamedTo ? (reg[entry.renamedTo] ?? entry) : entry;

    const versionParseable = !!(declaredVersion && semverParse(declaredVersion));

    if (versionParseable && entry.removeIn && semverGte(declaredVersion as string, entry.removeIn)) {
        return { kind: 'removed', canonical: canonicalName, entry: canonicalEntry, removedIn: entry.removeIn };
    }

    if (entry.deprecatedSince && entry.renamedTo) {
        return {
            kind: 'ok-deprecated',
            canonical: canonicalName,
            entry: canonicalEntry,
            deprecatedSince: entry.deprecatedSince,
            removeIn: entry.removeIn,
        };
    }

    if (versionParseable && semverGt(entry.addedIn, declaredVersion as string)) {
        return { kind: 'too-new', canonical: canonicalName, entry: canonicalEntry, addedIn: entry.addedIn };
    }

    return { kind: 'ok', canonical: canonicalName, entry: canonicalEntry };
}

/**
 * List of containment values that require `--experimental`. Derived from
 * the registry — single source of truth.
 *
 * Retained as a named export because earlier SDK versions exposed an
 * `ExperimentalBackends` const; consumers (and the helper itself) can
 * continue using it without knowing the registry exists.
 */
export const ExperimentalContainments: readonly string[] = Object.entries(ContainmentRegistry)
    .filter(([, e]) => e?.experimental)
    .map(([k]) => k);
