#!/usr/bin/env node

// Validates the declarative test catalog and emits GitHub Actions matrices.
// Keeping expansion here makes the workflow YAML small and lets CI reject an
// invalid catalog before allocating any specialized test runners.

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const FAMILIES = ['windows', 'linux', 'macos'];
const ARM64_UNSUPPORTED_BACKENDS = new Set(['hyperlight', 'microvm']);

function assertNonEmptyString(value, label) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${label} must be a non-empty string`);
  }
}

export function readCatalog(catalogPath) {
  return JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
}

export function validateCatalog(catalog) {
  if (catalog.schemaVersion !== 1) {
    throw new Error(`unsupported catalog schemaVersion: ${catalog.schemaVersion}`);
  }

  const platforms = new Map();
  const targets = new Set();
  for (const platform of catalog.platforms ?? []) {
    assertNonEmptyString(platform.id, 'platform.id');
    assertNonEmptyString(platform.displayName, `${platform.id}.displayName`);
    if (!FAMILIES.includes(platform.family)) {
      throw new Error(`${platform.id} has unsupported family ${platform.family}`);
    }
    if (platforms.has(platform.id)) {
      throw new Error(`duplicate platform id: ${platform.id}`);
    }
    if (platform.prerelease === true) {
      // Prerelease platforms use neutral IDs in public matrix fields.
      if (!/^windows-prerelease-[a-z-]+$/.test(platform.id)) {
        throw new Error(`${platform.id} must use a neutral prerelease-platform alias`);
      }
    }

    const architectures = Object.entries(platform.architectures ?? {});
    if (architectures.length === 0) {
      throw new Error(`${platform.id} has no architectures`);
    }

    for (const [architecture, details] of architectures) {
      if (!['x64', 'arm64'].includes(architecture)) {
        throw new Error(`${platform.id} has unsupported architecture ${architecture}`);
      }
      assertNonEmptyString(details.target, `${platform.id}.${architecture}.target`);
      assertNonEmptyString(details.artifact, `${platform.id}.${architecture}.artifact`);
      targets.add(details.target);

      if (platform.family === 'macos') {
        assertNonEmptyString(details.runner, `${platform.id}.${architecture}.runner`);
      } else if (details.pool != null && typeof details.pool !== 'string') {
        throw new Error(`${platform.id}.${architecture}.pool must be a string`);
      }

      const backends = new Set();
      for (const backend of details.backends ?? []) {
        assertNonEmptyString(backend, `${platform.id}.${architecture}.backend`);
        if (backends.has(backend)) {
          throw new Error(`duplicate backend ${backend} on ${platform.id}/${architecture}`);
        }
        if (architecture === 'arm64' && ARM64_UNSUPPORTED_BACKENDS.has(backend)) {
          throw new Error(`${backend} cannot be scheduled on arm64 (${platform.id})`);
        }
        backends.add(backend);
      }
    }
    platforms.set(platform.id, platform);
  }

  const expectedTargets = new Set([
    'aarch64-apple-darwin',
    'aarch64-pc-windows-msvc',
    'aarch64-unknown-linux-gnu',
    'x86_64-pc-windows-msvc',
    'x86_64-unknown-linux-gnu'
  ]);
  if (targets.size !== expectedTargets.size
      || [...expectedTargets].some(target => !targets.has(target))) {
    throw new Error(`catalog targets do not match the five required build targets`);
  }

  // The catalog's `triggers` keys are the plan list: a plan exists because it
  // is declared there.
  const triggers = catalog.triggers;
  if (triggers == null || typeof triggers !== 'object' || Array.isArray(triggers)) {
    throw new Error('catalog triggers must be an object keyed by plan name');
  }
  const plans = Object.keys(triggers);
  if (plans.length === 0) {
    throw new Error('catalog declares no plans under triggers');
  }

  // Trigger entries name an OS/backend pair. Architecture expansion happens
  // later, so a backend is valid here when at least one OS architecture has it.
  for (const plan of plans) {
    assertNonEmptyString(plan, 'trigger plan name');
    if (!Array.isArray(triggers[plan])) {
      throw new Error(`${plan} must be an array of trigger requests`);
    }

    const seenRequests = new Set();
    for (const request of triggers[plan]) {
      const platform = platforms.get(request.os);
      if (!platform) {
        throw new Error(`${plan} references unknown platform ${request.os}`);
      }
      for (const backend of request.backends ?? []) {
        const requestKey = `${request.os}|${backend}`;
        if (seenRequests.has(requestKey)) {
          throw new Error(`duplicate ${plan} request ${requestKey}`);
        }
        const supported = Object.values(platform.architectures)
          .some(details => details.backends.includes(backend));
        if (!supported) {
          throw new Error(`${plan} requests unsupported ${request.os}/${backend}`);
        }
        seenRequests.add(requestKey);
      }
    }
  }

  validateBackendDelayedStart(catalog);

  return { platforms, plans };
}

// backendDelayedStart is optional: an absent or empty section means every job
// starts as soon as its runner is ready.
function validateBackendDelayedStart(catalog) {
  const delays = catalog.backendDelayedStart;
  if (delays == null) {
    return;
  }
  if (!Array.isArray(delays)) {
    throw new Error('catalog backendDelayedStart must be an array');
  }

  const seen = new Set();
  for (const entry of delays) {
    if (entry == null || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error('each backendDelayedStart entry must be an object');
    }
    assertNonEmptyString(entry.backend, 'backendDelayedStart backend');
    if (seen.has(entry.backend)) {
      throw new Error(`duplicate backendDelayedStart entry for ${entry.backend}`);
    }
    seen.add(entry.backend);

    if (!Number.isInteger(entry.minutes) || entry.minutes < 0) {
      throw new Error(
        `backendDelayedStart ${entry.backend} minutes must be a non-negative integer`
      );
    }
  }
}

export function expandPlan(catalog, plan) {
  const { platforms, plans } = validateCatalog(catalog);
  if (!plans.includes(plan)) {
    throw new Error(`unsupported plan: ${plan} (catalog declares: ${plans.join(', ')})`);
  }
  const combinations = [];

  for (const request of catalog.triggers[plan]) {
    const platform = platforms.get(request.os);
    // A trigger is architecture-neutral. Expand it only where the platform's
    // capability declaration supports the requested backend.
    for (const [architecture, details] of Object.entries(platform.architectures)) {
      if (platform.family !== 'macos' && !details.pool?.trim()) {
        continue;
      }
      for (const backend of request.backends) {
        if (!details.backends.includes(backend)) {
          continue;
        }
        combinations.push({
          plan,
          os: platform.id,
          os_name: platform.displayName,
          family: platform.family,
          architecture,
          target: details.target,
          artifact: details.artifact,
          pool: details.pool,
          runner: details.runner,
          backend
        });
      }
    }
  }

  return combinations;
}

export function resolvePlan(catalog, plan) {
  // expandPlan validates the catalog and rejects an unknown plan name.
  const matrices = Object.fromEntries(FAMILIES.map(family => [family, []]));

  for (const combination of expandPlan(catalog, plan)) {
    // A trigger entry means "run this". A backend without a test script fails
    // in the dispatcher, which is an actionable result: write the tests or
    // remove the backend from the trigger.
    const { family, ...matrixEntry } = combination;
    matrices[family].push(matrixEntry);
  }

  suppressNonMacArm64(matrices);
  sortMatrices(matrices);
  applyDelayedStart(matrices, catalog.backendDelayedStart);
  return matrices;
}

// A backend named in backendDelayedStart has its jobs started at staggered
// offsets rather than all at once. This exists for backends whose setup
// downloads a large runtime or several container images: every runner in a
// pool shares one egress address, so simultaneous starts concentrate that
// traffic into a burst that draws rate limiting and stalled downloads.
//
// The entry's minutes value is the gap between consecutive jobs of that
// backend, counted independently per backend. Applied after sorting so the
// assignment follows the emitted order and stays reproducible.
function applyDelayedStart(matrices, delays) {
  if (!Array.isArray(delays) || delays.length === 0) {
    return;
  }

  const stepMinutes = new Map(delays.map(entry => [entry.backend, entry.minutes]));
  const scheduled = new Map();

  for (const family of FAMILIES) {
    for (const entry of matrices[family]) {
      const step = stepMinutes.get(entry.backend);
      if (step === undefined) {
        continue;
      }
      const position = scheduled.get(entry.backend) ?? 0;
      entry.startup_delay_minutes = position * step;
      scheduled.set(entry.backend, position + 1);
    }
  }
}

// Windows and Linux ARM64 hosted VMs currently lack nested virtualization.
// Keep their catalog entries intact for future enablement, but never emit them
// until suitable test hosts are available. macOS remains ARM64-only.
function suppressNonMacArm64(matrices) {
  for (const family of ['windows', 'linux']) {
    matrices[family] = matrices[family]
      .filter(entry => entry.architecture !== 'arm64');
  }
}

function sortMatrices(matrices) {
  for (const family of FAMILIES) {
    // Stable ordering keeps local output and workflow diagnostics reproducible.
    matrices[family].sort((left, right) => (
      `${left.os}|${left.architecture}|${left.backend}`
        .localeCompare(`${right.os}|${right.architecture}|${right.backend}`)
    ));
  }
}

function parseArguments(argv) {
  const args = { plan: undefined, catalog: undefined };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--plan') {
      args.plan = argv[++index];
    } else if (argument === '--catalog') {
      args.catalog = argv[++index];
    } else {
      throw new Error(`unknown argument: ${argument}`);
    }
  }
  if (!args.plan) {
    throw new Error('--plan is required');
  }
  return args;
}

function writeOutputs(matrices) {
  const lines = [];
  for (const family of FAMILIES) {
    // Empty-matrix flags let the reusable workflow skip an OS-family job
    // instead of asking GitHub Actions to evaluate an empty matrix.
    lines.push(`${family}=${JSON.stringify({ include: matrices[family] })}`);
    lines.push(`has_${family}=${matrices[family].length > 0}`);
  }

  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `${lines.join('\n')}\n`);
  } else {
    process.stdout.write(`${lines.join('\n')}\n`);
  }
}

const currentFile = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === currentFile) {
  try {
    const args = parseArguments(process.argv.slice(2));
    const defaultCatalog = path.join(path.dirname(currentFile), 'validation-test-matrix.json');
    const catalog = readCatalog(path.resolve(args.catalog ?? defaultCatalog));
    writeOutputs(resolvePlan(catalog, args.plan));
  } catch (error) {
    process.stderr.write(`resolve-validation-test-matrix: ${error.message}\n`);
    process.exitCode = 1;
  }
}
