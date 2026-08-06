#!/usr/bin/env node

// Validates the declarative test catalog and emits GitHub Actions matrices.
// Keeping expansion here makes the workflow YAML small and lets CI reject an
// invalid catalog before allocating any specialized test runners.

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const FAMILIES = ['windows', 'linux', 'macos'];
const PLANS = ['pr', 'nightly', 'weekly', 'enabled'];
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
        if (!catalog.handlers?.[platform.family]?.[backend]) {
          throw new Error(`missing ${platform.family} handler entry for ${backend}`);
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

  // Trigger entries name an OS/backend pair. Architecture expansion happens
  // later, so a backend is valid here when at least one OS architecture has it.
  for (const plan of PLANS) {
    const seenRequests = new Set();
    for (const request of catalog.triggers?.[plan] ?? []) {
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

  return { platforms };
}

export function expandPlan(catalog, plan) {
  if (!PLANS.includes(plan)) {
    throw new Error(`unsupported plan: ${plan}`);
  }
  const { platforms } = validateCatalog(catalog);
  const combinations = [];

  for (const request of catalog.triggers?.[plan] ?? []) {
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
        const handler = catalog.handlers[platform.family][backend];
        if (handler.architectures && !handler.architectures.includes(architecture)) {
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
          backend,
          command: handler.command,
          handler_status: handler.status
        });
      }
    }
  }

  return combinations;
}

export function resolvePlan(catalog, plan) {
  if (!PLANS.includes(plan)) {
    throw new Error(`unsupported plan: ${plan}`);
  }

  validateCatalog(catalog);
  const matrices = Object.fromEntries(FAMILIES.map(family => [family, []]));

  for (const combination of expandPlan(catalog, plan)) {
    if (combination.handler_status === 'wired' && combination.command) {
      // family selects the workflow job and handler_status is validation-only;
      // neither belongs in the matrix consumed by the runner.
      const { family, handler_status: _, ...matrixEntry } = combination;
      matrices[family].push(matrixEntry);
    }
  }

  suppressNonMacArm64(matrices);
  sortMatrices(matrices);
  return matrices;
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
