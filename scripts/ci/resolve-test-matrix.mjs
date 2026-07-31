#!/usr/bin/env node

// Validates the declarative test catalog and emits GitHub Actions matrices.
// Keeping expansion here makes the workflow YAML small and lets CI reject an
// invalid catalog before allocating any specialized test runners.

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const FAMILIES = ['windows', 'linux', 'macos'];
const PLANS = ['pr', 'nightly', 'weekly'];
const ARM64_UNSUPPORTED_BACKENDS = new Set(['hyperlight', 'microvm']);

function combinationKey(plan, os, architecture, backend) {
  return `${plan}|${os}|${architecture}|${backend}`;
}

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
      } else {
        assertNonEmptyString(details.pool, `${platform.id}.${architecture}.pool`);
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

  const enabled = new Set();
  for (const entry of catalog.enabled ?? []) {
    if (!PLANS.includes(entry.plan)) {
      throw new Error(`enabled entry has unsupported plan ${entry.plan}`);
    }
    const platform = platforms.get(entry.os);
    const architecture = platform?.architectures?.[entry.architecture];
    if (!architecture?.backends?.includes(entry.backend)) {
      throw new Error(
        `enabled entry is unsupported: ${entry.os}/${entry.architecture}/${entry.backend}`
      );
    }
    const requested = (catalog.triggers?.[entry.plan] ?? [])
      .some(request => request.os === entry.os && request.backends.includes(entry.backend));
    if (!requested) {
      throw new Error(
        `enabled entry is not present in ${entry.plan}: ${entry.os}/${entry.backend}`
      );
    }
    const handler = catalog.handlers[platform.family][entry.backend];
    // Capability entries may describe future coverage, but enabled entries
    // must have an executable dispatcher command for their architecture.
    if (handler.status !== 'wired' || !handler.command) {
      throw new Error(
        `enabled entry has no wired handler: ${entry.os}/${entry.architecture}/${entry.backend}`
      );
    }
    if (handler.architectures && !handler.architectures.includes(entry.architecture)) {
      throw new Error(
        `enabled entry handler does not support ${entry.architecture}: `
        + `${entry.os}/${entry.backend}`
      );
    }
    const key = combinationKey(entry.plan, entry.os, entry.architecture, entry.backend);
    if (enabled.has(key)) {
      throw new Error(`duplicate enabled entry: ${key}`);
    }
    enabled.add(key);
  }

  return { platforms, enabled };
}

export function expandPlan(catalog, plan) {
  if (!PLANS.includes(plan)) {
    throw new Error(`unsupported plan: ${plan}`);
  }
  const { platforms } = validateCatalog(catalog);
  // Sunday is one run containing the normal nightly set plus weekly additions.
  const planNames = plan === 'weekly' ? ['nightly', 'weekly'] : [plan];
  const combinations = [];

  for (const planName of planNames) {
    for (const request of catalog.triggers[planName]) {
      const platform = platforms.get(request.os);
      // A trigger is architecture-neutral. Expand it only where the platform's
      // capability declaration supports the requested backend.
      for (const [architecture, details] of Object.entries(platform.architectures)) {
        for (const backend of request.backends) {
          if (!details.backends.includes(backend)) {
            continue;
          }
          combinations.push({
            plan: planName,
            os: platform.id,
            os_name: platform.displayName,
            family: platform.family,
            architecture,
            target: details.target,
            artifact: details.artifact,
            pool: details.pool,
            runner: details.runner,
            backend,
            command: catalog.handlers[platform.family][backend].command,
            handler_status: catalog.handlers[platform.family][backend].status
          });
        }
      }
    }
  }

  return combinations;
}

export function resolvePlan(catalog, plan) {
  const { enabled } = validateCatalog(catalog);
  const matrices = Object.fromEntries(FAMILIES.map(family => [family, []]));

  for (const combination of expandPlan(catalog, plan)) {
    const key = combinationKey(
      combination.plan,
      combination.os,
      combination.architecture,
      combination.backend
    );
    if (enabled.has(key)) {
      // family selects the workflow job and handler_status is validation-only;
      // neither belongs in the matrix consumed by the runner.
      const { family, handler_status: _, ...matrixEntry } = combination;
      matrices[family].push(matrixEntry);
    }
  }

  for (const family of FAMILIES) {
    // Stable ordering keeps local output and workflow diagnostics reproducible.
    matrices[family].sort((left, right) => (
      `${left.os}|${left.architecture}|${left.backend}`
        .localeCompare(`${right.os}|${right.architecture}|${right.backend}`)
    ));
  }
  return matrices;
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
    const defaultCatalog = path.join(path.dirname(currentFile), 'test-matrix.json');
    const catalog = readCatalog(path.resolve(args.catalog ?? defaultCatalog));
    writeOutputs(resolvePlan(catalog, args.plan));
  } catch (error) {
    process.stderr.write(`resolve-test-matrix: ${error.message}\n`);
    process.exitCode = 1;
  }
}
