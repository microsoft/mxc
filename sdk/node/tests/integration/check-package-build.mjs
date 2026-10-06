// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const integrationRoot = path.dirname(fileURLToPath(import.meta.url));
const sdkRoot = path.resolve(integrationRoot, '..', '..');
const npmCli = process.env.npm_execpath;
if (!npmCli) {
  throw new Error('run this check through npm run typecheck:integration');
}

function runNpm(args, cwd, capture = false) {
  const result = spawnSync(process.execPath, [npmCli, ...args], {
    cwd,
    encoding: 'utf8',
    stdio: capture ? ['ignore', 'pipe', 'inherit'] : 'inherit',
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`npm ${args.join(' ')} failed with ${result.signal ?? result.status}`);
  }
  return result.stdout;
}

const temporaryRoot = mkdtempSync(path.join(tmpdir(), 'mxc-sdk-integration-'));
try {
  const packed = JSON.parse(runNpm(
    ['pack', '--ignore-scripts', '--json', '--pack-destination', temporaryRoot],
    sdkRoot,
    true,
  ));
  if (packed.length !== 1 || typeof packed[0].filename !== 'string') {
    throw new Error('npm pack did not produce exactly one SDK package');
  }

  // Compile away from the checkout so its dist cannot satisfy private imports.
  const fixtureRoot = path.join(temporaryRoot, 'integration');
  mkdirSync(fixtureRoot);
  for (const name of readdirSync(integrationRoot)) {
    if (name.endsWith('.ts') || name === 'tsconfig.json' || name === 'package-lock.json') {
      copyFileSync(path.join(integrationRoot, name), path.join(fixtureRoot, name));
    }
  }
  const manifest = JSON.parse(readFileSync(path.join(integrationRoot, 'package.json'), 'utf8'));
  manifest.dependencies['@microsoft/mxc-sdk'] = path.join(temporaryRoot, packed[0].filename);
  writeFileSync(path.join(fixtureRoot, 'package.json'), JSON.stringify(manifest, null, 2));

  runNpm(['install', '--ignore-scripts', '--no-audit', '--no-fund'], fixtureRoot);
  runNpm(['run', 'build'], fixtureRoot);
  console.log('Packed SDK integration build passed without checkout build output.');
} finally {
  rmSync(temporaryRoot, { recursive: true, force: true });
}
