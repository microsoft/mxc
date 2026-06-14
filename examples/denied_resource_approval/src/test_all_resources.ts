// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * All-Resource Denial Detection — Interactive Approval Demo
 *
 * Demonstrates MXC's denied-resource detection and policy regeneration
 * across supported resource types: file and network.
 *
 * Flow:
 *   1. Run sandbox with restrictive policy → process fails
 *   2. Detect what was denied (tiered detection)
 *   3. User approves/denies each resource
 *   4. Regenerate policy → re-run sandbox
 *   5. Show clear before/after comparison
 *
 * Usage:
 *   npm run build && npm run test:all-resources
 */

import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import { fileURLToPath } from 'url';
import * as readline from 'readline';

import {
  spawnSandboxFromConfig,
  createConfigFromPolicy,
  SandboxPolicy,
  DeniedResourceInfo,
  getAvailableToolsPolicy,
  getTemporaryFilesPolicy,
  getDeniedResources,
  generateUpdatedPolicyFromDetection,
  DetectionResult,
  ApprovedPath,
} from '@microsoft/mxc-sdk';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const EXAMPLE_ROOT = path.resolve(__dirname, '..');
const TEST_SCRIPT = path.join(EXAMPLE_ROOT, 'test_all_resources.py');

// Target directory for file write test — outside sandbox policy (home dir, NOT temp)
const TARGET_DIR = path.join(os.homedir(), 'mxc_all_resources_test');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function banner(msg: string): void {
  console.log();
  console.log(`  ${'━'.repeat(56)}`);
  console.log(`  ${msg}`);
  console.log(`  ${'━'.repeat(56)}`);
  console.log();
}

async function ask(question: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

/** Extract lines matching [type] SUCCESS or [type] DENIED from Python output */
function extractResultLines(output: string): string[] {
  return output.split('\n')
    .filter(line => /\[(file|network)\]\s*(SUCCESS|DENIED):/.test(line))
    .map(line => line.trim());
}

// ---------------------------------------------------------------------------
// Build restrictive policy (no network, minimal filesystem)
// ---------------------------------------------------------------------------

function buildRestrictivePolicy(): SandboxPolicy {
  const toolsPolicy = getAvailableToolsPolicy(process.env, { containerType: 'processcontainer' });
  const tempPolicy = getTemporaryFilesPolicy();

  const toolReadwritePaths = [
    ...toolsPolicy.readwritePaths,
    ...toolsPolicy.readonlyPaths.filter(p => {
      const normalized = path.resolve(p).toLowerCase();
      return normalized.length > 3;
    }),
    ...tempPolicy.readwritePaths,
  ];

  return {
    version: '0.4.0-alpha',
    filesystem: {
      readonlyPaths: [path.dirname(TEST_SCRIPT)],
      readwritePaths: toolReadwritePaths,
    },
    network: { allowOutbound: false },
  };
}

// ---------------------------------------------------------------------------
// Run sandbox and capture output
// ---------------------------------------------------------------------------

async function runSandbox(
  policy: SandboxPolicy,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  process.env['MXC_TEST_TARGET_DIR'] = TARGET_DIR;

  const config = createConfigFromPolicy(policy, undefined, 'all-resources-test');
  config.containment = 'processcontainer';
  config.process!.commandLine = `python "${TEST_SCRIPT}"`;

  return new Promise((resolve, reject) => {
    try {
      // Use usePty: false to pipe output silently (no TTY leakage to console)
      const child = spawnSandboxFromConfig(config, { usePty: false });
      let stdout = '';
      let stderr = '';

      child.stdout!.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
      child.stderr!.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });

      child.on('close', (code: number | null) => {
        resolve({ stdout, stderr, exitCode: code ?? 1 });
      });
      child.on('error', (err: Error) => {
        reject(err);
      });
    } catch (error) {
      reject(error);
    }
  });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  banner('MXC Denied Resource Detection — All Resource Types');

  // Ensure target directory exists
  fs.mkdirSync(TARGET_DIR, { recursive: true });

  // === STEP 1: First run ===
  console.log('  [1/5] Running sandbox with restrictive policy...');
  console.log(`        Network: blocked | File target: ${TARGET_DIR}`);
  console.log();

  const initialPolicy = buildRestrictivePolicy();
  const firstRun = await runSandbox(initialPolicy);

  if (firstRun.exitCode === 0) {
    console.log('  ✓ Process succeeded — no denials to handle.');
    process.exit(0);
  }

  // Show compact result from first run
  const firstResults = extractResultLines(firstRun.stdout);
  for (const line of firstResults) {
    const isDenied = line.includes('DENIED');
    const icon = isDenied ? '  ✗' : '  ✓';
    console.log(`    ${icon} ${line}`);
  }
  console.log();

  // === STEP 2: Detect ===
  console.log('  [2/5] Detecting denied resources...');

  const detection: DetectionResult = await getDeniedResources({
    containerName: 'all-resources-test',
    output: firstRun.stdout + firstRun.stderr,
  });

  console.log(`        Detection source: ${detection.serviceAvailable ? 'ETW service (kernel-accurate)' : 'output parsing (heuristic)'}`);
  console.log(`        Found ${detection.deniedResources.length} denied resource(s):`);
  console.log();

  // Group and display
  const denialsByType = new Map<string, DeniedResourceInfo[]>();
  for (const denial of detection.deniedResources) {
    const existing = denialsByType.get(denial.resourceType) ?? [];
    existing.push(denial);
    denialsByType.set(denial.resourceType, existing);
  }

  for (const [type, denials] of denialsByType) {
    console.log(`        ${type.toUpperCase()}:`);
    for (const d of denials) {
      console.log(`          • ${d.path}`);
    }
  }

  if (detection.deniedResources.length === 0) {
    console.log('        Process failed but no denied resources detected.');
    process.exit(1);
  }

  // === STEP 3: Approve ===
  banner('Resource Approval');
  console.log('  For each denied resource, choose:');
  console.log('    [y] Grant access    [r] Read-only    [n] Keep blocked');
  console.log();

  const approved: ApprovedPath[] = [];
  const userDeniedPaths = new Set<string>();

  for (const denial of detection.deniedResources) {
    const tag = denial.resourceType.toUpperCase().padEnd(8);
    // Show what action approving this resource will take
    let action: string;
    switch (denial.resourceType) {
      case 'file': action = '→ adds to filesystem policy'; break;
      case 'network': action = `→ adds host to network.allowedHosts`; break;
      default: action = ''; break;
    }
    console.log(`  [${tag}] ${denial.path}`);
    console.log(`             ${action}`);
    const answer = await ask(`             Allow? [y/r/n]: `);

    if (answer.toLowerCase() === 'y') {
      approved.push({ path: denial.path, accessLevel: 'readwrite' });
    } else if (answer.toLowerCase() === 'r') {
      approved.push({ path: denial.path, accessLevel: 'readonly' });
    } else {
      userDeniedPaths.add(denial.path);
    }
    console.log();
  }

  if (approved.length === 0) {
    console.log('\n  No resources approved. Exiting.');
    process.exit(1);
  }

  // === STEP 4: Regenerate + re-run ===
  banner('Policy Regeneration & Re-run');

  const result = generateUpdatedPolicyFromDetection(initialPolicy, detection, approved, {
    useParentDirectories: true,
  });

  console.log('  [4/5] Policy updated:');
  console.log(`        • ${result.addedCount} path(s) added to filesystem policy`);
  if (result.policy.network?.allowedHosts?.length) {
    console.log(`        • Network hosts allowed: ${result.policy.network.allowedHosts.join(', ')}`);
  }
  if (result.rejected.length > 0) {
    console.log(`        • ${result.rejected.length} path(s) cannot be granted (see below)`);
  }
  console.log();

  console.log('  [5/5] Re-running sandbox with updated policy...');
  console.log();

  const secondRun = await runSandbox(result.policy);
  const secondResults = extractResultLines(secondRun.stdout);

  // === FINAL REPORT ===
  banner('Results');

  // Show each resource with clear before → after status
  const secondDetection = await getDeniedResources({
    containerName: 'all-resources-test',
    output: secondRun.stdout + secondRun.stderr,
  });

  const secondDenialPaths = new Set(secondDetection.deniedResources.map(d => d.path));

  // Categorize
  const resolved: DeniedResourceInfo[] = [];
  const notResolvable: DeniedResourceInfo[] = [];
  const userBlocked: DeniedResourceInfo[] = [];

  for (const denial of detection.deniedResources) {
    if (userDeniedPaths.has(denial.path)) {
      userBlocked.push(denial);
    } else if (!secondDenialPaths.has(denial.path)) {
      resolved.push(denial);
    } else {
      notResolvable.push(denial);
    }
  }

  // Print each category
  if (resolved.length > 0) {
    console.log(`  ✅ FIXED (${resolved.length}) — these now work after policy update:`);
    for (const d of resolved) {
      console.log(`     • [${d.resourceType}] ${d.path}`);
    }
    console.log();
  }

  if (userBlocked.length > 0) {
    console.log(`  ⛔ BLOCKED BY YOU (${userBlocked.length}) — you chose to deny these:`);
    for (const d of userBlocked) {
      console.log(`     • [${d.resourceType}] ${d.path}`);
    }
    console.log();
  }

  if (notResolvable.length > 0) {
    console.log(`  ⚠️  NOT SUPPORTED YET (${notResolvable.length}) — detected but cannot be granted via policy:`);
    for (const d of notResolvable) {
      let reason: string;
      switch (d.resourceType) {
        case 'network': reason = 'HTTPS requires cert store access'; break;
        default:
          reason = d.path.toLowerCase().includes('\\windows\\')
            ? 'system-critical path'
            : 'sandbox limitation';
      }
      console.log(`     • [${d.resourceType}] ${d.path}`);
      console.log(`       └─ ${reason}`);
    }
    console.log();
  }

  // Final scoreboard
  const total = detection.deniedResources.length;
  console.log('  ┌─────────────────────────────────────┐');
  console.log(`  │  Total denied:      ${String(total).padStart(2)}              │`);
  console.log(`  │  ✅ Fixed:           ${String(resolved.length).padStart(2)}              │`);
  console.log(`  │  ⛔ User blocked:    ${String(userBlocked.length).padStart(2)}              │`);
  console.log(`  │  ⚠️  Not supported:   ${String(notResolvable.length).padStart(2)}              │`);
  console.log('  └─────────────────────────────────────┘');
  console.log();

  if (secondRun.exitCode === 0) {
    console.log('  🎉 Sandbox ran successfully after policy update!');
  } else if (resolved.length > 0) {
    console.log(`  ✓ Partial success — fixed ${resolved.length} of ${total} denial(s).`);
    if (notResolvable.length > 0) {
      console.log('    Remaining items need features not yet in the MXC policy schema.');
    }
  } else {
    console.log('  ✗ No denials could be resolved via policy.');
  }
  console.log();
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
