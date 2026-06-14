// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Denied Resource Approval — End-to-End Demo
 *
 * Demonstrates the full denied-resource workflow:
 *   1. Spawn a sandboxed process with a restrictive policy
 *   2. Observe that the process fails due to access denials
 *   3. Parse the process output to identify denied paths
 *   4. Prompt the user to approve/reject each path
 *   5. Regenerate the policy with approved paths
 *   6. Re-run the process successfully with the updated policy
 *
 * Usage:
 *   npm run build && npm start
 */

import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import * as readline from 'readline';
import { fileURLToPath } from 'url';

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
const TEST_SCRIPT = path.join(EXAMPLE_ROOT, 'test_script.py');

// The directory we want the script to write into. On first run it is NOT
// in the policy so access will be denied. We use a path OUTSIDE the temp
// directory (since temp is in the readwrite policy for Python to function).
const TARGET_DIR = path.join(os.homedir(), 'mxc_approval_demo');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function banner(msg: string): void {
  const line = '─'.repeat(60);
  console.log(`\n${line}`);
  console.log(`  ${msg}`);
  console.log(`${line}\n`);
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

function printPolicy(policy: SandboxPolicy): void {
  console.log(JSON.stringify(policy, null, 2));
}

// ---------------------------------------------------------------------------
// Step 1: Build restrictive initial policy
// ---------------------------------------------------------------------------

function buildInitialPolicy(): SandboxPolicy {
  // Discover tool paths so Python can actually launch (DLLs, interpreter, etc.)
  const toolsPolicy = getAvailableToolsPolicy(process.env, { containerType: 'processcontainer' });
  const tempPolicy = getTemporaryFilesPolicy();

  // BFS readonly (`--policybrokerreadonly`) does NOT grant execute permission for DLLs.
  // Tool directories (Python, Node, etc.) need readwrite access via BFS so the OS loader
  // can execute binaries and load DLLs from them. We move all tool paths to readwritePaths.
  const toolReadwritePaths = [
    ...toolsPolicy.readwritePaths,
    ...toolsPolicy.readonlyPaths.filter(p => {
      const normalized = path.resolve(p).toLowerCase();
      // Skip drive roots — BFS inherits and this would be too broad
      return normalized.length > 3;
    }),
    ...tempPolicy.readwritePaths,
  ];

  return {
    version: '0.4.0-alpha',
    filesystem: {
      // The test script directory only needs read access
      readonlyPaths: [
        path.dirname(TEST_SCRIPT),
      ],
      // Tool dirs need readwrite (BFS execute requires it) + temp
      // Intentionally does NOT include TARGET_DIR — the script will fail trying to write there
      readwritePaths: toolReadwritePaths,
    },
    // No network needed
    network: { allowOutbound: false },
  };
}

// ---------------------------------------------------------------------------
// Step 2: Run the sandbox and capture output
// ---------------------------------------------------------------------------

async function runSandbox(
  policy: SandboxPolicy,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const command = `python "${TEST_SCRIPT}"`;

  console.log(`  Command : ${command}`);
  console.log(`  Target  : ${TARGET_DIR}`);
  console.log(`  Policy readwritePaths: ${JSON.stringify(policy.filesystem?.readwritePaths?.slice(0, 3))}... (${policy.filesystem?.readwritePaths?.length ?? 0} total)`);
  console.log(`  Policy readonlyPaths : ${policy.filesystem?.readonlyPaths?.length ?? 0} entries`);
  console.log();

  // Set env var so wxc-exec inherits it → child process sees MXC_TEST_TARGET_DIR
  process.env['MXC_TEST_TARGET_DIR'] = TARGET_DIR;

  // Build config with AppContainer backend + PTY (AppContainer needs console sharing)
  const config = createConfigFromPolicy(policy, undefined, 'denied-resource-demo');
  config.containment = 'processcontainer';
  config.process!.commandLine = command;

  return new Promise((resolve, reject) => {
    try {
      // PTY mode — AppContainer child shares the ConPTY console
      const ptyProcess = spawnSandboxFromConfig(config);
      let output = '';

      ptyProcess.onData((data: string) => { output += data; });

      ptyProcess.onExit((event: { exitCode: number; signal?: number }) => {
        resolve({ stdout: output, stderr: '', exitCode: event.exitCode });
      });
    } catch (error) {
      reject(error);
    }
  });
}

// ---------------------------------------------------------------------------
// Step 3: Detect denied resources using tiered detection
// ---------------------------------------------------------------------------

async function detectDenials(output: string, containerName: string): Promise<DetectionResult> {
  const detection = await getDeniedResources({
    containerName: containerName,
    output: output,
  });

  console.log(`  Service available: ${detection.serviceAvailable}`);
  console.log(`  Sources used: ${detection.sourcesUsed.join(', ')}`);
  console.log(`  Detected ${detection.deniedResources.length} denied resource(s):`);
  for (const denial of detection.deniedResources) {
    console.log(`    • [${denial.resourceType}] ${denial.path} (${denial.accessType}) [${denial.source}]`);
  }

  return detection;
}

// ---------------------------------------------------------------------------
// Step 4: Prompt user for approval
// ---------------------------------------------------------------------------

async function promptForApproval(denials: DeniedResourceInfo[]): Promise<ApprovedPath[]> {
  const approved: ApprovedPath[] = [];

  for (const denial of denials) {
    if (denial.resourceType === 'network') {
      const hostMatch = denial.path.match(/^([^:]+)/);
      const host = hostMatch ? hostMatch[1] : denial.path;
      console.log(`    ⚠️  Denied: ${denial.path} (network)`);
      console.log(`        → Will add to network.allowedHosts`);
      const answer = await ask(
        `  Allow network access to "${host}"? [y=allow / n=deny]: `,
      );
      if (answer.toLowerCase() === 'y') {
        approved.push({ path: denial.path, accessLevel: 'readwrite' });
      } else {
        console.log(`    ⛔ Denied: ${denial.path}`);
      }
    } else {
      const answer = await ask(
        `  Grant access to "${denial.path}"? [y=readwrite / r=readonly / n=deny]: `,
      );

      if (answer.toLowerCase() === 'y') {
        approved.push({ path: denial.path, accessLevel: 'readwrite' });
      } else if (answer.toLowerCase() === 'r') {
        approved.push({ path: denial.path, accessLevel: 'readonly' });
      } else {
        console.log(`    ⛔ Denied: ${denial.path}`);
      }
    }
  }

  return approved;
}

// ---------------------------------------------------------------------------
// Step 5: Regenerate policy
// ---------------------------------------------------------------------------

function regeneratePolicy(original: SandboxPolicy, detection: DetectionResult, approved: ApprovedPath[]): SandboxPolicy {
  const result = generateUpdatedPolicyFromDetection(original, detection, approved, {
    useParentDirectories: true,
  });

  if (result.rejected.length > 0) {
    console.log('  ⚠ Some paths were rejected:');
    for (const r of result.rejected) {
      console.log(`    • ${r.path}: ${r.reason}`);
    }
  }

  console.log(`  Added ${result.addedCount} path(s) to the policy.`);
  return result.policy;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  banner('Step 1: Build initial restrictive policy');
  const initialPolicy = buildInitialPolicy();

  // Ensure target directory exists (outside sandbox) so Python gets PermissionError
  // on write, not FileNotFoundError on mkdir.
  fs.mkdirSync(TARGET_DIR, { recursive: true });

  banner('Step 2: Run sandbox with restrictive policy (expect failure)');
  const firstRun = await runSandbox(initialPolicy);
  console.log(`  Exit code: ${firstRun.exitCode}`);
  console.log(`  Output:\n${firstRun.stdout}`);

  if (firstRun.exitCode === 0) {
    console.log('  ✓ Process succeeded on first attempt — no denials to handle.');
    process.exit(0);
  }

  banner('Step 3: Detect denied resources (tiered detection)');
  const detection = await detectDenials(firstRun.stdout + firstRun.stderr, 'denied-resource-demo');

  if (detection.deniedResources.length === 0) {
    console.log('  Process failed but no access denials detected. Exiting.');
    process.exit(1);
  }

  banner('Step 4: Prompt user for approval');
  const approved = await promptForApproval(detection.deniedResources);

  if (approved.length === 0) {
    console.log('  No paths approved. Cannot proceed.');
    process.exit(1);
  }

  banner('Step 5: Regenerate policy with approved paths');
  const updatedPolicy = regeneratePolicy(initialPolicy, detection, approved);
  console.log('  Updated policy:');
  printPolicy(updatedPolicy);

  banner('Step 6: Re-run sandbox with updated policy (expect success)');
  const secondRun = await runSandbox(updatedPolicy);
  console.log(`  Exit code: ${secondRun.exitCode}`);
  console.log(`  Output:\n${secondRun.stdout}`);

  if (secondRun.exitCode === 0) {
    banner('✓ Success! The sandbox ran successfully after policy update.');
  } else {
    banner('✗ Second run still failed. Additional policy changes may be needed.');
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
