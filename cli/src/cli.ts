// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.


import { Command } from 'commander';
import {
  spawnSandbox,
  spawnSandboxWithoutPty,
  getPlatformSupport,
  SandboxPolicy,
  ContainmentType,
  getAvailableToolsPolicy,
} from '@microsoft/mxc-sdk';

import * as fs from 'fs';
import * as path from 'path';
import { ContainerConfig } from '@microsoft/mxc-sdk/dist/types';

const program = new Command();

program
  .name('wxc-cli')
  .description('CLI test driver for the MXC SDK and container backends')
  .version('0.1.0');

program
  .command('validate')
  .description('Validate a configuration file')
  .argument('<config>', 'Path to JSON configuration file')
  .action(async (configPath: string) => {
    try {
      if (!fs.existsSync(configPath)) {
        console.error(`Configuration file not found: ${configPath}`);
        process.exit(1);
      }

      const content = fs.readFileSync(configPath, 'utf-8');
      const policy: ContainerConfig = JSON.parse(content);

      // Basic validation
      if (!policy.process?.commandLine) {
        console.error('Invalid configuration: missing process.commandLine');
        process.exit(1);
      }

      const scriptLength = policy.process.commandLine.length;
      console.log('Configuration is valid');
      console.log('Script code length:', scriptLength, 'characters');

      if (policy.appContainer) {
        console.log('AppContainer:', policy.appContainer.name || 'WXC');
      }

      process.exit(0);
    } catch (error) {
      console.error('Validation error:', error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

program
  .command('encode')
  .description('Encode a configuration file to base64')
  .argument('<config>', 'Path to JSON configuration file')
  .action(async (configPath: string) => {
    try {
      if (!fs.existsSync(configPath)) {
        console.error(`Configuration file not found: ${configPath}`);
        process.exit(1);
      }

      const content = fs.readFileSync(configPath, 'utf-8');
      const base64 = Buffer.from(content).toString('base64');

      console.log(base64);
      process.exit(0);
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

program
  .command('run-sdk')
  .description('Run a workload in a sandbox using the MXC SDK')
  .option('--script <command>', 'Command line to execute')
  .option('--script-file <path>', 'Path to a script file (contents are read and passed as the command)')
  // Policy JSON should match the SandboxPolicy type defined in sdk/src/types.ts
  .option('--policy <json>', 'SandboxPolicy as a JSON string')
  .option('--policy-file <path>', 'Path to a SandboxPolicy JSON file')
  .option('--cwd <path>', 'Working directory for the sandboxed process')
  .option('--container-name <name>', 'Name for the sandbox container')
  .option('--containment <backend>', 'Override containment backend')
  .option('--no-pty', 'Use child_process.spawn instead of node-pty (reliable exit codes)')
  .option('--debug', 'Enable debug output')
  .option('--experimental', 'Enable experimental features')
  .action(async (options: { script?: string; scriptFile?: string; policy?: string; policyFile?: string; cwd?: string; containerName?: string; containment?: string; pty?: boolean; debug?: boolean; experimental?: boolean }) => {
    try {
      let scriptCommand: string;
      if (options.script) {
        scriptCommand = options.script;
      } else if (options.scriptFile) {
        if (!fs.existsSync(options.scriptFile)) {
          console.error(`Script file not found: ${options.scriptFile}`);
          process.exit(1);
        }
        scriptCommand = fs.readFileSync(path.resolve(options.scriptFile), 'utf-8').trim();
      } else {
        console.error('Error: Provide --script <command> or --script-file <path>');
        process.exit(1);
      }

      let policy: SandboxPolicy;
      if (options.policy) {
        policy = JSON.parse(options.policy);
      } else if (options.policyFile) {
        if (!fs.existsSync(options.policyFile)) {
          console.error(`Policy file not found: ${options.policyFile}`);
          process.exit(1);
        }
        policy = JSON.parse(fs.readFileSync(options.policyFile, 'utf-8'));
      } else {
        console.error('Error: Provide --policy <json> or --policy-file <path>');
        process.exit(1);
      }

      // Discover tool paths from the current environment and merge them
      const toolsPolicy = getAvailableToolsPolicy(process.env);
      if (toolsPolicy.readonlyPaths.length > 0) {
        if (!policy.filesystem) {
          policy.filesystem = {};
        }
        policy.filesystem.readonlyPaths = [
          ...(policy.filesystem.readonlyPaths ?? []),
          ...toolsPolicy.readonlyPaths,
        ];
      }
      if (toolsPolicy.readwritePaths.length > 0) {
        if (!policy.filesystem) {
          policy.filesystem = {};
        }
        policy.filesystem.readwritePaths = [
          ...(policy.filesystem.readwritePaths ?? []),
          ...toolsPolicy.readwritePaths,
        ];
      }

      const containment = options.containment as ContainmentType | undefined;

      const spawnOptions = {
        debug: options.debug ?? false,
        experimental: options.experimental ?? false,
      };

      if (options.pty === false) {
        // Non-PTY mode using spawnSandboxWithoutPty() (child_process.spawn).
        // This provides reliable exit code propagation and separate stdout/stderr
        // streams. Use this for CI, automation, or any scenario where correct exit
        // codes matter. The default PTY mode (node-pty/ConPTY) returns exit code -1
        // for all processes on Windows due to a known ConPTY limitation.
        const child = spawnSandboxWithoutPty(scriptCommand, policy, spawnOptions, options.cwd, options.containerName, undefined, containment);

        child.stdout?.on('data', (data: Buffer) => {
          process.stdout.write(data);
        });
        child.stderr?.on('data', (data: Buffer) => {
          process.stderr.write(data);
        });
        child.on('close', (code: number | null) => {
          process.exit(code ?? 1);
        });
        child.on('error', (err: Error) => {
          console.error('Error:', err.message);
          process.exit(1);
        });
      } else {
        // PTY mode: interactive terminal with colors/input
        console.log('Spawning sandboxed process using SDK...');
        const ptyProcess = spawnSandbox(scriptCommand, policy, spawnOptions, options.cwd, options.containerName, undefined, containment);

        ptyProcess.onData((data: string) => {
          process.stdout.write(data);
        });

        ptyProcess.onExit((event: { exitCode: number; signal?: number }) => {
          console.log(`\nProcess exited with code ${event.exitCode}`);
          process.exit(event.exitCode);
        });
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

program
  .command('platform')
  .description('Show platform support information for WXC')
  .action(() => {
    try {
      const support = getPlatformSupport();

      console.log('MXC Platform Support Information');
      console.log('='.repeat(50));
      console.log(`Supported: ${support.isSupported ? 'Yes' : 'No'}`);

      if (support.reason) {
        console.log(`Reason: ${support.reason}`);
      }

      console.log(`Available Sandboxing Methods: ${support.availableMethods.join(', ') || 'None'}`);
      process.exit(0);
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });
program.parse();
