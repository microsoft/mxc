// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.


import { Command } from 'commander';
import { ContainerExecutor } from './wxc-executor';
import {
  spawnSandbox,
  getPlatformSupport,
  SandboxPolicy,
  SandboxingMethod,
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
  .command('run')
  .description('Run a container config JSON directly via wxc-exec (non-interactive, proper exit codes)')
  .argument('<config>', 'Path to JSON configuration file')
  .option('--wxc-path <path>', 'Path to wxc-exec.exe (auto-detected if not specified)')
  .option('--config-base64', 'Treat <config> as a base64-encoded config string')
  .option('--debug', 'Enable debug output')
  .option('--experimental', 'Enable experimental features')
  .action(async (configArg: string, options: { wxcPath?: string; configBase64?: boolean; debug?: boolean; experimental?: boolean }) => {
    try {
      const { findWxcExecutable } = await import('@microsoft/mxc-sdk/dist/platform');
      const execPath = options.wxcPath ?? findWxcExecutable();
      if (!execPath) {
        console.error('Error: wxc-exec.exe not found. Use --wxc-path to specify.');
        process.exit(1);
      }
      const executor = new ContainerExecutor(execPath);
      const result = await executor.run(configArg, {
        isBase64: options.configBase64 ?? false,
        debug: options.debug ?? false,
        experimental: options.experimental ?? false,
      });
      if (!options.debug && result.stdout) {
        console.log(result.stdout);
      }
      if (result.stderr) {
        console.error(result.stderr);
      }
      process.exit(result.exitCode);
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

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
  .description('Simulate SDK usage: build a sandbox payload from a SandboxPolicy and spawn it')
  .option('--script <command>', 'Command line to execute')
  .option('--script-file <path>', 'Path to a script file (contents are read and passed as the command)')
  // Policy JSON should match the SandboxPolicy type defined in sdk/src/types.ts
  .option('--policy <json>', 'SandboxPolicy as a JSON string')
  .option('--policy-file <path>', 'Path to a SandboxPolicy JSON file')
  .option('--cwd <path>', 'Working directory for the sandboxed process')
  .option('--container-name <name>', 'Name for the sandbox container')
  .option('--containment <backend>', 'Override containment backend (appcontainer, sandbox, microvm, nanvix, lxc, wslc, vm)')
  .option('--debug', 'Enable debug output')
  .option('--experimental', 'Enable experimental features')
  .action(async (options: { script?: string; scriptFile?: string; policy?: string; policyFile?: string; cwd?: string; containerName?: string; containment?: string; debug?: boolean; experimental?: boolean }) => {
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

      console.log('Spawning sandboxed process using SDK...');

      const ptyProcess = spawnSandbox(scriptCommand, policy, {
        debug: options.debug ?? false,
        experimental: options.experimental ?? false,
        containment: options.containment as SandboxingMethod | undefined,
      }, options.cwd, options.containerName);

      ptyProcess.onData((data: string) => {
        process.stdout.write(data);
      });

      ptyProcess.onExit((event: { exitCode: number; signal?: number }) => {
        console.log(`\nProcess exited with code ${event.exitCode}`);
        process.exit(event.exitCode);
      });
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
