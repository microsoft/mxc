// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.


import { Command } from 'commander';
import { ContainerExecutor } from './wxc-executor';
import {
  spawnSandbox,
  getPlatformSupport,
  SandboxPolicy,
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
  .description('Run a config for a specific container backend')
  .argument('<config>', 'Path to ContainerConfig JSON file or base64-encoded config')
  .option('--config-base64', 'Treat config argument as base64-encoded JSON')
  .option('--debug', 'Enable debug output')
  .action(async (config: string, options: { configBase64?: boolean; debug?: boolean }) => {
    try {
      const platform = require('os').platform();
      let execPath: string | null;
      if (platform === 'linux') {
        const { findLxcExecutable } = require('@microsoft/mxc-sdk');
        execPath = findLxcExecutable();
      } else {
        const { findWxcExecutable } = require('@microsoft/mxc-sdk');
        execPath = findWxcExecutable();
      }
      if (!execPath) {
        console.error('Error: Executable not found. Ensure wxc-exec or lxc-exec is built.');
        process.exit(1);
      }
      const executor = new ContainerExecutor(execPath);
      const result = await executor.run(config, {
        isBase64: options.configBase64 ?? false,
        debug: options.debug ?? false
      });

      if (result.success) {
        console.log('Execution successful');
        if (result.stdout) {
          console.log('Output:', result.stdout);
        }
        process.exit(result.exitCode);
      } else {
        console.error('Execution failed');
        if (result.stderr) {
          console.error('Error:', result.stderr);
        }
        process.exit(result.exitCode);
      }
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
  .option('--debug', 'Enable debug output')
  .action(async (options: { script?: string; scriptFile?: string; policy?: string; policyFile?: string; debug?: boolean }) => {
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

      console.log('Spawning sandboxed process using SDK...');

      const ptyProcess = spawnSandbox(scriptCommand, policy, {
        debug: options.debug ?? false,
      });

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
