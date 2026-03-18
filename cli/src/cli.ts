#!/usr/bin/env node

import { Command } from 'commander';
import { WxcExecutor } from './wxc-executor';
import {
  spawnSandbox,
  getPlatformSupport,
  SandboxPolicy,
  getAvailableToolsPolicy
} from '@microsoft/mxc-sdk';

import * as fs from 'fs';
import * as path from 'path';
import { WxcConfiguration } from '@microsoft/mxc-sdk/dist/types';

const program = new Command();

program
  .name('wxc-cli')
  .description('CLI for invoking the WXC (Windows eXecution Container)')
  .version('0.1.0');

program
  .command('run')
  .description('Run Python code with WXC sandbox')
  .argument('<config>', 'Path to JSON configuration file or base64-encoded config')
  .option('--config-base64', 'Treat config argument as base64-encoded JSON')
  .option('--debug', 'Enable debug output')
  .option('--wxc-path <path>', 'Path to wxc-exec.exe executable', path.join(__dirname, '..', '..', 'src', 'target', 'debug', 'wxc-exec.exe'))
  .action(async (config: string, options: { base64?: boolean; debug?: boolean; wxcPath: string }) => {
    try {
      const executor = new WxcExecutor(options.wxcPath);
      const result = await executor.run(config, {
        isBase64: options.base64 ?? false,
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
      const policy: WxcConfiguration = JSON.parse(content);

      // Basic validation
      if (!policy.script) {
        console.error('Invalid configuration: missing script.code');
        process.exit(1);
      }

      console.log('Configuration is valid');
      console.log('Script code length:', policy.script.length, 'characters');

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

// SDK-based commands
program
  .command('run-sdk')
  .description('Run code with WXC sandbox using SDK (interactive mode with node-pty)')
  .argument('<config>', 'Path to JSON configuration file')
  .option('--debug', 'Enable debug output')
  .action(async (configPath: string, options: { debug?: boolean; wxcPath?: string }) => {
    try {
      // Check platform support
      const platformInfo = getPlatformSupport();
      if (!platformInfo.isSupported) {
        console.error(`Error: MXC is not supported on this platform: ${platformInfo.reason}`);
        process.exit(1);
      }

      // Read configuration
      if (!fs.existsSync(configPath)) {
        console.error(`Configuration file not found: ${configPath}`);
        process.exit(1);
      }

      // NOTE: This is a lossy conversion since WxcConfiguration is not exactly
      //  the same as SandboxPolicy, but for demo purposes we will just extract
      //  the relevant parts.
      const content = fs.readFileSync(configPath, 'utf-8');
      const config: WxcConfiguration = JSON.parse(content);
      const policy: SandboxPolicy = {
        filesystem: config.filesystem ? {
            readwritePaths: config.filesystem?.readwritePaths,
            readonlyPaths: config.filesystem?.readonlyPaths,
            deniedPaths: config.filesystem?.deniedPaths,
            clearPolicyOnExit: config.filesystem?.clearPolicyOnExit ?? true,
        } : undefined,
      };

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

      // Spawn the process
      // NOTE: For now, we will force winpty.
      const pty = spawnSandbox(config.script, policy, {
        debug: options.debug ?? false
      }, config.workingDirectory, config.appContainer?.name);

      // Handle output
      pty.onData((data: string) => {
        process.stdout.write(data);
      });

      // Handle exit
      pty.onExit((event: { exitCode: number; signal?: number }) => {
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
