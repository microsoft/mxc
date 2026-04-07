// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { spawn } from 'child_process';
import * as fs from 'fs';

export interface ContainerExecutionOptions {
  isBase64?: boolean;
  debug?: boolean;
  experimental?: boolean;
}

export interface ContainerExecutionResult {
  success: boolean;
  exitCode: number;
  stdout: string;
  stderr: string;
}

export class ContainerExecutor {
  private executablePath: string;

  constructor(executablePath: string) {
    if (!fs.existsSync(executablePath)) {
      throw new Error(`Container executable not found at: ${executablePath}`);
    }
    this.executablePath = executablePath;
  }

  async run(config: string, options: ContainerExecutionOptions = {}): Promise<ContainerExecutionResult> {
    return new Promise((resolve, reject) => {
      const args: string[] = [];

      if (options.isBase64) {
        args.push('--config-base64', config);
      } else {
        args.push(config);
      }

      if (options.debug) {
        args.push('--debug');
      }

      if (options.experimental) {
        args.push('--experimental');
      }

      const child = spawn(this.executablePath, args);

      let stdout = '';
      let stderr = '';

      child.stdout.on('data', (data: Buffer) => {
        const text = data.toString();
        stdout += text;
        if (options.debug) {
          process.stdout.write(text);
        }
      });

      child.stderr.on('data', (data: Buffer) => {
        const text = data.toString();
        stderr += text;
        if (options.debug) {
          process.stderr.write(text);
        }
      });

      child.on('error', (error: Error) => {
        reject(new Error(`Failed to spawn container process: ${error.message}`));
      });

      child.on('close', (code: number | null) => {
        const exitCode = code ?? 1;
        resolve({
          success: exitCode === 0,
          exitCode,
          stdout: stdout.trim(),
          stderr: stderr.trim()
        });
      });
    });
  }

  getExecutablePath(): string {
    return this.executablePath;
  }
}
