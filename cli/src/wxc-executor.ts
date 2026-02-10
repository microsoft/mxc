import { spawn } from 'child_process';
import * as fs from 'fs';

export interface WxcExecutionOptions {
  isBase64?: boolean;
  debug?: boolean;
}

export interface WxcExecutionResult {
  success: boolean;
  exitCode: number;
  stdout: string;
  stderr: string;
}

export class WxcExecutor {
  private wxcPath: string;

  constructor(wxcPath: string) {
    if (!fs.existsSync(wxcPath)) {
      throw new Error(`WXC executable not found at: ${wxcPath}`);
    }
    this.wxcPath = wxcPath;
  }

  async run(config: string, options: WxcExecutionOptions = {}): Promise<WxcExecutionResult> {
    return new Promise((resolve, reject) => {
      const args: string[] = [];

      // Add config argument (file path or base64 string)
      args.push(config);

      // Add base64 flag if needed
      if (options.isBase64) {
        args.push('--base64');
      }

      // Add debug flag if needed
      if (options.debug) {
        args.push('--debug');
      }

      const wxc = spawn(this.wxcPath, args);

      let stdout = '';
      let stderr = '';

      wxc.stdout.on('data', (data: Buffer) => {
        const text = data.toString();
        stdout += text;
        if (options.debug) {
          process.stdout.write(text);
        }
      });

      wxc.stderr.on('data', (data: Buffer) => {
        const text = data.toString();
        stderr += text;
        if (options.debug) {
          process.stderr.write(text);
        }
      });

      wxc.on('error', (error: Error) => {
        reject(new Error(`Failed to spawn WXC process: ${error.message}`));
      });

      wxc.on('close', (code: number | null) => {
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

  getWxcPath(): string {
    return this.wxcPath;
  }
}
