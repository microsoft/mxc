// sdk/src/logger.ts
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as fs from 'fs';
import * as path from 'path';

/**
 * Appends timestamped log lines to a file.
 * Emits console.warn if the file cannot be opened, then degrades to no-op.
 */
export class FileLogger {
  private fd: number | null = null;

  constructor(filePath: string) {
    try {
      const dir = path.dirname(filePath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      this.fd = fs.openSync(filePath, 'a');
    } catch (err) {
      console.warn(`[mxc-sdk] Could not open log file '${filePath}': ${err}`);
      this.fd = null;
    }
  }

  log(level: 'info' | 'warn' | 'error', message: string, data?: Record<string, unknown>): void {
    if (this.fd === null) return;
    try {
      const ts = new Date().toISOString();
      const suffix = data ? ' ' + JSON.stringify(data) : '';
      const line = `[${ts}] ${level.toUpperCase()} ${message}${suffix}\n`;
      fs.writeSync(this.fd, line);
    } catch { /* never throw from logging */ }
  }

  close(): void {
    if (this.fd !== null) {
      try { fs.closeSync(this.fd); } catch { /* ignore */ }
      this.fd = null;
    }
  }
}
