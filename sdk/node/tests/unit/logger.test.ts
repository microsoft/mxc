// sdk/tests/unit/logger.test.ts
import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { FileLogger } from '../../src/logger.js';

describe('FileLogger', () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-log-test-'));
    logPath = path.join(tmpDir, 'test.log');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should create log file and write entries with timestamp', () => {
    const logger = new FileLogger(logPath);
    logger.log('info', 'test message', { key: 'value' });
    logger.close();
    const content = fs.readFileSync(logPath, 'utf-8');
    assert.ok(content.includes('INFO'));
    assert.ok(content.includes('test message'));
    assert.ok(content.includes('"key":"value"'));
    assert.ok(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(content));
  });

  it('should emit console.warn on invalid path and degrade to no-op', () => {
    let warned = false;
    const origWarn = console.warn;
    console.warn = () => { warned = true; };
    try {
      const logger = new FileLogger(path.join(tmpDir, '\0invalid'));
      logger.log('info', 'this should not throw');
      logger.close();
      assert.ok(warned, 'console.warn should have been called');
    } finally {
      console.warn = origWarn;
    }
  });
});
