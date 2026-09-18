// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { runBindingRequestAttached } from './bindings/run.js';
import type { RequestSpec } from './bindings/request.js';

export function readPayload(argv: string[]): RequestSpec {
  const payloadFileIndex = argv.indexOf('--payload-file');
  const payloadFile = payloadFileIndex < 0 ? undefined : argv[payloadFileIndex + 1];
  if (!payloadFile) {
    throw new Error('Missing --payload-file');
  }

  const payloadJson = readFileSync(payloadFile, 'utf8');
  rmSync(path.dirname(payloadFile), { force: true, recursive: true });
  return JSON.parse(payloadJson) as RequestSpec;
}

function appendDiagnosticLine(value: string, line: string): string {
  return `${value}${value.endsWith('\n') || value.length === 0 ? '' : '\n'}${line}\n`;
}

export function attachedStderr(
  warnings: string[],
  outputMetadata: unknown,
): string {
  let stderr = '';
  for (const warning of warnings) {
    stderr = appendDiagnosticLine(stderr, warning);
  }
  if (
    outputMetadata !== null
    && typeof outputMetadata === 'object'
    && !Array.isArray(outputMetadata)
  ) {
    const captureDenials =
      (outputMetadata as Record<string, unknown>).captureDenials;
    if (captureDenials !== undefined) {
      stderr = appendDiagnosticLine(stderr, JSON.stringify(captureDenials));
    }
  }
  return stderr;
}

export function main(argv = process.argv.slice(2)): void {
  try {
    const result = runBindingRequestAttached(readPayload(argv));
    const diagnostics = attachedStderr(result.warnings, result.outputMetadata);
    if (diagnostics.length > 0) {
      process.stderr.write(diagnostics);
    }
    process.exitCode = result.exitCode;
  } catch (error) {
    const message =
      error instanceof Error && error.stack ? error.stack : String(error);
    process.stderr.write(`${message}\n`);
    process.exitCode = 127;
  }
}

function isMain(): boolean {
  const mainPath = process.argv[1];
  return mainPath !== undefined
    && import.meta.url === pathToFileURL(path.resolve(mainPath)).href;
}

if (isMain()) {
  main();
}
