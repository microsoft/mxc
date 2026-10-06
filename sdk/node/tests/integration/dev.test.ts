// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import { it } from 'node:test';
import { runJson, validateProcessJson } from '@microsoft/mxc-sdk/v1/dev';
import { MxcError } from '@microsoft/mxc-sdk/v1';

it('V1.Dev rejects unknown fields and unregistered exact versions through native', async () => {
  const unregistered =
    '{"version":"999.0.0","process":{"commandLine":"echo must-not-run"}}';
  await assert.rejects(
    runJson(unregistered),
    (error: unknown) => error instanceof MxcError && error.code === 'malformed_request',
  );

  const unknownField =
    '{"version":"1.0.0","phase":"exec","sandboxId":"iso:unused","process":{"commandLine":"echo must-not-run"},"extra":true}';
  await assert.rejects(
    validateProcessJson(unknownField),
    (error: unknown) => error instanceof MxcError && error.code === 'malformed_request',
  );
});
