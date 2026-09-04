// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const libraryName = process.platform === 'win32'
  ? 'mxc_uniffi.dll'
  : process.platform === 'darwin'
    ? 'libmxc_uniffi.dylib'
    : 'libmxc_uniffi.so';
const source = join(root, '..', '..', '..', 'src', 'target', 'debug', libraryName);
const destination = join(root, 'dist', libraryName);

mkdirSync(dirname(destination), { recursive: true });
copyFileSync(source, destination);
