# NVX npm examples

> [!NOTE]
> These examples describe the proposed completed NVX-backed MicroVM SDK
> surface. The MicroVM types are not available in the current npm package.

For architecture, packaging, policy limits, and implementation details, see
[NVX integration in MXC](./nvx-integration.md).

For .NET examples, see
[NVX .NET examples](./nvx-dotnet-examples.md).

## Install the packages

Install matching SDK and runtime package versions:

```bash
npm install @microsoft/mxc-sdk @microsoft/mxc-nvx-runtime
```

## Check MicroVM availability

```typescript
import { getPlatformSupport } from '@microsoft/mxc-sdk/v1';

const support = getPlatformSupport();
if (!support.availableMethods.includes('microvm')) {
  throw new Error(
    support.unavailableReasons?.microvm ?? 'MicroVM is unavailable',
  );
}
```

## Run and capture output

```typescript
import { runAsync } from '@microsoft/mxc-sdk/v1';

const result = await runAsync({
  command: 'python -c "print(\'hello from NVX\')"',
  timeoutMs: 30_000,
  containment: {
    type: 'microvm',
    config: {
      image: 'python:3.12-alpine',
      memoryMb: 256,
    },
  },
});

process.stdout.write(result.stdout);
process.stderr.write(result.stderr);
console.log(`exit=${result.exitCode} timedOut=${result.timedOut}`);
```

Prefer `runAsync`. The synchronous `run` operation blocks the Node event loop
until execution completes.

## Spawn with live output

```typescript
import { spawnAsync } from '@microsoft/mxc-sdk/v1';

const processHandle = await spawnAsync({
  command:
    'python -u -c "import sys,time; print(\'out\'); '
    + 'print(\'err\', file=sys.stderr); time.sleep(1)"',
  timeoutMs: 30_000,
  containment: {
    type: 'microvm',
    config: {
      image: 'python:3.12-alpine',
      memoryMb: 256,
    },
  },
});

try {
  processHandle.standardOutput?.on(
    'data',
    (chunk) => process.stdout.write(chunk),
  );
  processHandle.standardError?.on(
    'data',
    (chunk) => process.stderr.write(chunk),
  );

  const result = await processHandle.waitAsync();
  console.log(result);
} catch (error) {
  processHandle.kill();
  throw error;
} finally {
  processHandle.dispose();
}
```

Consume stdout and stderr concurrently. Call `kill()` when the application
must stop the workload.

## Reuse an NVX instance

The state-aware lifecycle is:

```text
provision → start → repeated execution → stop → deprovision
```

```typescript
import {
  deprovisionContainer,
  provisionContainer,
  runInContainerAsync,
  startContainer,
  stopContainer,
} from '@microsoft/mxc-sdk/v1';

const { containerId } = await provisionContainer({
  containment: 'microvm',
  image: 'python:3.12-alpine',
  memoryMb: 256,
});

let startAttempted = false;
let primaryError: unknown;
const cleanupErrors: unknown[] = [];

try {
  startAttempted = true;
  await startContainer(containerId);

  for (const value of ['first', 'second']) {
    const result = await runInContainerAsync(containerId, {
      command: `echo ${value}`,
    });
    console.log(result.stdout);
  }
} catch (error) {
  primaryError = error;
} finally {
  if (startAttempted) {
    try {
      await stopContainer(containerId);
    } catch (error) {
      cleanupErrors.push(error);
    }
  }

  try {
    await deprovisionContainer(containerId);
  } catch (error) {
    cleanupErrors.push(error);
  }
}

if (primaryError !== undefined || cleanupErrors.length !== 0) {
  const errors = [...cleanupErrors];
  if (primaryError !== undefined) {
    errors.unshift(primaryError);
  }
  throw new AggregateError(errors, `NVX lifecycle failed for ${containerId}`);
}
```

Keep `containerId` unchanged. If cleanup fails, keep the ID in application
logs so an operator can retry cleanup.

## Filesystem and network policy

```json
{
  "filesystem": {
    "readonlyPaths": ["C:\\nvx-work\\input"],
    "readwritePaths": ["C:\\nvx-work\\output"],
    "deniedPaths": ["C:\\nvx-work\\input\\private"]
  },
  "network": {
    "egress": {
      "default": "deny",
      "allow": [{
        "to": [{ "cidr": "203.0.113.0/24" }],
        "ports": [{ "protocol": "tcp", "port": 443 }]
      }]
    },
    "ingress": {
      "default": "deny",
      "hostLoopback": "deny"
    }
  }
}
```

Add `filesystem` and `network` to the one-shot request or the provision
request. Host paths must exist before launch.

Inside the Linux workload:

```text
C:\nvx-work\input  → /mnt/c/nvx-work/input
C:\nvx-work\output → /mnt/c/nvx-work/output
```

Use Linux guest paths in commands and `workingDirectory`. Read-write mappings
modify host files immediately.

## PTY and live stdin

PTY support is not available initially. `spawnWithPty` and
`spawnInContainerWithPty` reject MicroVM requests.

Use `spawn` or `spawnInContainer` for non-interactive workloads. These
operations provide stdout and stderr pipes. They do not provide a terminal.
Live stdin is not available initially, and the workload receives EOF.

## Errors

| Result | Meaning |
| --- | --- |
| `backend_unavailable` | The NVX runtime, WHP, runtime files, architecture, or runtime version is unavailable |
| Policy validation error | The request uses a policy form or value that NVX cannot enforce |
| Nonzero workload exit | The workload ran and returned a nonzero status |

