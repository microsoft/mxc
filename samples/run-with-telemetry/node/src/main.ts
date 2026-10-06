// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { execFile } from 'node:child_process';
import os from 'node:os';
import { createInterface } from 'node:readline';
import { promisify } from 'node:util';
import {
  MxcError,
  getPlatformSupport,
  getTelemetryConsentStatus,
  requestTelemetryConsent,
  run,
  type ContainerRequest,
  type TelemetryConsentDecision,
  type TelemetryConsentPrompt,
} from '@microsoft/mxc-sdk/v1';

const execFileAsync = promisify(execFile);
const sampleCommand = os.platform() === 'win32'
  ? 'cmd.exe /d /s /c "echo hello from telemetry"'
  : 'sh -c "printf \'hello from telemetry\\n\'"';

async function presentConsent(
  prompt: TelemetryConsentPrompt,
): Promise<TelemetryConsentDecision> {
  console.log(prompt.title.text);
  console.log();
  console.log(prompt.body.text);
  console.log();
  console.log(`${prompt.learnMoreLabel.text}: ${prompt.learnMoreUrl}`);

  const input = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  try {
    return await new Promise<TelemetryConsentDecision>((resolve, reject) => {
      let decided = false;
      const onInputError = (error: Error): void => {
        decided = true;
        reject(error);
      };
      const finish = (decision: TelemetryConsentDecision): void => {
        decided = true;
        process.stdin.off('error', onInputError);
        resolve(decision);
      };
      const ask = (): void => {
        input.question(
          `${prompt.affirmativeLabel.text} [y], `
          + `${prompt.negativeLabel.text} [n], `
          + `${prompt.learnMoreLabel.text} [l]: `,
          (response) => {
            switch (response.trim().toLowerCase()) {
              case 'y':
              case 'yes':
                finish('yes');
                break;
              case 'n':
              case 'no':
                finish('no');
                break;
              case 'l':
                void execFileAsync(
                  'rundll32.exe',
                  ['url.dll,FileProtocolHandler', prompt.learnMoreUrl],
                ).then(ask, reject);
                break;
              default:
                console.error('Enter y, n, or l.');
                ask();
                break;
            }
          },
        );
      };

      input.once('close', () => {
        if (!decided) {
          finish('dismissed');
        }
      });
      process.stdin.once('error', onInputError);
      ask();
    });
  } finally {
    input.close();
  }
}

async function main(): Promise<number> {
  const support = getPlatformSupport();
  if (!support.isSupported) {
    throw new Error(`MXC is not supported: ${support.reason ?? 'unknown reason'}`);
  }

  const status = await getTelemetryConsentStatus();
  if (status.error !== undefined) {
    console.error(`warning: ${status.error}`);
  }
  if (status.needsPrompt) {
    const outcome = await requestTelemetryConsent(presentConsent, 'en-US');
    console.error(`telemetry consent result: ${outcome.result}`);
  }

  const updatedStatus = await getTelemetryConsentStatus();
  if (updatedStatus.error !== undefined) {
    console.error(`warning: ${updatedStatus.error}`);
  }
  if (updatedStatus.effectiveState !== 'granted') {
    console.error(
      `telemetry is not authorized (${updatedStatus.effectiveState}) and will remain off`,
    );
  }

  const request: ContainerRequest = {
    command: sampleCommand,
    containment: { type: 'process' },
    timeoutMs: 30_000,
  };

  // This opts only this invocation into optional diagnostic telemetry. In a
  // Microsoft telemetry-routed build, authorized diagnostics may be sent to
  // Microsoft. Commands, output, credentials, and customer content are excluded.
  await run(request, {
    telemetry: { enabled: true },
  });
  return 0;
}

try {
  process.exitCode = await main();
} catch (error) {
  if (error instanceof MxcError) {
    console.error(`MXC error [${error.code}]: ${error.message}`);
  } else {
    console.error(error);
  }
  process.exitCode = 1;
}
