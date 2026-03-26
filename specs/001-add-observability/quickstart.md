# Quickstart: Testing MXC Telemetry Locally

**Feature**: [../spec.md](../spec.md)  
**Audience**: Developers implementing or validating the telemetry feature.

---

## Prerequisites

- `wxc-exec.exe` built (`build.bat` from repo root)
- Docker (for running a local OTel collector)
- Node.js 20+ (for TypeScript validation)

---

## Step 1: Start a local OTel collector

Run the OpenTelemetry Collector in Docker, exporting spans to the console:

```bash
docker run --rm -p 4318:4318 \
  -v $(pwd)/otelcol-config.yaml:/etc/otelcol/config.yaml \
  otel/opentelemetry-collector-contrib:latest
```

Create `otelcol-config.yaml` in the repo root:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: "0.0.0.0:4318"

exporters:
  debug:
    verbosity: detailed

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [debug]
    metrics:
      receivers: [otlp]
      exporters: [debug]
```

---

## Step 2: Verify telemetry is OFF by default

Run without the opt-in signal:

```powershell
.\wxc-exec.exe examples\01_hello_world.json
```

The collector console MUST show **no** spans or metrics. Exit code of `wxc-exec` must be 0.

---

## Step 3: Enable telemetry via environment variable

```powershell
$env:MXC_ENABLE_TELEMETRY = "1"
$env:OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:4318"

.\wxc-exec.exe examples\01_hello_world.json
```

In the collector console you should see:

```
Span #0
    Trace ID    : <32-char hex>
    Parent ID   :
    ID          : <16-char hex>
    Name        : mxc.execute
    ...
    Attributes:
         -> mxc.backend: STRING(appcontainer)
         -> mxc.exit_code: INT(0)
         -> mxc.version: STRING(0.1.5)
```

And child spans: `mxc.container.init`, `mxc.policy.filesystem`, `mxc.policy.network`, `mxc.script.run`, `mxc.container.teardown`.

---

## Step 4: Enable telemetry via JSON config

Create `telemetry_test.json` based on `examples/01_hello_world.json`, adding:

```json
{
  "telemetry": { "enabled": true }
}
```

Run **without** the env var:

```powershell
Remove-Item Env:MXC_ENABLE_TELEMETRY -ErrorAction SilentlyContinue

$env:OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:4318"
.\wxc-exec.exe telemetry_test.json
```

Same spans should appear in the collector.

---

## Step 5: Verify no PII in spans

Grep the collector output for any of the following — none should appear:

```powershell
# Prohibited content: script source, file paths, usernames, machine names
# Check collector output for:
#   - The script content
#   - Any path containing backslash or forward slash
#   - COMPUTERNAME / USERNAME values
```

---

## Step 6: Verify TypeScript layer

```typescript
// test-telemetry.ts (run with ts-node)
import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { WxcExecutor } from '@microsoft/mxc-sdk';

const sdk = new NodeSDK({
  traceExporter: new OTLPTraceExporter({ url: 'http://localhost:4318/v1/traces' }),
});
sdk.start();

process.env.MXC_ENABLE_TELEMETRY = '1';
process.env.OTEL_EXPORTER_OTLP_ENDPOINT = 'http://localhost:4318';

const executor = new WxcExecutor('./wxc-exec.exe');
const result = await executor.run({ script: 'python -c "print(42)"' });
console.log('Exit code:', result.exitCode);

await sdk.shutdown();
```

The collector should show a TS-layer span (`mxc.sdk.run`) as the parent of the `mxc.execute` Rust span (same trace ID, linked via `TRACEPARENT` env var).

---

## Step 7: Verify span loss prevention (force-flush)

Run a very fast execution (exit immediately):

```json
{
  "script": "exit 0",
  "telemetry": { "enabled": true }
}
```

```powershell
$env:OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:4318"
.\wxc-exec.exe fast_exit.json
```

The collector MUST receive the `mxc.execute` span even though the process ran in under 100 ms — confirming force-flush works.

---

## Cleaning up

```powershell
Remove-Item Env:MXC_ENABLE_TELEMETRY -ErrorAction SilentlyContinue
Remove-Item Env:OTEL_EXPORTER_OTLP_ENDPOINT -ErrorAction SilentlyContinue
# Stop Docker container
docker stop <container-id>
```
