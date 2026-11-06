// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { dirname, join, resolve } = require("node:path");
const { test } = require("node:test");
const { runInNewContext } = require("node:vm");

const root = resolve(__dirname, "..", "..", "..");
const gatePath = join(root, "scripts", "check-dotnet-api-parity.js");
const probePath = join(root, "src", "mxc-sdk", "src", "core", "mxc_engine", "probe.rs");
const platformPath = join(
  root, "sdk", "dotnet", "Microsoft.Mxc.Sdk", "V1", "MxcPlatform.cs"
);
const dispatchPath = join(
  root, "src", "mxc-sdk", "src", "core", "mxc_common", "state_aware_dispatch.rs"
);
const enginePath = join(
  root, "src", "mxc-sdk", "src", "core", "mxc_engine", "state_aware.rs"
);

function runGate(changedPath, transform) {
  const errors = [];
  const exit = Symbol("exit");
  let status = 0;
  try {
    runInNewContext(readFileSync(gatePath, "utf8"), {
      __dirname: dirname(gatePath),
      require(name) {
        if (name !== "fs") return require(name);
        return {
          readFileSync(path, encoding) {
            const source = readFileSync(path, encoding);
            return path === changedPath ? transform(source) : source;
          },
        };
      },
      console: {
        log() {},
        error(message) { errors.push(message); },
      },
      process: {
        exit(code) {
          status = code;
          throw exit;
        },
      },
    });
  } catch (error) {
    if (error !== exit) throw error;
  }
  return { status, errors: errors.join("\n") };
}

test("native-only discovery passes while V1 retains legacy tier readers", () => {
  assert.deepEqual(runGate(), { status: 0, errors: "" });
});

test("a new reported tier requires a managed parser case", () => {
  const result = runGate(probePath, (source) =>
    source.replaceAll('"base-container"', '"future-tier"')
  );
  assert.equal(result.status, 1);
  assert.match(result.errors, /isolation-tier wire names:.*future-tier/);
});

test("the gate fails when the canonical tier list cannot be found", () => {
  const result = runGate(probePath, (source) =>
    source.replace("const CANONICAL_TIERS:", "const RENAMED_TIERS:")
  );
  assert.equal(result.status, 1);
  assert.match(result.errors, /probe\.rs: could not find CANONICAL_TIERS/);
});

test("V1 must retain parser cases for published legacy tiers", () => {
  const result = runGate(platformPath, (source) =>
    source.replace(/^\s*"appcontainer-bfs"\s*=>[^\n]+\n/m, "")
  );
  assert.equal(result.status, 1);
  assert.match(result.errors, /isolation-tier wire names:.*appcontainer-bfs/);
});

test("unsupported lifecycle prefixes do not require managed SDK support", () => {
  const result = runGate(dispatchPath, (source) => {
    const marker = '"microvm" => Ok(ContainmentBackend::MicroVm),';
    assert.ok(source.includes(marker));
    return source.replace(marker, `${marker}\n        "future" => Ok(ContainmentBackend::Future),`);
  });
  assert.deepEqual(result, { status: 0, errors: "" });
});

test("supported lifecycle prefixes must remain in the native dispatcher", () => {
  const result = runGate(dispatchPath, (source) => {
    const marker = '"wslc" => Ok(ContainmentBackend::Wslc),';
    assert.ok(source.includes(marker));
    return source.replace(marker, "");
  });
  assert.equal(result.status, 1);
  assert.match(result.errors, /state-aware sandbox-id prefixes:.*wslc:Wslc/);
});

test("new lifecycle support requires managed enum and prefix parity", () => {
  const result = runGate(enginePath, (source) => {
    const marker = "_ => run_state_aware_fallback(parsed, dry_run),";
    assert.ok(source.includes(marker));
    return source.replace(
      marker,
      "crate::mxc_common::models::ContainmentBackend::MicroVm => unimplemented!(),\n" +
        `        ${marker}`
    );
  });
  assert.equal(result.status, 1);
  assert.match(result.errors, /state-aware containment enum:.*MicroVm/);
  assert.match(result.errors, /state-aware sandbox-id prefixes:.*microvm:MicroVm/);
});
