// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const { after, before, test } = require("node:test");
const assert = require("node:assert/strict");
const {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} = require("node:fs");
const { tmpdir } = require("node:os");
const { delimiter, join, resolve } = require("node:path");
const { spawnSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const { pathToFileURL } = require("node:url");
const { stripVTControlCharacters } = require("node:util");

const root = resolve(__dirname, "..", "..");
const dispatcher = join(root, "scripts", "ci", "run_backend_validation_tests.ps1");
const staging = join(root, "scripts", "ci", "stage-nvx-validation-tests.ps1");
const packaging = join(root, "scripts", "ci", "Invoke-CratePackage.ps1");
const microvmFixtures = [
  "microvm_hello.json",
  "microvm_exit_code.json",
  "microvm_multiline.json",
  "microvm_stdlib.json",
  "microvm_large_output.json",
  "microvm_error.json",
  "microvm_timeout.json",
];
let scratch;
let fixture;
let tools;

function fixtureEnvironment(overrides = {}) {
  return {
    ...process.env,
    TEMP: scratch,
    TMP: scratch,
    npm_config_cache: join(scratch, "npm-cache"),
    ...overrides,
  };
}

function runScript(script, args, env) {
  const result = spawnSync(
    "pwsh",
    ["-NoProfile", "-File", script, ...args],
    {
      cwd: root,
      env: fixtureEnvironment(env),
      encoding: "utf8",
      timeout: 30_000,
    }
  );
  assert.ifError(result.error);
  return {
    status: result.status,
    output: stripVTControlCharacters(result.stdout + result.stderr),
  };
}

before(() => {
  scratch = mkdtempSync(join(tmpdir(), "mxc-microvm-validation-"));
  tools = join(scratch, "tools");
  mkdirSync(tools);
  fixture = join(scratch, "fixture.exe");
  const source = join(scratch, "fixture.rs");
  // A native fixture exercises the real dispatcher's process and exit handling.
  writeFileSync(source, String.raw`
use std::{env, path::Path, process};

fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    let mode = env::var("MXC_CI_FIXTURE_MODE").unwrap_or_default();
    let exe = env::current_exe().unwrap();
    if exe.file_stem().unwrap() == "cargo" {
        if args.first().map(String::as_str) == Some("metadata") {
            let target = env::var("MXC_CI_PACKAGE_TARGET").unwrap();
            let manifest = env::var("MXC_CI_PACKAGE_MANIFEST").unwrap();
            println!(r#"{{"packages":[{{"name":"mxc-sdk","version":"1.0.0","manifest_path":{manifest:?},"description":"fixture","repository":"https://github.com/microsoft/mxc","license":"MIT","dependencies":[]}}],"target_directory":{target:?}}}"#);
            return;
        }
        if args.first().map(String::as_str) == Some("fetch") {
            return;
        }
        if args.first().map(String::as_str) == Some("package") {
            assert!(args.contains(&"--no-verify".to_owned()));
            let directory = Path::new(&env::var("MXC_CI_PACKAGE_TARGET").unwrap()).join("package");
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::copy(env::var("MXC_CI_PACKAGE_ARCHIVE").unwrap(), directory.join("mxc-sdk-1.0.0.crate")).unwrap();
            return;
        }
        assert!(args.contains(&"--locked".to_owned()));
        assert!(args.contains(&"--release".to_owned()));
        if args.windows(2).any(|pair| pair == ["--test", "module_lifetime"]) {
            assert!(args.windows(2).any(|pair| pair == ["--features", "microvm"]));
            assert!(args.contains(&"--exact".to_owned()));
            assert!(args.contains(&"nvx_error_keeps_pending_worker_code_loaded".to_owned()));
            match mode.as_str() {
                "module-lifetime-missing" => println!("test result: ok. 0 passed; 0 failed;"),
                "module-lifetime-ignored" => println!("test nvx_error_keeps_pending_worker_code_loaded ... ignored"),
                _ => println!("test nvx_error_keeps_pending_worker_code_loaded ... ok"),
            }
            if mode == "module-lifetime-failure" {
                process::exit(19);
            }
            return;
        }
        let signature_check = args.windows(2).any(|pair| pair == ["--test", "nvx_bundle_integrity"]);
        assert!(args.contains(&"--no-run".to_owned()) || signature_check);
        assert!(args.windows(2).any(|pair| pair == ["--test", "nvx_e2e"]) || signature_check);
        assert!(args.windows(2).any(|pair| pair == ["--target", "x86_64-pc-windows-msvc"]));
        if let Some(index) = args.iter().position(|arg| arg == "--manifest-path") {
            let manifest = Path::new(&args[index + 1]);
            assert!(manifest.is_file());
            assert_eq!(manifest.parent().unwrap().file_name().unwrap(), "mxc-sdk-1.0.0");
            assert!(args.contains(&"--offline".to_owned()));
            if signature_check {
                assert!(args.iter().any(|arg| arg == "crate_staged_bundle_opens_and_rejects_an_unverified_library"));
                if mode == "packaged-signature-failure" {
                    eprintln!("fixture packaged signature failed");
                    process::exit(31);
                }
                let passed = if mode == "packaged-signature-empty" { 0 } else { 1 };
                println!("test result: ok. {passed} passed; 0 failed; 0 ignored;");
                return;
            }
            if mode == "packaged-build-failure" {
                eprintln!("fixture packaged compilation failed");
                process::exit(29);
            }
            println!("PACKAGE_COMPILED extracted nvx_e2e target");
            return;
        }
        if mode == "cargo-failure" {
            eprintln!("fixture cargo failed");
            process::exit(17);
        }
        if mode != "cargo-no-artifact" {
            let executable = env::var("MXC_CI_FIXTURE_EXECUTABLE").unwrap();
            assert!(Path::new(&executable).is_file());
            println!("{{\"reason\":\"compiler-artifact\",\"target\":{{\"name\":\"nvx_e2e\"}},\"profile\":{{\"test\":true}},\"executable\":{executable:?}}}");
            if mode != "missing-signature-artifact" {
                println!("{{\"reason\":\"compiler-artifact\",\"target\":{{\"name\":\"nvx_bundle_integrity\"}},\"profile\":{{\"test\":true}},\"executable\":{executable:?}}}");
            }
        }
        return;
    }
    if args.iter().any(|arg| arg == "crate_staged_bundle_opens_and_rejects_an_unverified_library") {
        if mode == "signature-failure" {
            eprintln!("fixture NVX signature validation failed");
            process::exit(31);
        }
        let passed = if mode == "signature-empty" { 0 } else { 1 };
        println!("test result: ok. {passed} passed; 0 failed; 0 ignored;");
        return;
    }
    if args == ["--list"] {
        if mode != "missing-validation-discovery" {
            println!("windows_x64::native_validation_rejects_requests_without_booting_a_vm: test");
        }
        if mode != "missing-proxy-discovery" {
            println!("windows_x64::signed_agent_proxy_validation_withholds_credentials: test");
        }
        if mode != "missing-alias-discovery" {
            println!("windows_x64::guest_path_resolves_windows_case_alias: test");
        }
        if mode != "missing-executor-proxy-discovery" {
            println!("windows_x64::signed_executor_proxy_validation_withholds_credentials: test");
        }
        println!("windows_x64::signed_bundle_executor_configs: test");
        println!("windows_x64::signed_bundle_executor_create_and_run: test");
        println!("windows_x64::signed_bundle_json_image_and_filesystem_policy: test");
        if mode != "missing-interruption-discovery" {
            println!("windows_x64::signed_bundle_executor_console_interrupt: test");
        }
        if mode != "missing-stdin-close-discovery" {
            println!("windows_x64::signed_bundle_executor_stdin_close_cancels: test");
        }
        if mode != "missing-held-container-discovery" {
            println!("windows_x64::signed_bundle_executor_holds_a_container: test");
        }
        if mode != "missing-image-reuse-discovery" {
            println!("windows_x64::signed_bundle_executor_reuses_registered_images: test");
        }
        if mode != "missing-platform-snapshots-discovery" {
            println!("windows_x64::signed_bundle_executor_starts_sandboxes_from_platform_snapshots: test");
        }
        if mode != "missing-snapshot-memory-discovery" {
            println!("windows_x64::signed_bundle_snapshot_memory_capacity: test");
        }
        if mode != "missing-discovery" {
            println!("windows_x64::signed_bundle_facade_create_and_run: test");
        }
        if mode != "missing-sdk-json-discovery" {
            println!("windows_x64::signed_bundle_sdk_json_capture: test");
        }
        if mode != "missing-sdk-lifecycle-discovery" {
            println!("windows_x64::signed_bundle_sdk_json_lifecycle: test");
        }
        if mode != "missing-network-discovery" {
            println!("windows_network::signed_bundle_network_rules_enforce_allow_deny_and_port_selectors: test");
        }
        if mode != "missing-host-loopback-discovery" {
            println!("windows_network::signed_bundle_host_loopback_ingress: test");
        }
        if mode != "missing-network-proxy-discovery" {
            println!("windows_network::signed_bundle_deny_default_proxy_policy: test");
        }
        return;
    }
    assert!(args.contains(&"--include-ignored".to_owned()));
    assert!(args.contains(&"--nocapture".to_owned()));
    assert!(args.contains(&"--test-threads=1".to_owned()));
    if mode == "native-failure" {
        eprintln!("fixture runtime failed");
        process::exit(23);
    }
    if mode == "zero-tests" {
        println!("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;");
        return;
    }
    if mode != "missing-facade" {
        println!("VM_EXECUTED facade sequential stdout/stderr/exit/env/cwd/timeout/capture-limit/cleanup");
    }
    if mode != "missing-sdk-json" {
        println!("VM_EXECUTED SDK JSON binary capture timeout limit and cleanup");
    }
    if mode != "missing-sdk-lifecycle" {
        println!("VM_EXECUTED SDK JSON lifecycle clone start state reuse live-owner rejection and adoption");
    }
    if mode != "missing-sdk-clone-cleanup" {
        println!("VM_EXECUTED SDK JSON lifecycle same-process clone cleanup lease release and reuse");
    }
    if mode != "missing-snapshot-memory" {
        println!("VM_EXECUTED snapshot memory explicit 256 clone and 512 resource cold boot guest sizing both modes");
    }
    if mode != "missing-executor-lifecycle" {
        println!("VM_EXECUTED executor lifecycle provision/dry-run clone start cross-process exec and cleanup");
    }
    if mode != "missing-platform-snapshots" {
        println!("VM_EXECUTED executor platform snapshot NIC/noNIC clones stable templates and isolated VMs");
    }
    if mode != "missing-sdk-platform-snapshots" {
        println!("VM_EXECUTED SDK JSON platform snapshot repeated capture/streaming clones and isolation");
    }
    if mode != "missing-snapshot-fallback" {
        println!("VM_EXECUTED SDK JSON platform snapshot cold fallback capture/streaming warnings lifecycle diagnostics and recovery");
    } else {
        println!("VM_EXECUTED SDK JSON platform snapshot cold fallback warnings capture/streaming/lifecycle and recovery");
    }
    if mode != "missing-json-image" {
        let suffix = if mode == "unconfirmed-filesystem" { "" } else { " confirmed clones" };
        println!("VM_EXECUTED JSON selected-image filesystem read/write/deny and cleanup{suffix}");
    }
    if mode != "missing-executor" {
        println!("VM_EXECUTED executor sequential stdout/stderr/exit/timeout/capture-limit/cleanup");
    }
    if mode != "missing-configs" {
        println!("VM_EXECUTED executor configs all seven fixtures");
    }
    if mode != "missing-interruption" {
        println!("VM_EXECUTED executor console interruption capture/startup/execution/owned-vmm/cleanup");
    } else {
        println!("VM_EXECUTED executor console interruption startup/execution/owned-vmm/cleanup");
    }
    if mode != "missing-stdin-close" {
        println!("VM_EXECUTED executor stdin-close cancellation startup/execution/owned-vmm/cleanup");
    }
    if mode != "missing-held-container" {
        println!("VM_EXECUTED executor held container side-by-side execs/state/cancel/teardown");
    }
    if mode != "missing-image-reuse" {
        println!("VM_EXECUTED executor registered-image reuse offline concurrent first-capture clone isolation");
    } else {
        println!("VM_EXECUTED executor registered-image reuse offline and concurrent");
    }
    if mode != "missing-network" {
        let suffix = if mode == "unconfirmed-network" { "" } else { " confirmed clones" };
        println!("VM_EXECUTED reachable controls and network allow/deny/nonmatching-port enforcement{suffix}");
    }
    if mode != "missing-network-udp" {
        let suffix = if mode == "unconfirmed-network-udp" { "" } else { " confirmed clones" };
        println!("VM_EXECUTED UDP datagrams replies delivery counts protocol separation and inclusive ranges{suffix}");
    }
    if mode != "missing-host-loopback" {
        let suffix = if mode == "unconfirmed-host-loopback" { "" } else { " confirmed clones" };
        println!("VM_EXECUTED host-loopback ingress TCP/UDP allow deny ready listeners and reply controls{suffix}");
    }
    if mode != "missing-network-proxy" {
        let suffix = if mode == "unconfirmed-network-proxy" { "" } else { " confirmed clones" };
        println!("VM_EXECUTED reachable controls, blocked direct egress and successful proxy traffic{suffix}");
    }
    if mode == "skipped" {
        println!("SKIPPED: fixture VM unavailable");
    }
    let ignored = if mode == "ignored" { 1 } else { 0 };
    println!("test result: ok. 7 passed; 0 failed; {ignored} ignored; 0 measured; 0 filtered out;");
}
`);
  const build = spawnSync(
    "rustc",
    ["--edition=2021", "--crate-name", "mxc_ci_fixture", source, "-o", fixture],
    { cwd: root, env: fixtureEnvironment(), encoding: "utf8", timeout: 60_000 }
  );
  assert.ifError(build.error);
  assert.equal(build.status, 0, build.stdout + build.stderr);
  copyFileSync(fixture, join(tools, "cargo.exe"));
});

after(() => {
  if (scratch) rmSync(scratch, { recursive: true, force: true });
});

function artifact() {
  const directory = mkdtempSync(join(scratch, "artifact-"));
  copyFileSync(fixture, join(directory, "wxc-exec.exe"));
  copyFileSync(fixture, join(directory, "nvx-e2e-tests.exe"));
  mkdirSync(join(directory, "aci-edge-sandboxes"));
  writeFileSync(
    join(directory, "aci-edge-sandboxes", "bundle-manifest.json"),
    "{}"
  );
  return directory;
}

function dispatch(directory, mode = "", architecture = "x64") {
  return runScript(
    dispatcher,
    [
      "-Backend", "microvm", "-BinaryDirectory", directory, "-Architecture", architecture,
      "-TempDirectory", join(directory, "logs"),
    ],
    {
      MXC_CI_FIXTURE_MODE: mode,
    }
  );
}

test("nightly schedules exactly Windows 25H2 x64 MicroVM", async () => {
  const { expandPlan, readCatalog } = await import(
    pathToFileURL(join(root, "scripts", "ci", "resolve-validation-test-matrix.mjs"))
  );
  const catalog = readCatalog(join(root, "scripts", "ci", "validation-test-matrix.json"));
  assert.deepEqual(
    expandPlan(catalog, "nightly")
      .filter((entry) => entry.backend === "microvm")
      .map(({ os, architecture, target, artifact }) => ({ os, architecture, target, artifact })),
    [{
      os: "windows-25h2",
      architecture: "x64",
      target: "x86_64-pc-windows-msvc",
      artifact: "wxc-binaries-x86_64-pc-windows-msvc",
    }]
  );
});

test("Windows builds stage and upload the SDK tests and the complete runtime bundle", () => {
  const workflow = readFileSync(join(root, ".github", "workflows", "Build.Windows.Job.yml"), "utf8");
  assert.match(workflow, /node --test scripts\/tests\/microvm-validation\.test\.js/);
  assert.match(workflow, /scripts\/ci\/stage-nvx-validation-tests\.ps1/);
  assert.ok(workflow.includes("src/target/${{ matrix.target }}/release/nvx-e2e-tests.exe"));
  assert.ok(workflow.includes("src/target/${{ matrix.target }}/release/aci-edge-sandboxes/"));
  assert.match(workflow, /Invoke-CratePackage\.ps1[\s\S]*-VerifyMicrovmTests/);
  assert.match(workflow, /ACI_EDGE_SANDBOXES_AGENT_BUNDLE_DIR:/);
  assert.equal(existsSync(join(root, ".github", "workflows", "microvm-e2e.yml")), false);
});

function azureBundleStep() {
  const pipeline = readFileSync(
    join(root, ".azure-pipelines", "templates", "Rust.Build.Job.yml"),
    "utf8"
  );
  const match = pipeline.match(
    /      - pwsh: \|\r?\n((?:          .*\r?\n)+)        displayName: Copy signed NVX runtime bundle\r?\n        condition: (.*)/
  );
  assert.ok(match, "Azure builds must stage the signed NVX runtime bundle");
  assert.equal(
    match[2].trim(),
    "and(succeeded(), eq('${{ item.os }}', 'windows'), eq('${{ item.arch }}', 'x64'))"
  );
  assert.ok(pipeline.indexOf(match[0]) < pipeline.search(/displayName: Publish\r?\n/));
  const signing = pipeline.match(/        signPattern: \|\r?\n((?:            .*\r?\n)+)/);
  assert.ok(signing, "Windows signing patterns must remain explicit");
  assert.doesNotMatch(signing[1], /aci.edge|openvmm|direct-images|guest[\\/]|[*?]/);
  return match[1].replace(/^          /gm, "");
}

function azureBundleFixture(mode = "") {
  const directory = mkdtempSync(join(scratch, "azure-bundle-"));
  const target = join(directory, "target");
  const outputDirectory = join(directory, "out");
  const triplet = "x86_64-pc-windows-msvc";
  const bundle = join(target, "aci-edge-sandboxes");
  mkdirSync(target);
  mkdirSync(join(outputDirectory, triplet), { recursive: true });
  // Verify recursive copying, including files unknown to MXC's packaging logic.
  const inventory = ["SOURCE-MANIFEST.json", "bundle-manifest.json", "SHA256SUMS",
    "bin/aci_edge_agent.dll", "bin/direct-images.exe", "bin/openvmm.exe",
    "guest/vmlinux", "guest/initramfs-edge.cpio.gz", "source/nested/extra.txt"];

  if (mode !== "absent") {
    mkdirSync(bundle);
    if (mode !== "empty") {
      for (const relative of inventory) {
        if (mode === "missing-manifest" && relative === "SOURCE-MANIFEST.json") continue;
        const path = join(bundle, ...relative.split("/"));
        mkdirSync(resolve(path, ".."), { recursive: true });
        writeFileSync(path, Buffer.from(`signed fixture bytes: ${relative}\0\xff`, "latin1"));
      }
    }
  }
  const script = azureBundleStep()
    .replaceAll("$(targetTripleDir)", target.replaceAll("'", "''"))
    .replaceAll("$(outputDirectory)", outputDirectory.replaceAll("'", "''"))
    .replaceAll("$(targetTriple)", triplet);
  const scriptPath = join(directory, "copy-bundle.ps1");
  writeFileSync(scriptPath, script);
  const result = runScript(scriptPath, [], {});
  return { ...result, directory, bundle, outputDirectory, triplet, inventory };
}

function fileDigests(directory, prefix = "") {
  return readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      return entry.isDirectory()
        ? fileDigests(join(directory, entry.name), relative)
        : [[relative, createHash("sha256").update(readFileSync(join(directory, entry.name))).digest("hex")]];
    })
    .sort(([left], [right]) => left.localeCompare(right));
}

test("Azure release artifact recursively copies the NVX bundle unchanged", () => {
  const result = azureBundleFixture();
  assert.equal(result.status, 0, result.output);
  const expected = fileDigests(result.bundle);
  assert.equal(expected.length, result.inventory.length);
  assert.deepEqual(fileDigests(join(result.outputDirectory, result.triplet, "aci-edge-sandboxes")), expected);

  // The release job downloads the Windows x64 artifact into x64/ before archiving.
  const release = readFileSync(
    join(root, ".azure-pipelines", "templates", "Mxc.Binary.Packaging.Job.yml"),
    "utf8"
  );
  assert.match(release, /artifact: wxc-binaries-x86_64-pc-windows-msvc\s+sdkArch: x64/);
  assert.ok(release.includes("path: $(stagingDirectory)/${{ target.sdkArch }}"));
  assert.ok(release.includes("includeRootFolder: false"));
  const staging = join(result.directory, "release-staging");
  const x64 = join(staging, "x64");
  const archive = join(result.directory, "mxc-release-binaries.zip");
  const extracted = join(result.directory, "extracted");
  mkdirSync(x64, { recursive: true });
  mkdirSync(extracted);
  const script = join(result.directory, "release-archive.ps1");
  const quote = (path) => `'${path.replaceAll("'", "''")}'`;
  writeFileSync(script, [
    "$ErrorActionPreference = 'Stop'",
    `Copy-Item -LiteralPath ${quote(join(result.outputDirectory, result.triplet, "aci-edge-sandboxes"))} -Destination ${quote(x64)} -Recurse`,
    `Compress-Archive -Path ${quote(join(staging, "*"))} -DestinationPath ${quote(archive)}`,
    `Expand-Archive -LiteralPath ${quote(archive)} -DestinationPath ${quote(extracted)}`,
  ].join("\n"));
  const archived = runScript(script, [], {});
  assert.equal(archived.status, 0, archived.output);
  assert.deepEqual(fileDigests(join(extracted, "x64", "aci-edge-sandboxes")), expected);
});

test("npm pack excludes NVX runtime and validation payloads without removing supported SDK binaries", () => {
  const result = azureBundleFixture();
  assert.equal(result.status, 0, result.output);
  const packageRoot = join(result.directory, "node-sdk");
  const binaryRoot = join(packageRoot, "bin");
  const x64 = join(binaryRoot, "x64");
  mkdirSync(x64, { recursive: true });
  copyFileSync(join(root, "sdk", "node", "package.json"), join(packageRoot, "package.json"));
  copyFileSync(join(root, "sdk", "node", "bin", ".npmignore"), join(binaryRoot, ".npmignore"));
  writeFileSync(join(x64, "wxc-exec.exe"), "executor fixture");
  writeFileSync(join(x64, "mxc_ffi.dll"), "SDK library fixture");
  const validationSuite = Buffer.from("nightly validation executable");
  const artifactSuite = join(result.outputDirectory, result.triplet, "nvx-e2e-tests.exe");
  writeFileSync(artifactSuite, validationSuite);
  writeFileSync(join(x64, "nvx-e2e-tests.exe"), validationSuite);
  const probeSuites = ["x64", "arm64"].flatMap((arch) =>
    ["mxc-filesystem-probe-tests", "mxc-filesystem-probe-tests.exe"].map((name) => ({ arch, name }))
  );
  for (const { arch, name } of probeSuites) {
    const directory = join(binaryRoot, arch);
    mkdirSync(directory, { recursive: true });
    writeFileSync(join(directory, name), validationSuite);
  }
  const script = join(result.directory, "npm-artifact.ps1");
  const quote = (path) => `'${path.replaceAll("'", "''")}'`;
  writeFileSync(script, [
    "$ErrorActionPreference = 'Stop'",
    `Copy-Item -LiteralPath ${quote(join(result.outputDirectory, result.triplet, "aci-edge-sandboxes"))} -Destination ${quote(x64)} -Recurse`,
  ].join("\n"));
  const copied = runScript(script, [], {});
  assert.equal(copied.status, 0, copied.output);
  const packed = spawnSync("npm pack --ignore-scripts --offline --json", {
    cwd: packageRoot,
    env: fixtureEnvironment(),
    shell: true,
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.ifError(packed.error);
  assert.equal(packed.status, 0, packed.stdout + packed.stderr);
  const files = JSON.parse(packed.stdout)[0].files.map(({ path }) => path).sort();
  assert.deepEqual(files, ["bin/x64/mxc_ffi.dll", "bin/x64/wxc-exec.exe", "package.json"]);
  const expected = fileDigests(result.bundle);
  assert.deepEqual(fileDigests(join(x64, "aci-edge-sandboxes")), expected);
  assert.deepEqual(fileDigests(join(result.outputDirectory, result.triplet, "aci-edge-sandboxes")), expected);
  assert.deepEqual(readFileSync(artifactSuite), validationSuite);
  assert.deepEqual(readFileSync(join(x64, "nvx-e2e-tests.exe")), validationSuite);
  for (const { arch, name } of probeSuites) {
    assert.deepEqual(readFileSync(join(binaryRoot, arch, name)), validationSuite);
  }

  rmSync(join(binaryRoot, ".npmignore"));
  const unfiltered = spawnSync("npm pack --ignore-scripts --offline --json", {
    cwd: packageRoot,
    env: fixtureEnvironment(),
    shell: true,
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.ifError(unfiltered.error);
  assert.equal(unfiltered.status, 0, unfiltered.stdout + unfiltered.stderr);
  const unfilteredFiles = JSON.parse(unfiltered.stdout)[0].files.map(({ path }) => path);
  assert.ok(unfilteredFiles.includes("bin/x64/nvx-e2e-tests.exe"));
  for (const { arch, name } of probeSuites) {
    assert.ok(unfilteredFiles.includes(`bin/${arch}/${name}`));
  }
  assert.deepEqual(
    unfilteredFiles
      .filter((path) => path.startsWith("bin/x64/aci-edge-sandboxes/"))
      .sort(),
    result.inventory.map((path) => `bin/x64/aci-edge-sandboxes/${path}`).sort()
  );
});

for (const mode of ["absent", "empty", "missing-manifest"]) {
  test(`Azure bundle copy rejects ${mode} runtime input`, () => {
    const result = azureBundleFixture(mode);
    assert.notEqual(result.status, 0, result.output);
    assert.match(result.output, /missing the signed NVX bundle/);
    assert.equal(existsSync(join(result.outputDirectory, result.triplet, "aci-edge-sandboxes")), false);
  });
}

test("MicroVM fixtures are canonical packaged inputs and remain in schema validation", () => {
  const fixtureRoot = join(root, "src", "mxc-sdk", "tests", "fixtures", "microvm");
  const sdkTests = readFileSync(join(root, "src", "mxc-sdk", "tests", "nvx_e2e.rs"), "utf8");
  for (const name of microvmFixtures) {
    const request = JSON.parse(readFileSync(join(fixtureRoot, name), "utf8"));
    assert.equal(request.version, "1.1.0-alpha");
    assert.equal(request.containment, "microvm");
    assert.equal(existsSync(join(root, "tests", "configs", name)), false);
    assert.ok(sdkTests.includes(`include_str!("fixtures/microvm/${name}")`), name);
  }
  const validation = readFileSync(join(root, "scripts", "versioning", "validate-configs.js"), "utf8");
  assert.ok(validation.includes('join("src", "mxc-sdk", "tests", "fixtures", "microvm")'));
});

function verifyPackage(mode = "") {
  const directory = mkdtempSync(join(scratch, "package-"));
  const inputs = join(directory, "inputs");
  const packageRoot = join(inputs, "mxc-sdk-1.0.0");
  const fixtureRoot = join(packageRoot, "tests", "fixtures", "microvm");
  mkdirSync(fixtureRoot, { recursive: true });
  const manifest = join(packageRoot, "Cargo.toml");
  writeFileSync(manifest, '[package]\nname = "mxc-sdk"\nversion = "1.0.0"\n');
  for (const name of microvmFixtures) {
    if (mode === "packaged-missing-fixture" && name === "microvm_timeout.json") continue;
    copyFileSync(join(root, "src", "mxc-sdk", "tests", "fixtures", "microvm", name), join(fixtureRoot, name));
  }
  const archive = join(directory, "fixture.crate");
  const packed = spawnSync(
    "tar",
    ["--create", "--gzip", "--file", archive, "--directory", inputs, "mxc-sdk-1.0.0"],
    { env: fixtureEnvironment(), encoding: "utf8", timeout: 30_000 }
  );
  assert.ifError(packed.error);
  assert.equal(packed.status, 0, packed.stdout + packed.stderr);
  return runScript(
    packaging,
    ["-OutDir", join(directory, "output"), "-VerifyMicrovmTests"],
    {
      PATH: tools + delimiter + process.env.PATH,
      MXC_CI_FIXTURE_MODE: mode,
      MXC_CI_PACKAGE_ARCHIVE: archive,
      MXC_CI_PACKAGE_TARGET: join(directory, "target"),
      MXC_CI_PACKAGE_MANIFEST: manifest,
    }
  );
}

test("package gate compiles MicroVM tests from the extracted archive", () => {
  const result = verifyPackage();
  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /PACKAGE_COMPILED extracted nvx_e2e target/);
});

for (const [mode, message] of [
  ["packaged-missing-fixture", /Packaged MicroVM fixture is missing: microvm_timeout\.json/],
  ["packaged-build-failure", /packaged MicroVM test compilation failed with exit 29/],
  ["packaged-signature-failure", /packaged NVX signature verification failed with exit 31/],
  ["packaged-signature-empty", /packaged NVX signature verification did not execute its required test/],
]) {
  test(`package gate rejects ${mode}`, () => {
    const result = verifyPackage(mode);
    assert.notEqual(result.status, 0, result.output);
    assert.match(result.output, message);
    if (mode.startsWith("packaged-signature-")) {
      assert.match(result.output, /Compiled the MicroVM test target/);
    } else {
      assert.doesNotMatch(result.output, /Compiled the MicroVM test target/);
    }
  });
}

test("artifact dispatcher executes prebuilt SDK tests and preserves the log", () => {
  const directory = artifact();
  const result = dispatch(directory);
  assert.equal(result.status, 0, result.output);
  const log = readFileSync(join(directory, "logs", "microvm-nvx.log"), "utf8");
  assert.match(log, /VM_EXECUTED facade /);
  assert.match(log, /VM_EXECUTED SDK JSON binary capture /);
  assert.match(log, /VM_EXECUTED SDK JSON lifecycle clone start state reuse live-owner rejection and adoption/);
  assert.match(log, /VM_EXECUTED SDK JSON lifecycle same-process clone cleanup lease release and reuse/);
  assert.match(log, /VM_EXECUTED snapshot memory explicit 256 clone and 512 resource cold boot guest sizing both modes/);
  assert.match(log, /VM_EXECUTED executor lifecycle provision\/dry-run clone start cross-process exec and cleanup/);
  assert.match(log, /VM_EXECUTED executor platform snapshot NIC\/noNIC clones stable templates and isolated VMs/);
  assert.match(log, /VM_EXECUTED SDK JSON platform snapshot repeated capture\/streaming clones and isolation/);
  assert.match(log, /VM_EXECUTED SDK JSON platform snapshot cold fallback capture\/streaming warnings lifecycle diagnostics and recovery/);
  assert.match(log, /VM_EXECUTED JSON selected-image filesystem read\/write\/deny and cleanup confirmed clones/);
  assert.match(log, /VM_EXECUTED executor /);
  assert.match(log, /VM_EXECUTED executor console interruption capture\/startup\/execution\/owned-vmm\/cleanup/);
  assert.match(log, /VM_EXECUTED executor stdin-close cancellation startup\/execution\/owned-vmm\/cleanup/);
  assert.match(log, /VM_EXECUTED executor held container /);
  assert.match(log, /VM_EXECUTED executor registered-image reuse offline concurrent first-capture clone isolation/);
  assert.match(log, /VM_EXECUTED reachable controls and network allow\/deny\/nonmatching-port enforcement confirmed clones/);
  assert.match(log, /VM_EXECUTED UDP datagrams replies delivery counts protocol separation and inclusive ranges confirmed clones/);
  assert.match(log, /VM_EXECUTED host-loopback ingress TCP\/UDP allow deny ready listeners and reply controls confirmed clones/);
  assert.match(log, /VM_EXECUTED reachable controls, blocked direct egress and successful proxy traffic confirmed clones/);
});

for (const [mode, message] of [
  ["native-failure", /exited 23/],
  ["zero-tests", /executed no tests/],
  ["missing-facade", /did not execute the facade VM scenario/],
  ["missing-sdk-json", /did not execute the SDK JSON capture VM scenario/],
  ["missing-sdk-lifecycle", /did not execute the SDK JSON lifecycle VM scenario/],
  ["missing-sdk-clone-cleanup", /did not execute the SDK clone cleanup VM scenario/],
  ["missing-snapshot-memory", /did not execute the snapshot memory VM scenario/],
  ["missing-executor-lifecycle", /did not execute the executor lifecycle VM scenario/],
  ["missing-platform-snapshots", /did not execute the executor platform snapshots VM scenario/],
  ["missing-sdk-platform-snapshots", /did not execute the SDK platform snapshots VM scenario/],
  ["missing-snapshot-fallback", /did not execute the snapshot fallback warnings VM scenario/],
  ["missing-json-image", /did not execute the JSON image and policy VM scenario/],
  ["missing-executor", /did not execute the executor VM scenario/],
  ["missing-configs", /did not execute the executor configs VM scenario/],
  ["missing-interruption", /did not execute the executor interruption VM scenario/],
  ["missing-stdin-close", /did not execute the executor stdin close VM scenario/],
  ["missing-held-container", /did not execute the executor held container VM scenario/],
  ["missing-image-reuse", /did not execute the executor image reuse VM scenario/],
  ["missing-network", /did not execute the network rules VM scenario/],
  ["missing-network-udp", /did not execute the UDP network rules VM scenario/],
  ["missing-host-loopback", /did not execute the host-loopback ingress VM scenario/],
  ["missing-network-proxy", /did not execute the network proxy VM scenario/],
  ["unconfirmed-filesystem", /did not execute the JSON image and policy VM scenario/],
  ["unconfirmed-network", /did not execute the network rules VM scenario/],
  ["unconfirmed-network-udp", /did not execute the UDP network rules VM scenario/],
  ["unconfirmed-host-loopback", /did not execute the host-loopback ingress VM scenario/],
  ["unconfirmed-network-proxy", /did not execute the network proxy VM scenario/],
  ["skipped", /skipped or filtered tests/],
  ["ignored", /skipped or filtered tests/],
]) {
  test(`artifact dispatcher fails closed for ${mode}`, () => {
    const result = dispatch(artifact(), mode);
    assert.notEqual(result.status, 0, result.output);
    assert.match(result.output, message);
  });
}

test("artifact dispatcher rejects a missing test payload", () => {
  const directory = artifact();
  rmSync(join(directory, "nvx-e2e-tests.exe"));
  const result = dispatch(directory);
  assert.notEqual(result.status, 0, result.output);
  assert.match(result.output, /Required CI artifact file is missing:[\s\S]*nvx-e2e-tests\.exe/);
});

test("artifact dispatcher rejects ARM64 instead of running the x64 suite", () => {
  const result = dispatch(artifact(), "", "arm64");
  assert.notEqual(result.status, 0, result.output);
  assert.match(result.output, /MicroVM validation requires x64/);
});

function stage(mode = "") {
  const directory = artifact();
  rmSync(join(directory, "nvx-e2e-tests.exe"));
  const result = runScript(
    staging,
    ["-BinaryDirectory", directory, "-Features", "microvm"],
    {
      PATH: tools + delimiter + process.env.PATH,
      MXC_CI_FIXTURE_MODE: mode,
      MXC_CI_FIXTURE_EXECUTABLE: fixture,
    }
  );
  return { ...result, directory };
}

function requireModuleLifetime(mode = "") {
  const workflow = readFileSync(join(root, ".github", "workflows", "Build.Windows.Job.yml"), "utf8");
  const block = workflow.match(
    /      - name: Require NVX module lifetime regression\n[\s\S]*?        run: \|\n((?:          [^\n]*\n)+)/
  );
  assert.ok(block, "Windows must require the NVX module lifetime regression");
  const script = join(mkdtempSync(join(scratch, "module-lifetime-")), "require.ps1");
  writeFileSync(
    script,
    "$ErrorActionPreference = 'Stop'\n" +
      block[1].replace(/^ {10}/gm, "").replaceAll("${{ matrix.target }}", "x86_64-pc-windows-msvc")
  );
  return runScript(script, [], {
    PATH: tools + delimiter + process.env.PATH,
    MXC_CI_FIXTURE_MODE: mode,
  });
}

test("Windows requires the NVX module lifetime scenario to execute and pass", () => {
  const result = requireModuleLifetime();
  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /test nvx_error_keeps_pending_worker_code_loaded \.\.\. ok/);
});

for (const mode of ["module-lifetime-missing", "module-lifetime-ignored", "module-lifetime-failure"]) {
  test(`module lifetime gate rejects ${mode}`, () => {
    const result = requireModuleLifetime(mode);
    assert.notEqual(result.status, 0, result.output);
    assert.match(result.output, /NVX module lifetime regression must execute and pass/);
  });
}

test("staging uses Cargo's reported executable and checks VM test discovery", () => {
  const result = stage();
  assert.equal(result.status, 0, result.output);
  assert.deepEqual(
    readFileSync(join(result.directory, "nvx-e2e-tests.exe")),
    readFileSync(fixture)
  );
});

for (const [mode, message] of [
  ["cargo-failure", /cargo test --no-run failed with exit code 17/],
  ["cargo-no-artifact", /Expected one nvx_e2e test executable/],
  ["missing-validation-discovery", /did not discover windows_x64::native_validation_rejects_requests_without_booting_a_vm/],
  ["missing-proxy-discovery", /did not discover windows_x64::signed_agent_proxy_validation_withholds_credentials/],
  ["missing-alias-discovery", /did not discover windows_x64::guest_path_resolves_windows_case_alias/],
  ["missing-executor-proxy-discovery", /did not discover windows_x64::signed_executor_proxy_validation_withholds_credentials/],
  ["missing-discovery", /did not discover windows_x64::signed_bundle_facade_create_and_run/],
  ["missing-sdk-json-discovery", /did not discover windows_x64::signed_bundle_sdk_json_capture/],
  ["missing-sdk-lifecycle-discovery", /did not discover windows_x64::signed_bundle_sdk_json_lifecycle/],
  ["missing-interruption-discovery", /did not discover windows_x64::signed_bundle_executor_console_interrupt/],
  ["missing-stdin-close-discovery", /did not discover windows_x64::signed_bundle_executor_stdin_close_cancels/],
  ["missing-held-container-discovery", /did not discover windows_x64::signed_bundle_executor_holds_a_container/],
  ["missing-image-reuse-discovery", /did not discover windows_x64::signed_bundle_executor_reuses_registered_images/],
  ["missing-platform-snapshots-discovery", /did not discover[\s\S]*windows_x64::signed_bundle_executor_starts_sandboxes_from_platform_snapshots/],
  ["missing-snapshot-memory-discovery", /did not discover[\s\S]*windows_x64::signed_bundle_snapshot_memory_capacity/],
  ["missing-network-discovery", /did not discover[\s\S]*windows_network::signed_bundle_network_rules_enforce_allow_deny_and_port_selectors/],
  ["missing-host-loopback-discovery", /did not discover[\s\S]*windows_network::signed_bundle_host_loopback_ingress/],
  ["missing-network-proxy-discovery", /did not discover[\s\S]*windows_network::signed_bundle_deny_default_proxy_policy/],
  ["missing-signature-artifact", /Expected one NVX bundle verification executable/],
  ["signature-failure", /staged NVX artifact failed signature and integrity validation with exit code 31/],
  ["signature-empty", /staged NVX signature verification did not execute its required test/],
]) {
  test(`staging rejects ${mode}`, () => {
    const result = stage(mode);
    assert.notEqual(result.status, 0, result.output);
    assert.match(result.output, message);
    if (![
      "missing-validation-discovery",
      "missing-proxy-discovery",
      "missing-alias-discovery",
      "missing-executor-proxy-discovery",
      "missing-discovery",
      "missing-sdk-json-discovery",
      "missing-sdk-lifecycle-discovery",
      "missing-interruption-discovery",
      "missing-stdin-close-discovery",
      "missing-held-container-discovery",
      "missing-image-reuse-discovery",
      "missing-platform-snapshots-discovery",
      "missing-snapshot-memory-discovery",
      "missing-network-discovery",
      "missing-host-loopback-discovery",
      "missing-network-proxy-discovery",
      "missing-signature-artifact",
      "signature-failure",
      "signature-empty",
    ].includes(mode)) {
      assert.equal(existsSync(join(result.directory, "nvx-e2e-tests.exe")), false);
    }
  });
}
