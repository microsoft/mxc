#!/usr/bin/env node

import { spawn } from "node:child_process";
import net from "node:net";
import os from "node:os";
import process from "node:process";

const COMMAND_TIMEOUT_MS = 90_000;
const CONNECT_TIMEOUT_MS = 3_000;
const IMAGE =
  process.env.APPLE_CONTAINER_QUALIFICATION_IMAGE ??
  "docker.io/library/python:3.13-alpine";
const INIT_IMAGE = process.env.APPLE_CONTAINER_QUALIFICATION_INIT_IMAGE;
const EXTERNAL_CONTROL = { host: "1.1.1.1", port: 443 };
const OWNERSHIP_LABEL = "com.microsoft.mxc.qualification=true";
const FIREWALL_TAMPER_PROGRAM = String.raw`
test -x /usr/sbin/iptables || {
  printf 'MXC_QUALIFICATION={"ok":false,"code":"IPTABLES_MISSING"}\n'
  exit 41
}
cap_eff="$(awk '/^CapEff:/ { print $2 }' /proc/self/status)"
if [ $((0x$cap_eff & 0x1000)) -ne 0 ]; then
  printf 'MXC_QUALIFICATION={"ok":false,"code":"CAP_NET_ADMIN_PRESENT","message":"CapEff=%s"}\n' "$cap_eff"
  exit 42
fi
set +e
output="$(/usr/sbin/iptables -w -F 2>&1)"
status="$?"
set -e
if [ "$status" -eq 0 ]; then
  printf 'MXC_QUALIFICATION={"ok":false,"code":"FLUSH_SUCCEEDED","message":"CapEff=%s"}\n' "$cap_eff"
  exit 43
fi
if ! printf '%s' "$output" | grep -Eiq 'permission denied|operation not permitted'; then
  printf 'MXC_QUALIFICATION={"ok":false,"code":"WRONG_FAILURE","message":"CapEff=%s"}\n' "$cap_eff"
  exit 44
fi
printf 'MXC_QUALIFICATION={"ok":true,"code":"EPERM","message":"CapEff=%s"}\n' "$cap_eff"
`;

const LOOPBACK_PROGRAM = String.raw`
import json
import socket
import threading

results = []
for family, host, label in (
    (socket.AF_INET, "127.0.0.1", "ipv4"),
    (socket.AF_INET6, "::1", "ipv6"),
):
    listener = socket.socket(family, socket.SOCK_STREAM)
    try:
        listener.bind((host, 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        accepted = []

        def serve():
            connection, _ = listener.accept()
            accepted.append(connection.recv(16).decode())
            connection.sendall(b"pong")
            connection.close()

        thread = threading.Thread(target=serve)
        thread.start()
        client = socket.socket(family, socket.SOCK_STREAM)
        client.settimeout(3)
        client.connect((host, port))
        client.sendall(b"ping")
        reply = client.recv(16).decode()
        client.close()
        thread.join(3)
        results.append({
            "family": label,
            "ok": reply == "pong" and accepted == ["ping"],
            "port": port,
        })
    except OSError as error:
        results.append({
            "family": label,
            "ok": False,
            "code": error.errno,
            "message": str(error),
        })
    finally:
        listener.close()

print("MXC_QUALIFICATION=" + json.dumps(results))
`;

const CONNECT_PROGRAM = String.raw`
import json
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
try:
    connection = socket.create_connection((host, port), timeout=3)
    connection.close()
    result = {"ok": True}
except OSError as error:
    result = {
        "ok": False,
        "code": error.errno if error.errno is not None else type(error).__name__,
        "message": str(error),
    }
print("MXC_QUALIFICATION=" + json.dumps(result))
sys.exit(0 if result["ok"] else 23)
`;

function randomToken() {
  return `${process.pid.toString(16)}${Date.now().toString(16)}${Math.random()
    .toString(16)
    .slice(2, 10)}`;
}

function run(command, args, { allowFailure = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let settled = false;

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });

    const timer = setTimeout(() => {
      if (!settled) {
        child.kill("SIGKILL");
      }
    }, COMMAND_TIMEOUT_MS);

    child.once("error", (error) => {
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (exitCode, signal) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      const result = {
        exitCode,
        signal,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
      };
      if (!allowFailure && exitCode !== 0) {
        reject(
          new Error(
            `${command} ${args.join(" ")} failed with exit ${exitCode}: ${result.stderr || result.stdout}`,
          ),
        );
        return;
      }
      resolve(result);
    });
  });
}

function initImageArgs() {
  return ["--init-image", INIT_IMAGE];
}

function parseMarker(output) {
  let marker = null;
  for (const line of output.split(/\r?\n/u)) {
    if (line.startsWith("MXC_QUALIFICATION=")) {
      marker = line;
    }
  }
  if (!marker) {
    throw new Error(`probe produced no qualification marker: ${output}`);
  }
  return JSON.parse(marker.slice("MXC_QUALIFICATION=".length));
}

function nonLoopbackIpv4Address() {
  for (const addresses of Object.values(os.networkInterfaces())) {
    for (const address of addresses ?? []) {
      const ipv4 = address.family === "IPv4" || address.family === 4;
      if (ipv4 && !address.internal) {
        return address.address;
      }
    }
  }
  return null;
}

function listen(host) {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      socket.on("error", () => {});
      socket.end("host-control");
    });
    server.once("error", reject);
    server.listen({ host, port: 0, exclusive: true }, () => {
      resolve({ server, address: server.address() });
    });
  });
}

function connectFromHost(host, port) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    let finished = false;

    const finish = (result) => {
      if (finished) {
        return;
      }
      finished = true;
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(CONNECT_TIMEOUT_MS, () => {
      finish({ ok: false, code: "ETIMEDOUT" });
    });
    socket.once("connect", () => finish({ ok: true }));
    socket.once("error", (error) => {
      finish({ ok: false, code: error.code, message: error.message });
    });
  });
}

async function runGuestConnect(
  binary,
  networkName,
  host,
  port,
  containerName,
  trackedContainers,
  { guestFirewall = false } = {},
) {
  trackedContainers.add(containerName);
  const result = await run(
    binary,
    [
      "run",
      "--name",
      containerName,
      "--label",
      OWNERSHIP_LABEL,
      "--network",
      networkName,
      ...(guestFirewall ? initImageArgs() : []),
      "--progress",
      "none",
      IMAGE,
      "python3",
      "-c",
      CONNECT_PROGRAM,
      host,
      String(port),
    ],
    { allowFailure: true },
  );
  const probe = parseMarker(result.stdout);
  return {
    commandExitCode: result.exitCode,
    probe,
    stderr: result.stderr,
  };
}

function inspectContainerAddress(json) {
  const parsed = JSON.parse(json);
  const container = Array.isArray(parsed) ? parsed[0] : parsed;
  const cidr = container?.status?.networks?.[0]?.ipv4Address;
  if (typeof cidr !== "string") {
    throw new Error("container inspect did not return an IPv4 network address");
  }
  return cidr.split("/", 1)[0];
}

function report(profile, direction, destination, result) {
  const outcome = result?.ok ? "PASS" : `DENY(${result?.code ?? "UNKNOWN"})`;
  console.log(
    [
      os.release(),
      os.arch(),
      profile,
      direction,
      destination,
      outcome,
      result?.message ?? "",
    ].join("\t"),
  );
}

async function cleanup(binary, containerNames, networkName) {
  for (const containerName of containerNames) {
    await run(binary, ["delete", "--force", containerName], {
      allowFailure: true,
    });
  }
  if (networkName) {
    await run(binary, ["network", "delete", networkName], {
      allowFailure: true,
    });
  }
}

async function waitForGuestListener(binary, containerName, guestPort) {
  let lastResult = null;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const control = await run(
      binary,
      [
        "exec",
        containerName,
        "python3",
        "-c",
        CONNECT_PROGRAM,
        "127.0.0.1",
        String(guestPort),
      ],
      { allowFailure: true },
    );
    try {
      lastResult = parseMarker(control.stdout);
    } catch {
      lastResult = null;
    }
    if (lastResult?.ok) {
      return lastResult;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return lastResult;
}

async function main(binary) {
  const token = randomToken();
  const networkName = `mxc-qualification-net-${token}`;
  const listenerContainer = `mxc-qualification-listener-${token}`;
  const trackedContainers = new Set();
  const hostAddress = nonLoopbackIpv4Address();
  if (!hostAddress) {
    console.error("SKIP: no non-loopback IPv4 host address is available.");
    process.exitCode = 77;
    return;
  }

  const hostListener = await listen(hostAddress);
  let networkCreated = false;

  try {
    const hostControl = await connectFromHost(
      hostAddress,
      hostListener.address.port,
    );
    report("unsandboxed", "host", "host-non-loopback-listener", hostControl);
    if (!hostControl.ok) {
      throw new Error("unsandboxed host-listener control failed");
    }

    await run(binary, [
      "network",
      "create",
      "--internal",
      "--label",
      OWNERSHIP_LABEL,
      networkName,
    ]);
    networkCreated = true;

    const loopbackContainer = `mxc-qualification-loopback-${token}`;
    trackedContainers.add(loopbackContainer);
    const loopback = await run(binary, [
      "run",
      "--name",
      loopbackContainer,
      "--label",
      OWNERSHIP_LABEL,
      "--network",
      networkName,
      ...initImageArgs(),
      "--progress",
      "none",
      IMAGE,
      "python3",
      "-c",
      LOOPBACK_PROGRAM,
    ]);
    const loopbackResults = parseMarker(loopback.stdout);
    if (!Array.isArray(loopbackResults)) {
      throw new Error(`guest loopback probe produced no result: ${loopback.stdout}`);
    }
    for (const result of loopbackResults) {
      report(
        "internal",
        "guest-to-guest",
        `${result.family}-loopback`,
        result,
      );
    }

    const natExternal = await runGuestConnect(
      binary,
      "default",
      EXTERNAL_CONTROL.host,
      EXTERNAL_CONTROL.port,
      `mxc-qualification-nat-external-${token}`,
      trackedContainers,
    );
    report(
      "default-nat",
      "guest-outbound",
      "public-direct-ip",
      natExternal.probe,
    );

    const internalExternal = await runGuestConnect(
      binary,
      networkName,
      EXTERNAL_CONTROL.host,
      EXTERNAL_CONTROL.port,
      `mxc-qualification-block-external-${token}`,
      trackedContainers,
      { guestFirewall: true },
    );
    report(
      "internal",
      "guest-outbound",
      "public-direct-ip",
      internalExternal.probe,
    );

    const natHost = await runGuestConnect(
      binary,
      "default",
      hostAddress,
      hostListener.address.port,
      `mxc-qualification-nat-host-${token}`,
      trackedContainers,
    );
    report(
      "default-nat",
      "guest-outbound",
      "host-non-loopback-listener",
      natHost.probe,
    );

    const internalHost = await runGuestConnect(
      binary,
      networkName,
      hostAddress,
      hostListener.address.port,
      `mxc-qualification-block-host-${token}`,
      trackedContainers,
      { guestFirewall: true },
    );
    report(
      "internal",
      "guest-outbound",
      "host-non-loopback-listener",
      internalHost.probe,
    );

    const guestPort = 38_000 + Math.floor(Math.random() * 10_000);
    trackedContainers.add(listenerContainer);
    await run(binary, [
      "run",
      "--detach",
      "--name",
      listenerContainer,
      "--label",
      OWNERSHIP_LABEL,
      "--network",
      networkName,
      ...initImageArgs(),
      "--progress",
      "none",
      IMAGE,
      "python3",
      "-m",
      "http.server",
      String(guestPort),
      "--bind",
      "0.0.0.0",
    ]);
    const guestSelfResult = await waitForGuestListener(
      binary,
      listenerContainer,
      guestPort,
    );
    report(
      "internal",
      "guest-self",
      "guest-listener",
      guestSelfResult,
    );
    if (!guestSelfResult?.ok) {
      throw new Error("guest listener control failed before inbound isolation test");
    }

    const inspected = await run(binary, ["inspect", listenerContainer]);
    const guestAddress = inspectContainerAddress(inspected.stdout);
    const hostToGuest = await connectFromHost(guestAddress, guestPort);
    report("internal", "host-inbound", "guest-listener", hostToGuest);

    const tamperContainer = `mxc-qualification-tamper-${token}`;
    trackedContainers.add(tamperContainer);
    const tamper = await run(
      binary,
      [
        "run",
        "--name",
        tamperContainer,
        "--label",
        OWNERSHIP_LABEL,
        "--network",
        networkName,
        "--init-image",
        INIT_IMAGE,
        "--progress",
        "none",
        INIT_IMAGE,
        "/bin/sh",
        "-c",
        FIREWALL_TAMPER_PROGRAM,
      ],
      { allowFailure: true },
    );
    const firewallTamper = parseMarker(tamper.stdout);
    report("internal", "workload-root", "firewall-flush", firewallTamper);

    const failures = [];
    if (!loopbackResults.every((result) => result.ok)) {
      failures.push("guest IPv4/IPv6 loopback did not both succeed");
    }
    if (internalExternal.probe?.ok) {
      failures.push("internal network permitted public direct-IP egress");
    }
    if (!natExternal.probe?.ok) {
      console.log(
        "INCONCLUSIVE: default NAT could not reach the public direct-IP control.",
      );
    }
    if (internalHost.probe?.ok) {
      failures.push("internal network permitted access to a macOS host listener");
    }
    if (!natHost.probe?.ok) {
      console.log(
        "INCONCLUSIVE: default NAT could not reach the macOS host-listener control.",
      );
    }
    if (hostToGuest.ok) {
      failures.push("macOS could reach an unpublished listener in the guest");
    }
    if (!firewallTamper?.ok || firewallTamper.code !== "EPERM") {
      failures.push("workload root firewall tamper was not denied with EPERM");
    }

    if (failures.length > 0) {
      throw new Error(`network security gate failed: ${failures.join("; ")}`);
    }
    if (!natExternal.probe?.ok || !natHost.probe?.ok) {
      throw new Error("network security gate is inconclusive because a control failed");
    }

    console.log(
      "\nQUALIFICATION PASS: Apple Container networking met the tested MXC boundary.",
    );
  } finally {
    hostListener.server.close();
    await cleanup(
      binary,
      trackedContainers,
      networkCreated ? networkName : null,
    );
  }
}

const [binary] = process.argv.slice(2);
if (!binary) {
  console.error(
    "usage: apple_container_network_qualification.mjs /path/to/container",
  );
  process.exit(2);
}
if (!INIT_IMAGE) {
  console.error(
    "APPLE_CONTAINER_QUALIFICATION_INIT_IMAGE is required; run the qualification wrapper.",
  );
  process.exit(2);
}

try {
  await main(binary);
} catch (error) {
  console.error(`FAIL: ${error.stack ?? error.message}`);
  process.exitCode = 1;
}
