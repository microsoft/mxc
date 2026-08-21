# MXC Sandbox Policy Spec v0.8.0

## SandboxPolicy

`SandboxPolicy` is the Node SDK's user-facing authoring type. It expresses the
requested filesystem, network, UI, and execution restrictions.
`createConfigFromPolicy()` translates it into the wire-format
`ContainerConfig` consumed by MXC.

```typescript
type SandboxPolicy = {
  version: "0.8.0-alpha";
  filesystem?: {
    readwritePaths?: string[];
    readonlyPaths?: string[];
    deniedPaths?: string[];
    clearPolicyOnExit?: boolean;
  };
  network?: {
    // Legacy 0.6/0.7-compatible fields:
    allowOutbound?: boolean;
    allowLocalNetwork?: boolean;
    allowedHosts?: string[];
    blockedHosts?: string[];
    proxy?: { builtinTestServer: true } | { localhost: number } | { url: string };

    // Schema 0.8 directional fields:
    egress?: NetworkEgressConfig;
    ingress?: NetworkIngressConfig;
  };
  runtimeConfig?: {
    networkProxy?: string;
  };
  processContainer?: {
    network?: {
      allowedProxyPeer?: string;
    };
  };
  ui?: {
    allowWindows?: boolean;
    clipboard?: "none" | "read" | "write" | "all";
    allowInputInjection?: boolean;
  };
  timeoutMs?: number;
};
```

The directional network types are:

```typescript
type NetworkAction = "allow" | "deny";
type NetworkProtocol = "tcp" | "udp" | "icmp" | "any";

type NetworkPeerConfig = {
  cidr: string;
  except?: string[];
};

type NetworkPortConfig = {
  protocol?: NetworkProtocol;
  port?: number;
  endPort?: number;
};

type NetworkRuleConfig = {
  to?: NetworkPeerConfig[];
  ports?: NetworkPortConfig[];
};

type NetworkEgressConfig = {
  default?: NetworkAction;
  allow?: NetworkRuleConfig[];
  deny?: NetworkRuleConfig[];
};

type NetworkIngressConfig = {
  default?: NetworkAction;
  hostLoopback?: NetworkAction;
};
```

Schema 0.8 accepts either the legacy network fields or the directional fields,
but not both in one policy. `runtimeConfig.networkProxy` and
`processContainer.network.allowedProxyPeer` select the directional format.
Omitted permissions remain default-deny.

See [Schema updates from 0.7 to 0.8](networking/schema-updates.md) for field
mappings and [Network configuration](networking/networking.md) for directional
rule semantics.

## Node SDK example

```typescript
import {
  createConfigFromPolicy,
  spawnSandboxFromConfig,
} from '@microsoft/mxc-sdk';

const config = createConfigFromPolicy({
  version: '0.8.0-alpha',
  filesystem: {
    readonlyPaths: ['C:\\workspace'],
  },
  network: {
    egress: { default: 'deny' },
    ingress: { default: 'allow', hostLoopback: 'allow' },
  },
  runtimeConfig: {
    networkProxy: 'http://127.0.0.1:8080',
  },
  processContainer: {
    network: {
      allowedProxyPeer: 'Contoso.Proxy_1234567890abc',
    },
  },
});

config.process!.commandLine = 'node C:\\workspace\\agent.js';

const child = spawnSandboxFromConfig(config, { usePty: false });
child.stdout!.pipe(process.stdout);
child.stderr!.pipe(process.stderr);
```

For complete wire-format configuration examples, see
[`tests/examples`](../../../tests/examples/).
