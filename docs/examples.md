## Examples

For a more comprehensive list of examples, look in the examples\ directory.

### Basic Hello World
```json
{
  "script": "python -c \"import sys; print('Hello from MXC!'); print(f'Python version: {sys.version}');\"",
  "processContainer": {
    "name": "CLI-HelloWorld"
  }
}
```

### Filesystem Access Control
```json
{
  "script": "python -c \"open('C:\\\\temp\\\\output.txt', 'w').write('test')\"",
  "processContainer": {
    "name": "CLI-Filesystem-Test"
  },
  "filesystem": {
    "readwritePaths": [
      "C:\\temp"
    ],
    "deniedPaths": [
      "C:\\Windows\\System32"
    ],
    "clearPolicyOnExit": true
  }
}
```

### ProcessContainer Network Egress

Schema 0.8 uses IP/CIDR, protocol, and port rules. This example permits only
TCP/443 to one destination:

```json
{
  "version": "0.8.0-dev",
  "containment": "processcontainer",
  "network": {
    "egress": {
      "default": "deny",
      "allow": [
        {
          "to": [{"cidr": "1.1.1.1/32"}],
          "ports": [{"protocol": "tcp", "port": 443}]
        }
      ]
    }
  }
}
```

See the complete
[`egress examples`](../tests/examples/processcontainer/networking/README.md)
for CIDR exceptions, multiple protocols, and explicit deny rules.

### ProcessContainer Network Proxy

Proxy mode denies direct egress and permits the BaseContainer to communicate
only with one loopback AppContainer proxy. The proxy must already be running,
both AppContainers need `privateNetworkClientServer`, and the proxy executable
needs inbound firewall authorization. A packaged proxy can own that
authorization through an MSIX/AppX `windows.firewallRules` declaration.

See the
[`proxy example and setup guide`](../tests/examples/processcontainer/networking/README.md)
for the complete config, minimal package manifest, launch order, capabilities,
firewall requirements, and unpackaged alternative.