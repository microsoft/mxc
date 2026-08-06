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

Starting in schema 0.8, ProcessContainer networking adds IP/CIDR, protocol, and
port rules. Schema 0.7.0 and earlier retain their existing network config
unchanged. This example permits only TCP/443 to one destination:

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
only with one loopback proxy identity. The proxy must already be running, both
the BaseContainer client and proxy security environments need
`privateNetworkClientServer`, and the proxy executable needs inbound firewall
authorization. Use either an unpackaged AppContainer profile with an
administrator-installed firewall rule or a package family with an MSIX/AppX
`windows.firewallRules` declaration.

See the
[`proxy example and setup guide`](../tests/examples/processcontainer/networking/README.md)
for the complete config, minimal package manifest, launch order, capabilities,
firewall requirements, and unpackaged alternative.