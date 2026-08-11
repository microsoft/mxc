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

### Networking

The [planned schema 0.8.0 update](sandbox-policy/0.8.0/networking/schema-updates.md)
uses `egress` and `ingress` sections. The current parser does not yet accept
this shape. This example allows outbound TCP/443 to one CIDR, denies all other
egress, and blocks private-network and host-loopback inbound connections:

```jsonc
{
  "network": {
    "egress": {
      "default": "deny",
      "allow": [
        {
          "to": [ { "cidr": "140.82.112.0/20" } ],
          "ports": [ { "protocol": "tcp", "port": 443 } ]
        }
      ],
      "deny": []
    },
    "ingress": {
      "default": "deny",
      "hostLoopback": "deny"
    }
  }
}
```

See the [planned network policy](sandbox-policy/0.8.0/networking/networking.md) for the
complete schema and backend support.