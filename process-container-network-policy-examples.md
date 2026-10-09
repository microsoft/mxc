# Windows ProcessContainer network policy examples

These examples assume a Tier 1 BaseContainer host. The JSON values are fragments,
not complete MXC requests. In the "Not enforceable" rows, the fragments describe
the desired policy; some contain fields the schema does not accept and must not
be submitted as-is.

| Status | Desired policy - description | Desired policy - JSON fragment | Limitation |
| --- | --- | --- | --- |
| Enforceable | Block external traffic in both directions, including host loopback. | `{"network":{"egress":{"default":"deny"},"ingress":{"default":"deny","hostLoopback":"deny"}}}` | None; omitting `network` also defaults to deny. |
| Enforceable | Allow outbound TCP/443 to `140.82.112.0/20` only; deny private-network ingress and host loopback. | `{"network":{"egress":{"default":"deny","allow":[{"to":[{"cidr":"140.82.112.0/20"}],"ports":[{"protocol":"tcp","port":443}]}]},"ingress":{"default":"deny","hostLoopback":"deny"}}}` | Matches IP addresses, not a durable domain name. |
| Enforceable | Permit private-network inbound; block outbound traffic and host loopback. | `{"network":{"egress":{"default":"deny"},"ingress":{"default":"allow","hostLoopback":"deny"}}}` | Requires Tier 1 PSEC/WFP enforcement. A separate Windows Firewall rule may still be needed for a remote client to reach the listener. |
| Not enforceable | Allow outbound connections to a private-network range without allowing private-network inbound. | `{"network":{"egress":{"default":"deny","allow":[{"to":[{"cidr":"192.168.1.0/24"}],"ports":[{"protocol":"tcp","port":443}]}]},"ingress":{"default":"deny"}}}` | Private-network access requires the bidirectional `privateNetworkClientServer` capability. |
| Not enforceable | Allow inbound TCP/443 only from `192.168.1.0/24`. | `{"network":{"ingress":{"allow":[{"from":[{"cidr":"192.168.1.0/24"}],"ports":[{"protocol":"tcp","port":443}]}]}}}` | Illustrative, invalid schema: ingress has no `allow`, source-CIDR, or port rules. |
| Not enforceable | Allow outbound traffic by durable DNS name, such as `example.com`. | `{"network":{"egress":{"allow":[{"to":[{"domain":"example.com"}]}]}}}` | Illustrative, invalid schema: egress destinations are numeric IP/CIDR ranges, not domain names. |
| Not enforceable | Combine a direct egress allowlist with a runtime network proxy. | `{"network":{"egress":{"default":"deny","allow":[{"to":[{"cidr":"140.82.112.0/20"}],"ports":[{"protocol":"tcp","port":443}]}]},"ingress":{"default":"allow"}},"runtimeConfig":{"networkProxy":"http://127.0.0.1:8080"}}` | Direct egress rules and proxy-only mode are mutually exclusive. |

For the third example, PSEC 1.0 can grant private-network inbound through
`privateNetworkClientServer` while OS-managed WFP filters block outbound traffic.
PSEC 1.1 with advertised ingress support is required for direct-mode
`hostLoopback: "allow"`, not for this policy. The OS installs WFP filters in a
privileged context without elevating the MXC caller or prompting for UAC per
launch.

See the [ProcessContainer networking guide](docs/backends/process-container/networking.md)
for backend enforcement and the [directional networking schema](docs/schema.md#directional-networking-supported-contracts)
for accepted policy fields and defaults.
