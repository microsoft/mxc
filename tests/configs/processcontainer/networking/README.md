# ProcessContainer networking test configs

This directory contains the config-driven ProcessContainer networking matrix
used by the Rust `wxc_e2e_tests` harness. The thin
[`run_base_container_network_tests.ps1`](../../../scripts/run_base_container_network_tests.ps1)
launcher builds the required binaries and selects that test. The Rust harness
executes the legacy cases now and automatically skips the forward-looking
schema 0.8 cases until `egress`, `runtimeConfig`, and `allowedPeer` appear in
the checked-in dev schema.

The matrix covers:

- legacy schema 0.7 allow and deny behavior;
- schema 0.8 deny-by-default policy;
- IPv4/CIDR destinations and CIDR exceptions;
- individual ports, port ranges, TCP, UDP, ICMP, and `any`;
- multiple allow and deny blocks with deny precedence;
- proxy and direct-egress mutual-exclusion validation; and
- blocked DNS, ICMP, TCP, and UNC access.

The script builds the B1-B6 proxy configs dynamically because the temporary
packaged proxy receives a unique package family name and loopback port on each
run. User-facing egress and proxy examples are under
[`tests/examples/processcontainer/networking`](../../../examples/processcontainer/networking/README.md).
