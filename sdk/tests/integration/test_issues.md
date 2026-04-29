# Known Test Issues

## Store Python fails in AppContainer and BaseContainer

Store Python App Execution Alias reparse points can't be resolved inside sandboxes. See #66.

## Proxy tests timeout

Base process container proxy test stalls mid-round-trip when using 0.5.0 schema. Traffic reaches the proxy but times out on external requests.

## LXC network tests fail in CI

LXC containers lack network bridge/NAT config on hosted Ubuntu runners, causing outbound connectivity failures.
