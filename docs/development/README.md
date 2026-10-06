# MXC development documentation

> **Audience:** MXC developers

This section covers MXC architecture, implementation, validation, and planned
work. Consumer documentation remains under `docs/`; start with the
[project README](../../README.md).

## Architecture

- [Repository architecture](architecture/repository-architecture.md)
- [Container lifecycle architecture](architecture/container-lifecycle.md)
- [Versioning design](architecture/versioning.md)
- [Telemetry architecture](architecture/telemetry.md)
- [Telemetry consent design](architecture/telemetry-consent-design.md)
- [IsolationSession one-shot architecture](architecture/backends/isolation-session/oneshot.md)
- [IsolationSession state-aware Rust architecture](architecture/backends/isolation-session/state-aware-rust.md)
- [IsolationSession state-aware TypeScript architecture](architecture/backends/isolation-session/state-aware-typescript.md)

## Build and test

- [CI validation infrastructure](build-and-test/ci-validation-infrastructure.md)
- [Pull request builds](build-and-test/pull-requests.md)
- [Schema code generation](build-and-test/schema-codegen.md)
- [Fuzzing](build-and-test/fuzzing.md)
- [WSLC SDK bindings runbook](build-and-test/wslc-sdk-bindings.md)

## Contributor guides

- [Authoring a new feature](guides/authoring-a-new-feature.md)
- [Diagnostics](guides/diagnostics.md)
- [Adding ProcessContainer OS features](guides/process-container-adding-os-features.md)

## Plans

- [Backend support probe API](plans/backend-support-probe-api.md)
- [Bubblewrap backend feasibility](plans/bubblewrap-backend.md)
- [Linux and WSL roadmap](plans/linux-wsl-roadmap-june-2026.md)
- [Nanvix integration](plans/nanvix-integration.md)
