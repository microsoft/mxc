# MXC consumer glossary

> **Audience:** MXC consumers

Terms used in the [SDK reference](api-reference/README.md) and [configuration guide](schema.md). Internal terms: [developer glossary](development/glossary.md).

| Term | Meaning in MXC | Example |
|---|---|---|
| Container | Isolated environment in which a command or program runs. | Process isolation, Linux container, user session, or VM. |
| Backend | MXC implementation of a container technology. | Bubblewrap on Linux. |
| Workload | Command or program running inside the container. | `node -e "console.log('hello')"` |
| Policy / config | Access rules enforced by the container. | `FilesystemPolicy`: readable, writable, and denied paths. |
| **Create-and-run** \(transient\) | Setup, execute, and cleanup all in "one-shot". | Node V1 `run` or `spawn`. |
| **Lifecycle** \(persistable\) | Provision, start, execute, stop, and deprovision. | [Container Lifecycle operations guide](container-lifecycle.md). |
| Persistent / transient container | Retained between calls / cleaned up after a run. | Neither promises survival across host reboots. |
| Provision / deprovision | Allocate / release container resources. | `provisionContainer` / `deprovisionContainer`. |
| Container identity / opaque ID | Provisioned container's `ContainerId`; pass unchanged, never parse or construct it. | Provision returns it; later operations take it. |
| **MXC request JSON** | Versioned JSON request format for containment rules and operations. | [Stable `1.0.0` schema](../schemas/stable/mxc-config.schema.1.0.0.json). |
| **\[I\/O model\]** Captured | Full output emitted after program execution. | Node V1 `run`. |
| **\[I\/O model\]** Streaming output | Output collected after completion / readable during execution. | Node V1 `spawn`. |
| **\[I\/O model\]** PTY (pseudoterminal) | Interactive terminal with input, combined output, and resizing. | Node V1 `spawnWithPty`. |
| **\[Networking\]** Host loopback | Container-to-host loopback communication, not access from other machines. | `network.ingress.hostLoopback`. |
