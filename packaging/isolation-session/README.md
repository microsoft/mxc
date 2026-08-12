# IsolationSession packaging

This directory contains the repository-owned packaging inputs used by
`.azure-pipelines/1ES.IsoSession.Artifacts.yml`.

The payload binaries are not built in this repository. The pipeline resolves a
Windows OS `BIN` artifact drop from a BNS `BuildGuid`, downloads the six
required IsolationSession binaries, and then:

1. builds and signs x64 and ARM64 MSI/EXE outputs in parallel;
2. records per-architecture provenance and a shared release contract; and
3. publishes separate x64 and ARM64 installer artifacts.

The SDK NuGet aggregation and publication path is deferred because the BNS
`BIN` drop does not contain the two IsolationSession WinMDs.

## Upstream source

The packaging authoring was imported from:

`onecoreuap\windows\core\isoenvbroker`

| MXC directory | Upstream directory |
|---|---|
| `nuget` | `isoenvbroker\nuget` |
| `installer` | `isoenvbroker\msi` plus `isoenvbroker\src\cli\IsoSessionCli.exe.manifest` |

Only maintained source inputs are copied. Do not add upstream `bin`, `obj`,
logs, or generated packages.

When synchronizing an upstream change:

1. Compare the relevant upstream scripts, WiX authoring, templates, and assets.
2. Reapply MXC's hosted-pipeline changes, including x64/ARM64 parameterization,
   the shared release contract helper, and test signing.
3. Run the tests under each packaging subtree.
4. Update this file with the upstream OS commit or build identity used for the
   synchronization.

Initial import reference: local OS enlistment at
`C:\os\src\onecoreuap\windows\core\isoenvbroker` on 2026-08-06. Replace this
reference with a durable upstream commit identifier before a public release.

## Release status

The current pipeline produces **test-signed installer artifacts only** and
does not publish to NuGet.org or GitHub Releases. Public release requires:

- production signing of the payloads and installers;
- review of the copied license and bootstrapper assets;
- a separate approved public-release pipeline.

A successful build is not evidence that these release gates have been met.
