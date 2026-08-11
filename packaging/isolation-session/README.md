# IsolationSession packaging

This directory contains the repository-owned packaging inputs used by
`.azure-pipelines/1ES.IsoSession.Artifacts.yml`.

The payload binaries are not built in this repository. The pipeline resolves a
Windows OS `BIN` artifact drop from a BNS `BuildGuid`, downloads the six
required IsolationSession binaries plus both IsolationSession WinMDs, and then:

1. builds and signs x64 and ARM64 MSI/EXE outputs in parallel;
2. records per-architecture provenance and a shared release contract; and
3. aggregates the signed payloads into one multi-RID
   `Microsoft.Windows.AI.IsolationSession.SDK` NuGet carrying both WinMDs and
   the signed `win-x64` / `win-arm64` `IsoSessionApp.dll` runtime assets.

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
   the shared release contract helper, cross-architecture aggregation, and
   pipeline-owned multi-RID NuGet generation.
3. Run the tests under each packaging subtree.
4. Update this file with the upstream OS commit or build identity used for the
   synchronization.

Initial import reference: local OS enlistment at
`C:\os\src\onecoreuap\windows\core\isoenvbroker` on 2026-08-06. Replace this
reference with a durable upstream commit identifier before a public release.

## Release status

The first pipeline version produces **test-signed pipeline artifacts only**.
It can optionally publish the final SDK package to an internal Azure Artifacts
feed, defaulting to the existing private Dart `Mxc-Azure-Feed`, but it does
not publish to NuGet.org or GitHub Releases.

The SDK NuGet is generated in-pipeline from restricted Windows OS payloads.
Current MXC provenance documentation still says that WinMD is not publicly
redistributable.
Public release therefore requires all of the following:

- documented approval to redistribute the WinMD-containing SDK package;
- production signing of the payloads and installers;
- review of the copied license and bootstrapper assets;
- a separate approved public-release pipeline.

A successful build is not evidence that these release gates have been met.
