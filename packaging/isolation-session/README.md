# IsolationSession packaging

This directory contains the repository-owned packaging inputs used by
`.azure-pipelines/1ES.IsoSession.Artifacts.yml`.

The payload binaries are not built in this repository. The pipeline resolves a
Windows OS `BIN` artifact drop from a BNS `BuildGuid`, downloads the seven
required IsolationSession binaries and two WinMDs, generates the month-specific
`IsoSession.manifest`, and then:

1. builds and signs x64 and ARM64 MSI/EXE outputs in parallel, including the
   detached Burn engine and the complete bootstrapper EXE;
2. records per-architecture provenance and a shared release contract;
3. aggregates the two WinMDs and the signed x64 `IsoSessionApp.dll` activation
   shim into `Microsoft.Windows.AI.IsolationSession.SDK`; and
4. publishes the per-architecture installer artifacts plus a combined release
   artifact containing the NuGet, installers, provenance, and release metadata.

The NuGet uses the x64 WinMD pair and signed x64 activation shim consumed by
MXC. ARM64 WinMD hashes remain in release provenance but are not required to
match the independently generated x64 metadata byte-for-byte. The package also
carries the repository-owned reg-free COM activation manifest and a
pipeline-stamped `IsoSessionApp.runtimeversion` sidecar. The sidecar uses the
same underscore runtime token as the MSI registry key.

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

The pipeline supports both test-signed validation artifacts and
production-signed release candidates. Release-candidate runs use MXC's approved
`CP-230012` production signing policy, build and sign once, publish the
immutable pipeline artifacts, and then wait on the configured Azure Pipelines
manual validation and environment approval. Resume and approve those gates only
after supported-SF2 qualification confirms the matching MSI and SDK hashes and
the inbox `IsoSessionCore.dll` contract.

After approval, the same run can publish the SDK to the restricted Azure
Artifacts feed. The production-signed x64 and ARM64 MSI/bootstrapper files
remain internal ADO pipeline artifacts unless `publishMsiToEsrp=true` is
explicitly selected. ESRP CDN publication may create externally accessible
links and therefore remains disabled until that destination is approved for
the intended visibility. The pipeline does not publish to NuGet.org or GitHub
Releases.
