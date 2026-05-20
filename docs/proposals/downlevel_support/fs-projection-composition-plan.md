# Downlevel FS projection — composition plan

**Status**: draft / pre-spike
**Owner**: gudgmi (with Copilot CLI as pair)
**Branch**: `user/gudge/downlevel-fs-projection-plan`
**Floor**: Windows 11 23H2 (`NTDDI_WIN10_CU`)

This document is the engineering plan agreed at end-of-day 2026-05-20.
It is intended to be read cold the next morning and acted on.

## Resuming the Copilot CLI session

The full derivation of this plan lives in Copilot CLI session
`d739a782-d102-4c2b-b4f9-31b461abef5a`. To resume tomorrow:

```
copilot --resume d739a782-d102-4c2b-b4f9-31b461abef5a
```

Or pick from the interactive list:

```
copilot --resume
```

(If the id has expired locally, this doc is self-contained — just
hand it to a fresh session as context and pick up from the
`## Two-day plan` section.)

## TL;DR

- BFS is unsafe on 25H2 (`bfscfg.exe` hard-locks the box). Quarantine it.
- Replace it with a **composition** of three primitives on 23H2+:
  - **AppContainer** for the security boundary, identity, and network.
  - **bindflt** as the naming layer. It does the bulk of the work:
    direct R/W identity binds for writable subtrees, direct R/O
    identity binds for AAP-readable system roots (`C:\Windows`,
    `Program Files*`, `ProgramData`, `Users\Public`).
  - **ProjFS** with a provider hosted inside `wxc-exec.exe`, used
    **only** for the non-AAP-readable residual (user profile,
    custom paths) — the BFS replacement primitive, scoped tightly.
  - Plus tiny owner-side **DACL grant ACEs** on the writable roots
    (paths the user already owns) and a deny ACE on any in-RW
    deny path.
- This composition is one rung on a capability-driven decision model
  (see `## Selection model`), not a fixed tier. Other compositions
  remain available for hosts without ProjFS, callers who refuse
  user-mode brokers in the TCB, etc.
- Path identity is preserved: inside the container, `C:\Windows\…`
  looks like `C:\Windows\…` and `C:\etc\src\git\myrepo\…` looks like
  `C:\etc\src\git\myrepo\…`.
- **Performance** is native for the R/W and AAP-readable cases (no
  copy, no upcall). Only the brokered residual pays ProjFS's
  cold-first-touch tax, and only on disk-materialized files within
  that residual. See `## Performance and disk-space model`.
- **A machine-readable backend-capability profile** (versioned
  JSON under `schemas/.../container-capabilities/`) feeds the
  selector and the SDK so that "what does this container see by
  default" is auditable, testable, and per-Windows-version
  variant-able. See `## Backend capability profiles`.
- Two-day plan below builds a hand-driven proof-of-concept and an
  updated productization roadmap. Two-day plan is **not** shippable
  code — productization is a separate phase estimated at 2–3 weeks.

## Why this composition

We arrived at this through a sequence of eliminations:

1. The current downlevel chain (T1 BaseContainer → T2 AppContainer+BFS
   → T3 AppContainer+DACL) has a P0: T2's `bfscfg.exe` hard-locks
   25H2 hosts; the fix in `c:\etc\src\os\src\onecore\ds\security\
   isolation\broker\fs` has not been serviced downlevel.
2. Substituting bindflt for BFS as a like-for-like swap looked
   appealing, but bindflt is a **naming layer only** — it does not
   broker access. The AppContainer's package SID is still the
   principal at the backing file; reads of arbitrary user-profile
   files still fail because the AAP SID isn't on their DACLs. BFS
   used to mask this with its broker; bindflt cannot.
3. Solving the broker problem with permanent host ACL grants
   (current T3) has the well-known `WRITE_DAC`-on-every-ancestor
   problem and a huge blast radius.
4. ProjFS (`gvflt` in the OS tree) is, structurally, BFS with the
   policy moved into user mode. The kernel filter ships with
   Windows; the provider is ours. Hosting the provider inside
   `wxc-exec.exe` gives us the BFS broker property under code we
   own and can service, without a kernel-mode dependency.
5. The path-identity requirement means we still need a naming layer
   on top: bindflt redirects the AppContainer's view of `C:\` into
   the ProjFS virt root, and overlays the writable subtrees as
   direct identity binds (which therefore bypass ProjFS entirely
   for the write path).

The earlier conversation (kept in the session transcript) walks
through bindflt-alone, custom-broker, and isolated-local-user
alternatives. The composition above scored best on the example
policy because it satisfies the "wide read" clause without
permanent host mutation, preserves path identity, and keeps the
existing AppContainer/WFP/integrity story intact.

## The composition, concretely

**Routing principle**: ProjFS is only used for paths the
AppContainer cannot natively read (i.e. not covered by the
`ALL APPLICATION PACKAGES` ACE). Paths that AAP already grants
get a direct bindflt R/O bind (or no bind at all — see below), so
they skip the broker entirely. ProjFS handles the residual —
primarily user-profile and other user-owned trees.

For one container run, the runtime does:

1. **Create AppContainer SID + Job.** Existing repo code.
2. **Probe the AAP-readable set** for the paths the policy
   touches. For v1 we use a curated allowlist of known
   AAP-readable roots: `%SystemRoot%`, `%ProgramFiles%`,
   `%ProgramFiles(x86)%`, `%ProgramData%`, `C:\Users\Public`.
   Anything else the policy says should be readable falls to
   the brokered path. (A future refinement is a runtime
   `AccessCheck` probe per policy path so we don't have to
   hardcode the allowlist.)
3. **Create a private virt root** at
   `%LOCALAPPDATA%\Microsoft\MXC\runs\<run-id>\virt\`. ACL it to
   give the AppContainer package SID traverse + read.
4. **Start ProjFS** rooted at the virt directory. Provider lives
   on threads inside `wxc-exec.exe` under the real user's token.
   Implements:
   - `GetPlaceholderInfoCallback` / `GetFileDataCallback` — maps
     the virt-relative path back to the corresponding host path
     (under the *brokered* roots only), opens under user identity,
     streams bytes.
   - `StartDirectoryEnumerationCallback` /
     `GetDirectoryEnumerationCallback` — enumerates the host
     directory, **omitting** any R/W subtree paths that the
     bindflt overlay covers (so they don't appear twice).
   - Refuses writes (returns `ACCESS_DENIED` from notification
     callbacks). The R/W story is handled by bindflt direct
     binds, not by ProjFS.
   - Honors a small allowlist/denylist passed at start (e.g.
     refuse `C:\temp\logs` materialization to enforce a deny on
     a non-existent path).
5. **Install bindflt mappings**, per-Job, in priority order
   (more-specific wins):
   - **R/W identity binds** for each R/W subtree:
     `C:\etc\src\git\myrepo` → `C:\etc\src\git\myrepo`,
     `C:\Users\<u>\temp` → `C:\Users\<u>\temp`,
     `C:\Users\<u>\Documents\workinprogress` → identity, with
     `…\private` in the exception list when the policy denies it.
   - **R/O direct binds** for the AAP-readable roots:
     `C:\Windows` → `C:\Windows`,
     `C:\Program Files` → `C:\Program Files`,
     `C:\Program Files (x86)` → `C:\Program Files (x86)`,
     `C:\ProgramData` → `C:\ProgramData`,
     `C:\Users\Public` → `C:\Users\Public`.
     These are identity binds with `BINDFLT_FLAG_READ_ONLY_MAPPING`;
     no ProjFS hop, no copy, no cold tax. The AppContainer's
     existing AAP token gating decides what's actually readable
     within each root.
   - **ProjFS-redirected binds** for the brokered residual that
     the policy says should be readable but AAP can't grant:
     `C:\Users\<u>` → `<virt>\Users\<u>` R/O,
     plus an exception list pointing to the R/W subtrees inside
     `C:\Users\<u>` so those keep their identity-bind behaviour.
     For the example policy this is the only ProjFS-routed bind.
6. **Add small grant ACEs** for the AppContainer package SID on
   each R/W root. Tracked in the existing `filesystem_dacl`
   crash-restore bookkeeping. Plus a single deny ACE on
   `…\workinprogress\private` (or wherever the in-RW deny lives).
7. **Spawn the child** into the AppContainer + Job.
8. **Teardown**: child exits → job closes → bindflt mappings
   auto-removed → `PrjStopVirtualizing` → delete virt root →
   revoke the grant/deny ACEs.

The net effect: `C:\Windows`, `C:\Program Files*`, `C:\ProgramData`,
`C:\Users\Public` reads go straight to NTFS through bindflt with
zero copies and zero provider involvement. Only the user-profile
(and any other policy-required non-AAP-readable trees) go through
the ProjFS broker. Path identity is preserved everywhere.

### Path resolution table (the demo we want to drive)

| Container call | bindflt result | ProjFS? | Backing op | Expected |
|---|---|---|---|---|
| `CreateFile C:\Windows\System32\kernel32.dll` | identity R/O bind `C:\Windows` | **no** | direct NTFS open; AAP grants the read | read OK, native perf |
| `CreateFile C:\Program Files\Git\cmd\git.exe` | identity R/O bind `C:\Program Files` | **no** | direct NTFS open; AAP grants the read | read OK, native perf |
| `CreateFile C:\Users\<u>\.gitconfig GENERIC_READ` | `C:\Users\<u>` → `<virt>\Users\<u>` (R/O) | yes | provider opens real file as user | read OK even though AppContainer SID has no ACE on it |
| `CreateFile C:\Users\<u>\.gitconfig GENERIC_WRITE` | same | yes | provider returns `ACCESS_DENIED` | write blocked |
| `CreateFile C:\Users\<u>\AppData\Local\Programs\dev-tool\bin\foo.exe` | same `C:\Users\<u>` bind | yes | provider brokers | read OK |
| `CreateFile C:\etc\src\git\myrepo\src\main.rs RW` | identity R/W bind (most specific) | no | direct NTFS open; package SID grant ACE allows | works, native perf |
| `CreateFile C:\Users\<u>\temp\out.log RW` | identity R/W bind (more specific than the `C:\Users\<u>` ProjFS bind) | no | direct write to host | works, native perf |
| `CreateFile C:\Users\<u>\Documents\workinprogress\private\secret.txt` | identity R/W bind on `workinprogress` with `private` in exception list; falls through; underlying `C:\Users\<u>` ProjFS bind also has `…\private` denied | yes, then refused | provider denies (allowlist) + deny ACE on the path | fails |
| `CreateFile C:\NonExistent\x.txt CREATE_NEW` | no bind matches a path outside our covered set; raw host | no | AppContainer SID has no write; AAP doesn't grant write | fails (`ACCESS_DENIED` at NTFS) |
| `git status` in the repo | combination | mixed | walks `.git` (R/W bind, direct), reads ambient git/system files (R/O bind, direct), reads `.gitconfig` (ProjFS) | works |
| Create `C:\temp\logs` from container | no bind matches; raw host | no | AppContainer can't write `C:\temp` (no ACE); creation fails at NTFS | fails |

## Performance and disk-space model

### How ProjFS actually serves a read

ProjFS is **not** a handle pass-through. It is a kernel-mode
lazy-hydration cache backed by a user-mode provider.

The data flow for the very first read of, e.g.,
`C:\Windows\System32\kernel32.dll` from inside the container:

1. The AppContainer issues `CreateFile` for `C:\Windows\System32\
   kernel32.dll`. bindflt rewrites the path to
   `<virt>\Windows\System32\kernel32.dll`.
2. NTFS sees a *placeholder* in the virt root — a tiny stub file
   with a reparse tag. The ProjFS kernel filter intercepts.
3. The filter upcalls our provider's `GetPlaceholderInfoCallback`
   (so we can supply metadata if the placeholder didn't yet
   exist), then `GetFileDataCallback` for the requested byte range.
4. The provider, running in `wxc-exec.exe` under the real user's
   token, calls `CreateFile` on the **real host file**
   `C:\Windows\System32\kernel32.dll`, reads the bytes into a
   buffer, and returns them via `PrjWriteFileData`.
5. The kernel filter writes those bytes into the on-disk virt-root
   file as a side effect, transitioning the placeholder to a
   *hydrated* file (full or partial — ProjFS supports per-range
   hydration).
6. The AppContainer's read completes.

The provider's host-file handle is opened and closed inside the
provider. **No handle ever crosses a process boundary.** The bytes
do cross — through user-mode memory in the provider, into the
kernel via `PrjWriteFileData`, onto NTFS in the virt root, and
back out to the AppContainer's read.

### Subsequent reads

Once a byte range has been hydrated:

- The placeholder file in the virt root contains real bytes.
- Subsequent reads (this run, or later runs if we keep the virt
  root) come straight from NTFS via the page cache.
- **The provider is not involved.** No upcall, no user-mode round
  trip, no extra copy.

So the cost model is:

- **First touch of a file**: one provider upcall + one host read
  + one virt-root write + the AppContainer's read. Roughly
  1–10 ms per file depending on size and disk; small files are
  dominated by the upcall round-trip, large files by I/O.
- **First touch of a directory listing**: one provider upcall pair
  (`StartDirectoryEnumeration` + `GetDirectoryEnumeration`) for
  the directory; subsequent enumerations come from the virt-root
  directory itself.
- **Subsequent reads (warm)**: indistinguishable from a regular
  NTFS open of an already-cached file. Same throughput as native.

ProjFS callbacks are dispatched on a pool of provider threads by
default, so multiple concurrent upcalls are served in parallel —
single-threaded provider code would be a bottleneck but is not
the design.

### Disk-space implications

Every file the container reads **through ProjFS** becomes a real
materialized copy in the virt root. Because ProjFS only covers
the non-AAP-readable residual (mainly user-profile) in our v1
composition, the materialized footprint is much smaller than
"every system DLL we open". Rough estimates for dev workloads:

| Workload class | What goes through ProjFS | Materialized footprint |
|---|---|---|
| `pwsh.exe` startup | Just the user's PowerShell profile, module manifests under `$HOME\Documents\PowerShell` (PowerShell binaries themselves come via the direct R/O bind on `Program Files`) | a few MB |
| `git status` / `git log` | `.gitconfig`, `.ssh\known_hosts` if read; the repo itself is R/W direct | < 1 MB |
| `cargo check` | `~/.cargo/config.toml`, `~/.cargo/registry` indices/cache **if read R/O via ProjFS** (registry is often a R/W bind instead) | tens of MB if registry brokered, near-zero if registry is R/W bound |
| `msbuild` of a C++ project | `~/.nuget/packages` if not R/W bound; user-installed VS extensions | tens to low hundreds of MB |
| `npm install` | `.npmrc`; cache dir if not R/W bound | tens of MB if cache brokered |

System DLLs, Windows SDK headers, MSVC toolchain, Node runtime,
Git install, etc. do **not** materialize through ProjFS — they're
served by direct bindflt R/O binds on `Program Files` /
`Windows`. That removes the biggest source of disk pressure the
naïve "route all of C:\" design would have had.

**Two consequences**:

1. **Per-run cleanup is mandatory.** On teardown we
   `PrjStopVirtualizing` and recursively delete the virt root.
   Footprint per run is small enough that this is cheap.
2. **Cross-run virt-root reuse is a smaller win than it would be
   under the naïve design**, because the dominant first-touch
   tax (system DLLs) is already eliminated. Still worth doing
   for repeated agent invocations against the same user profile,
   but probably not P2 — defer to P3 or later.

### Performance expectations for the listed workloads

Concrete, bracketed estimates (subject to validation in the
Day 2 stretch). These assume the v1 composition: AAP-readable
system roots served by direct bindflt R/O (no provider), only
user-profile served by ProjFS provider.

- **Cold run of `pwsh -Command "git status"` in a real repo**:
  perhaps 50–200 ms additional latency vs. native, dominated by
  the handful of user-profile config reads (`.gitconfig`,
  PowerShell profile, etc.) going through the provider. `pwsh.exe`
  and `git.exe` and their DLL closures load through the direct
  R/O bind — no provider involvement, native cost.
- **Warm second run of the same**: within 1–5% of native.
- **Cold `cargo check` of a medium crate**: 200 ms–2 s additional
  cold-read tax for `~/.cargo/config.toml` and any registry
  metadata that's read R/O. The Rust toolchain itself — if
  installed via rustup under `~/.cargo` or `~/.rustup` — would
  be R/W bound (since cargo updates it), so it skips ProjFS.
  Warm runs: near-native.
- **Cold `msbuild` of a meaty C++ project**: the worst case in
  v1 is `~/.nuget/packages` if it's read-only-brokered (i.e. not
  in the R/W bind list). Best to bind `.nuget` R/W since msbuild
  mutates it; then the cold tax shrinks to user-installed VS
  extensions and a few config files. Probably 500 ms–3 s on a
  cold first run, near-native warm.

These are educated guesses, not measurements. Day 2's stretch
goal is to capture real numbers and replace this section with them.

### Comparison of the path classes

| Path class | Mechanism | Cold cost | Warm cost | Disk cost |
|---|---|---|---|---|
| R/W subtree (repo, temp, scratch, NuGet cache if R/W bound, etc.) | bindflt identity bind + grant ACE | zero — direct NTFS | zero — direct NTFS | zero |
| AAP-readable system root (`C:\Windows`, `Program Files*`, `ProgramData`, `Users\Public`) | bindflt identity R/O bind | zero — direct NTFS | zero — direct NTFS | zero |
| Non-AAP-readable R/O tree included in policy (user profile, etc.) | bindflt → ProjFS provider | one upcall round-trip per first-touched file | direct NTFS from virt root | size of touched-files set in that tree, until teardown |
| Path explicitly excluded by policy | bindflt exception + provider denylist + deny ACE | n/a | n/a | zero |
| Path outside any policy scope | no bind; raw host | zero | zero | n/a (fails at AppContainer ACL check) |

### Tuning knobs we can apply later

If measured performance is worse than the bracketed estimates,
levers in order of likely effectiveness:

1. **Add more roots to the direct R/O bind set.** If a workload
   touches large amounts of user-installed content that doesn't
   need brokering (e.g. a user-installed SDK whose files are
   AAP-readable because their installer set them that way), bind
   it directly and skip ProjFS for those reads.
2. **Eager pre-hydration on container start** for a "warm set" of
   commonly-touched user-profile paths (`.gitconfig`, `.cargo/
   config.toml`, etc.). Trades a few ms of startup for first-call
   latency on those exact files.
3. **Cross-run virt-root cache**. Lower priority than under the
   naïve design but still useful for agents that re-run repeatedly
   against the same profile.
4. **Range-hydration tuning** — `PrjWriteFileData` can serve
   partial ranges; ProjFS supports it. Whether we benefit depends
   on what tools actually read partially vs. whole-file.
5. **Provider thread-pool sizing** — default is reasonable but
   tunable.
6. **Runtime `AccessCheck`-based AAP probe** to discover the
   AAP-readable set dynamically rather than hardcoding the roots.
   Removes a class of "we bound it through ProjFS even though AAP
   would have allowed it natively" cases.

## Selection model (capability-driven)

We are **not** building a fixed ladder. The selector at runtime
takes (host capabilities) + (policy requirements) and picks the
minimum-surface combination of primitives that satisfies the
policy.

- "More primitives" is not "more secure" — ProjFS adds a user-mode
  broker in the TCB; we don't add it if the policy doesn't need
  brokered reads.
- The composition described above is one *result* of the selector
  for one *class* of policies (those needing wide reads).
- For a policy that only needs R/W on a repo with no wide reads,
  the selector should return `AppContainer + bindflt + grant ACE`
  and skip ProjFS entirely.
- For a host without ProjFS, the selector falls back to
  `AppContainer + bindflt + curated-read-set ACEs` (degraded
  policy: caller must accept a narrower read set, surfaced via a
  structured `DegradationReason`).
- A caller-side `minimum_acceptable_security` (set of capability
  predicates, not a tier letter) lets the caller refuse runs that
  the host can't meet.

Selection algorithm (pseudo):

```
1. Probe host: { ProjFS present?, bindflt available?, AppContainer
   profile creatable?, WRITE_DAC on each policy path?, ... }
2. Load backend-capability profile (see next section) for each
   backend the host supports.
3. Lower policy: { wide_read_needed?, write_roots[], deny_paths[],
   network_policy, ... }
4. For each backend × policy pair, compute the residual: the set
   of policy reads the backend's principal can't satisfy from its
   default-grant set. The residual is what needs brokering or
   ACEing.
5. Enumerate primitive subsets that cover every requirement
   (including the residual).
6. Score each by attack-surface + host-mutation + reversibility.
7. Pick lowest-cost; report chosen + rejected with reasons.
8. If none cover: structured failure naming the un-coverable
   requirements.
```

## Backend capability profiles (machine-readable)

The "residual" calculation in step 4 above needs to know what
each backend's principal gets by default. Encoding that as
versioned JSON (or TOML) rather than hardcoding it in Rust has
several upsides:

- **Selector input is auditable.** A reviewer can see exactly
  what assumptions about AAP-readability we baked in, without
  reading the Rust.
- **Per-Windows-version variants** can ship without recompiling
  the binary. Stock AAP grants drift between OS releases (and
  occasionally between cumulative updates); a JSON file can hold
  multiple `windowsBuildRange`-tagged variants.
- **The SDK can surface this to callers** as part of the
  "what your container will see by default" contract — far more
  useful than prose docs that fall out of date.
- **Tests can verify it.** A probe runner on a clean Win11 image
  can assert that each path in `defaultRead.roots` is in fact
  readable by an AppContainer with no extra capabilities. CI
  detects drift before users do.

### Location and shape

Proposed location, matching the existing `schemas/` convention
(see `docs/versioning.md`):

```
schemas/dev/container-capabilities/<backend>.schema.<version>.json
schemas/stable/container-capabilities/<backend>.schema.<version>.json
```

with one file per (backend, schema-version):

- `appcontainer.schema.0.1.0-alpha.json`
- `base-container.schema.0.1.0-alpha.json`
- `isolation-session.schema.0.1.0-alpha.json`
- `windows-sandbox.schema.0.1.0-alpha.json`
- `lxc.schema.0.1.0-alpha.json`
- `seatbelt.schema.0.1.0-alpha.json`

The JSON schema in `schemas/dev/container-capabilities-meta/`
defines the contract every per-backend file conforms to.

### Sketch of the AppContainer profile

```jsonc
{
  "$schema": "https://example/schemas/dev/container-capabilities-meta/0.1.0-alpha.json",
  "backend": "appcontainer",
  "version": "0.1.0-alpha",
  "windowsBuildRange": { "min": "10.0.22631", "max": "10.0.26100" },
  "description": "Default capability floor for an MXC AppContainer principal with no extra capabilities granted, on stock Windows 11 23H2 through 25H2.",

  "principal": {
    "kind": "package-sid",
    "strippedFromToken": [
      "BUILTIN\\Users", "Authenticated Users", "Everyone", "INTERACTIVE"
    ],
    "inheritedGroups": [
      { "sid": "S-1-15-2-1", "name": "ALL APPLICATION PACKAGES" }
    ],
    "integrityLevel": "low"
  },

  "defaultRead": {
    "roots": [
      {
        "path": "%SystemRoot%",
        "grantedVia": "all-application-packages",
        "exclusions": [
          "%SystemRoot%\\System32\\config",
          "%SystemRoot%\\System32\\LogFiles",
          "%SystemRoot%\\CSC",
          "%SystemRoot%\\ServiceProfiles"
        ]
      },
      { "path": "%ProgramFiles%",        "grantedVia": "all-application-packages" },
      { "path": "%ProgramFiles(x86)%",   "grantedVia": "all-application-packages" },
      {
        "path": "%ProgramData%",
        "grantedVia": "all-application-packages",
        "exclusions": [
          "%ProgramData%\\Microsoft\\Crypto",
          "%ProgramData%\\Microsoft\\IdentityCRL"
        ]
      },
      { "path": "%PUBLIC%",              "grantedVia": "all-application-packages" }
    ],
    "knownNotGranted": [
      { "path": "%USERPROFILE%",        "reason": "user-profile DACL is per-user, no AAP ACE" },
      { "path": "%LOCALAPPDATA%\\Programs", "reason": "user-installed tools; user-owned" },
      { "path": "C:\\etc",              "reason": "common dev path; not in default AAP grants" }
    ]
  },

  "defaultWrite": {
    "roots": [
      {
        "path": "%LOCALAPPDATA%\\Packages\\<package-family-name>",
        "grantedVia": "per-package-storage"
      }
    ]
  },

  "defaultNetwork": {
    "egress":   { "default": "denied", "grantableVia": "capability" },
    "ingress":  { "default": "denied", "grantableVia": "capability" },
    "loopback": { "default": "denied", "grantableVia": "capability" }
  },

  "namespaces": {
    "object":    "\\Sessions\\<n>\\AppContainerNamedObjects\\<package-sid>",
    "registry":  "HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\<package-sid>"
  }
}
```

### Who consumes it

1. **The composition selector**, to compute the residual that
   needs brokering and to choose which paths to direct-bind R/O
   vs route through ProjFS.
2. **The SDK**, to expose to callers: "given your policy, here
   is what the container will see by default before any of your
   write/deny clauses are applied".
3. **The structured run-result reporter**, to attribute per-clause
   enforcement decisions back to capability-profile entries
   (e.g. "this read clause was satisfied by `defaultRead.roots[0]`
   on the AppContainer profile — no extra mechanism needed").
4. **A CI verifier**, to probe a clean Windows image and assert
   that every `defaultRead.roots[…]` entry is in fact readable
   and every `knownNotGranted[…]` entry is in fact not. Drift
   detection.
5. **Documentation generation**, to keep
   `docs/base-process-container/guide.md` and similar in sync.

### Maintenance model

- File is checked in. Updates are normal PRs.
- New Windows builds: run the CI verifier against a fresh image;
  if it diverges, file a PR with a new `windowsBuildRange`-tagged
  variant or update the existing entry.
- Schema version bumps follow the same model as
  `mxc-config.schema` (see `docs/versioning.md`): dev under
  `schemas/dev/`, frozen at release under `schemas/stable/`.

### Scope for the two-day probe

Out of scope. The probe hardcodes the AAP-readable root list in
the throwaway binary. The capability-profile file is a
productization-phase artifact (P1.5 in the roadmap — between
BFS quarantine and the ProjFS module work; it's the input the
composition selector needs to exist before the selector itself
is meaningful).

## Two-day plan (starting day after writing)

Goal: prove the composition works on real hardware with real dev
tools, **or** kill it cleanly. Output is a working hand-driven
probe + a productization roadmap. Not shippable code.

### Day 1 — validate each leg in isolation

**Spike A — ProjFS provider, smallest possible.** Highest-leverage
spike: this is the BFS-replacement primitive.

- Probe ProjFS feature state on the box:
  `Get-WindowsOptionalFeature -Online -FeatureName Client-ProjFS`.
  If `Disabled`, enable with
  `Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS`.
- Standalone Rust binary `mxc_projfs_probe.exe` that:
  - Picks `%LOCALAPPDATA%\Microsoft\MXC\probe\virt\` as virt root.
  - Calls `PrjMarkDirectoryAsPlaceholder` + `PrjStartVirtualizing`.
  - Implements minimal `GetPlaceholderInfo` / `GetFileData` /
    `StartDirectoryEnumeration` / `GetDirectoryEnumeration` that
    treat the relative virt path as relative to `C:\` and open
    under our token.
- Drive it (no AppContainer yet — just our normal process):
  - `notepad %LOCALAPPDATA%\Microsoft\MXC\probe\virt\Windows\System32\drivers\etc\hosts`
  - `Get-Content %LOCALAPPDATA%\Microsoft\MXC\probe\virt\Users\<u>\.gitconfig`
  - `dir %LOCALAPPDATA%\Microsoft\MXC\probe\virt\Windows\System32\`
- Pass: file content matches the real host file; directory
  enumeration matches.

**Spike B — bindflt job-scoped overlay.**

- Standalone Rust binary `mxc_bindflt_probe.exe` that:
  - Creates a Job.
  - Calls `CreateBindLink` first (public API). If insufficient,
    fall back to internal `BfSetupFilterEx` from `bindflt_pub.h`.
  - Adds RO bind `C:\probebind` → `C:\Windows` for the Job.
  - Adds RW identity bind `C:\probebind\System32` → a writable
    user-owned scratch dir; grant ACE for current user (this
    spike doesn't need AppContainer SID — we're just verifying
    the layering).
  - Spawns `cmd.exe /K` into the Job.
- Drive interactively in the spawned cmd:
  - `dir C:\probebind` should show Windows contents.
  - `dir C:\probebind\System32` should show scratch contents
    (override wins).
  - `dir C:\probebind` from a *different* console (outside Job)
    should show nothing/error.
- Pass: layering works as designed; per-Job scoping confirmed.

**Spike C — AppContainer + ProjFS interaction.**

- Reuse existing AppContainer creation code from `wxc_common`.
- Manually wire: create AppContainer SID, ACL Spike A's virt root
  to grant the package SID traverse+read, spawn `cmd.exe` into
  the AppContainer (no Job/bindflt yet), and try the same opens
  from inside.
- Pass: AppContainer can read files via the provider. This is the
  critical "does the broker actually solve the wide-read problem
  on AppContainer" check.

End of Day 1: three independent passes, or a clear written
explanation of which leg failed and what we'll do about it.

### Day 2 — compose and capture

**Compose into a single probe.**

- `mxc_compose_probe.exe`:
  - Creates AppContainer SID + Job.
  - Starts ProjFS provider (from Spike A code).
  - Installs the bindflt overlay (from Spike B code): `C:\` → `<virt>` RO + per-R/W-subtree identity bind.
  - Adds grant ACEs on the R/W roots (reuse `filesystem_dacl`).
  - Spawns `pwsh.exe` interactively into the AppContainer + Job.
- Drive it through the path-resolution table above. Tick off each
  row; record any deviation.

**Stretch: real dev workload.**

- Inside the spawned pwsh, run:
  - `git status` in `C:\etc\src\git\<a real repo>` (R/W bound)
  - `git log --oneline -5`
  - `cargo --version` (and if there's time: `cargo check` in a
    small Rust crate)
  - `node --version`, `npm --version`
- Capture first-touch latency for cold reads.
- Note any tool that fails and why.

**Write up.**

- Update this document's `## Findings` section (currently empty)
  with what actually happened: what worked, what surprised us,
  what's the next plan.
- Update `## Productization roadmap` with concrete work items and
  size estimates based on the spike code.

### Explicitly NOT in two days

- Changes to `wxc-exec.exe`'s main runloop / dispatcher
- New public modules in `wxc_common` (the probes live in
  `playground/` or similar, not under `src/`)
- The composition/selection logic in `fallback_detector`
- Structured result/error reporting
- Crash recovery / leak cleanup for the provider
- E2E tests in `wxc_e2e_tests` or the test driver
- SDK or CLI surface changes
- BFS quarantine code change (separate, smaller, parallelizable —
  see `## BFS quarantine` below)

## Two-day risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `CreateBindLink` public API lacks per-Job/exception-list scoping | Medium | Half-day pivot to internal `bindflt_pub.h` (extra build-system work) | Try public API first; have the internal header ready |
| ProjFS optional feature off on the dev box | High | 10 minutes to enable; raises deployment Q for productization | DISM enable on Day 1 morning; note in productization plan |
| AppContainer ↔ ProjFS surprise interaction (token denial inside provider open, IL check on virt root, `ERROR_REPARSE`) | Medium | Half-day debug | Day 1 Spike C catches this early; build in slack |
| ProjFS provider perf is unacceptable on cold dev workload | Low (medium-term) | Doesn't block the demo; productization Q | Note for productization; consider pre-warm strategy |
| Probe-to-productization gap larger than expected (e.g. we need real concurrency in the provider) | Medium | Adds to productization estimate, not to two-day demo | Time-box probe; don't over-engineer |

## Findings

*To be filled in at end of Day 2.*

- [ ] Day 1 Spike A result
- [ ] Day 1 Spike B result
- [ ] Day 1 Spike C result
- [ ] Day 2 composition probe result
- [ ] Day 2 stretch (real dev workload) result
- [ ] Surprises and gotchas
- [ ] Decision: green / yellow / red for productization

## Productization roadmap (post-probe)

*To be refined at end of Day 2 based on findings.* Rough shape:

- **Phase P1 (≈ ½ week)**: BFS quarantine (see below). Smallest,
  most urgent.
- **Phase P1.5 (≈ 3 days)**: Backend capability profiles —
  `schemas/dev/container-capabilities-meta/0.1.0-alpha.json`
  defining the contract, plus per-backend files (`appcontainer.
  schema.0.1.0-alpha.json` at minimum; others can come later as
  the corresponding backends gain capability-driven selection).
  CI verifier that probes a clean image and asserts the
  `defaultRead.roots` set is actually AAP-readable and the
  `knownNotGranted` set is not. This artifact is the input the
  P4 composition selector needs to exist.
- **Phase P2 (≈ 1 week)**: `wxc_common::filesystem_projfs` Rust
  module — provider, callback registration, policy table, path
  canonicalization, crash cleanup. This is the security-critical
  module; expect more review cycles than line count suggests.
- **Phase P3 (≈ 3 days)**: `wxc_common::filesystem_bindflt` Rust
  module — thin wrapper over `CreateBindLink` / `BfSetupFilterEx`
  with job-scoped lifetime.
- **Phase P4 (≈ 3 days)**: composition layer in `fallback_detector`
  — replace linear tier enum with capability-driven selector that
  consumes the P1.5 capability profiles and the host probe.
  Keep `IsolationTier` as a display-only summary for telemetry.
- **Phase P5 (≈ 2 days)**: structured result/degradation reporting
  through to the SDK (`MxcError` extensions, new `ErrorCode`
  variants `ProjFsUnavailable`, `BindfltSurfaceMissing`,
  `BfsUnsafeOnHost`, `FsCompositionUnsatisfiable`). Result
  includes capability-profile-attributed per-clause enforcement
  decisions.
- **Phase P6 (≈ ½ week)**: `wxc_e2e_tests` covering the new
  composition for representative policies, on 23H2/24H2/25H2.
  Test matrix includes the capability-profile CI verifier from
  P1.5.
- **Phase P7 (≈ 2 days)**: docs — replace the tier narrative in
  `docs/base-process-container/guide.md` with the
  capability-composition model; auto-generate per-backend
  "default container view" tables from the capability profiles;
  new entry in `docs/proposals/downlevel_support/`.

Total: 2–3 weeks of focused engineering for an MVP that ships.

## BFS quarantine (urgent, parallelizable)

Independent of the rest of this plan, and worth landing
immediately:

- Delete the `Tier 2 — AppContainer + BFS` arm from
  `fallback_detector::detect`. Forced selection via
  `MXC_FORCE_TIER=appcontainer-bfs` returns a structured refusal.
- Move `wxc_common/src/filesystem_bfs.rs` behind a default-off
  cargo feature `unsafe-bfs`.
- New `ErrorCode::BfsUnsafeOnHost`.
- Update SDK to surface the new error.
- Update `docs/proposals/downlevel_support/basecontainer-fallback-
  plan-v2.md` (referenced from current code but does not yet
  exist) with a red banner; or write that doc fresh as part of
  this change.

Half-day's work. Should not wait for the probe.

## Open questions to settle before productization

- **OQ1**: Is enabling the `Client-ProjFS` optional feature a
  documented MXC prerequisite, or do we auto-enable on install
  (admin)? Affects deployment story.
- **OQ2**: Public `CreateBindLink` vs internal `BfSetupFilterEx`.
  Decided after Spike B. Internal-header dependency is real cost.
- **OQ3**: Does any agent tool we care about open files via
  volume-GUID paths, `\Device\HarddiskVolumeN`, or by file ID,
  bypassing the bindflt naming? AppContainer's SID-based check
  still holds, but the *naming contract* could leak. Investigate
  by running a representative workload under Sysinternals
  `Process Monitor` after Day 2.
- **OQ4**: Does the ProjFS provider need to handle the
  by-file-ID open path? `PrjFillDirEntryBuffer2` and friends
  expose file IDs; if a tool reopens by ID we may need to
  cooperate.
- **OQ5**: How does Defender's real-time scan interact with cold
  reads through the provider? Performance + log-noise.
- **OQ6**: Concurrent runs sharing a virt-root parent: any
  collision? Use per-run-id subdirectory (already planned).
- **OQ7**: Backend capability profile maintenance: build a CI
  verifier that compares the profile against a clean Windows
  image, run it on every supported build (23H2, 24H2, 25H2 at
  minimum). Where does the test image come from — internal CI?
  Public Win11 ISO? Defines who owns drift detection.
- **OQ8**: Does the capability profile need to model
  capabilities other than filesystem (registry namespaces,
  WinRT capabilities, RPC endpoints, etc.) in v1, or do we
  scope it to FS for the MVP and grow later? Lean: FS-only in
  v1; the schema is extensible so growth is additive.

## References

- Existing code:
  - `src/wxc_common/src/fallback_detector.rs` — current linear
    tier selector
  - `src/wxc_common/src/filesystem_bfs.rs` — to be quarantined
  - `src/wxc_common/src/filesystem_dacl.rs` — reused for grant ACEs
  - `src/wxc_common/src/appcontainer_runner.rs` —
    AppContainer creation
  - `src/wxc_common/src/base_container_runner.rs` — confirms
    BaseContainer FS is OS-owned (FlatBuffer to
    `Experimental_CreateProcessInSandbox`)
- Windows source (for cross-checking primitive behaviour):
  - `C:\etc\src\os\src\onecore\base\fs\gvflt\` — ProjFS source
    (`api\projectedfslib.h`, `filter\filter.c`)
  - `C:\etc\src\os\src\onecore\base\fs\wci\bindflt\` — bindflt
    source (`filter\mapping.c` for per-Job/SID behaviour)
  - `C:\etc\src\os\src\onecore\base\fs\wci\inc\bindflt_pub.h` —
    internal user-mode bindflt API (`BfSetupFilterEx`)
  - `C:\etc\src\os\src\onecore\base\fs\wci\inc\bindlink.h` —
    public bindflt API (`CreateBindLink`)
  - `C:\etc\src\os\src\onecore\ds\security\isolation\broker\fs\` —
    BFS source (reference for what the broker model used to do;
    fixes here have not been serviced downlevel)
- Conversation transcript (session
  `d739a782-d102-4c2b-b4f9-31b461abef5a`) walks through the full
  derivation: bindflt-only → broker-needed → ProjFS → composition
  → capability-driven selection.
