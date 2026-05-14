# Phase 6 session notes — 2026-05-14

Scratch notes from the session that produced commits `c5ead11` and
`081ce0c` on top of `cba22a5`. **Delete this file before opening the
phase 6 PR.**

## What landed on the branch

| Commit | Subject |
|---|---|
| `cba22a5` | phase6: install_acls module + `--adjustacls` / `--remove-acls` / `--check-acls` CLI |
| `c5ead11` | phase6: DaclManager::grant_ancestor_traverse + T3 wiring |
| `081ce0c` | phase6: test scripts for ACL perf and LowBox access-check semantics |

## Key design decisions

### Persistent ancestor traverse
`grant_ancestor_traverse` calls `install_acls::add_grant` directly,
which is idempotent (check-before-add via `check_grant`). The grants
are **not** tracked in `self.applied`, **not** removed on Drop, and
**not** in the crash-recovery state file.

The motivation is performance: `SetNamedSecurityInfoW` walks the
target's descendants on every call. On a 332k-file subtree
(`AppData\Local`), a cold add takes ~800 ms; a warm
add-via-check_grant takes ~20 ms (~40× speedup). Without
persistence, every wxc-exec startup would pay the cold cost.

The walk stops at the first ancestor where `WRITE_DAC` is unavailable
(system-owned). Coverage past that point is the admin's job via
`wxc-exec --adjustacls`.

### Cleanup matrix

| Grant | `self.applied`? | Drop removes? | Crash recovery? |
|---|---|---|---|
| `SID:(rw)` / `SID:(r)` on policy leaves | yes | yes | yes |
| `SID:(deny)` on denied paths | yes | yes | yes |
| `SID:(traverse)` on user-owned ancestors | **no** | no | no |

## Security analysis

### Cross-user attack (deterministic SIDs) — NOT viable

User worried about: attacker creates an AppContainer with the same name
as a previous victim's AppContainer, gets the same deterministic SID,
inherits any persistent grants on the victim's files.

Settled empirically via `test_scripts/Test-LowBoxSidOnlyAccess.ps1`
(uses `NtCreateLowBoxToken` + `AccessCheck`, no admin needed). Five
DACL configurations against a LowBox token:

| DACL | `AccessCheck` for `FILE_GENERIC_READ` |
|---|---|
| `SY:FA + AppContainerSID:FR` | **DENIED** |
| `SY:FA + AU:FR + AppContainerSID:FR` | GRANTED |
| `SY:FA + AU:FR` (no SID) | **DENIED** |
| `SY:FA` only | DENIED |
| `AAP:FR` only | DENIED |

Confirms the two-check model: the standard-token side and the
LowBox-restricted side must **independently** find a matching Allow
ACE. The cross-user attacker's process never appears on the victim's
standard side, so the standard check fails before the SID match
matters. Persistent ancestor-traverse ACEs are safe from this attack.

### Sequential same-name attack — safe
- Normal exit: `Drop::restore()` removes all `self.applied` entries
  (the dangerous leaf grants).
- Crashed exit: `recover_orphaned_state()` runs unconditionally at
  every wxc-exec startup (main.rs:399), reaps any state file whose
  PID is dead, restores its ACEs.
- The only thing that persists across runs is `FILE_TRAVERSE` on
  user-owned ancestors. Traverse alone confers nothing the user
  doesn't already have on their own directories.

### Concurrent same-name attack — RESIDUAL HOLE
- Run A (legit) is alive with state file PID-A, has granted
  `SID-of-MyApp:(rw)` on `projectA`.
- Run B (attacker) starts. Recovery sees PID-A alive → skips it.
  Run B applies its own grants in a separate state file (PID-B).
  Same containerId → same SID.
- Run B's AppContainer process gets `SID-of-MyApp` and can read
  `projectA` — beyond its own policy.

Attacker must run as the same user, so the practical exposure is
narrow (paths the user can't directly reach but an admin granted to a
specific AppContainer SID, or sub-sandbox scenarios where the attacker
can invoke wxc-exec but not touch the FS directly).

**Phase 6 does not introduce this hole** — leaf grants leak the moment
they're applied, regardless of whether ancestor grants are persisted.

#### Proposed mitigations (deferred to a future phase)
1. **Refuse concurrent same-containerId**: at startup, scan state
   files for a live PID with matching `container_id`; abort. Simple
   but kills the legitimate parallel-run case.
2. **Per-invocation nonce on the AppContainer name**: internal name
   becomes `{container_id}-{nonce}`. SID derives from that. Concurrent
   runs are independent. Cost: profile dirs under
   `AppData\Local\Packages\` accumulate — needs a janitor.
3. **Both** (1) and (2) as defense in depth.

Recommendation: option 2 + startup janitor. Preserves parallel-run
capability and doesn't depend on PID-liveness for correctness.

## Open work tracked by tasks

- #6 — Add Phase-T3Enumeration sub-test to `Win25H2Safe-Tests.ps1`
- #7 — Update threat-model doc to reflect post-fix state (must also
  cover the concurrent same-name residual hole and the chosen
  mitigation path)
- #8 — Open PR for phase 6 (base = `phase5_no_tier2`)

## Performance numbers worth retaining

From `test_scripts/Measure-AclIdempotence.ps1` against a 332k-file
subtree:

| Operation | Cold | Warm |
|---|---|---|
| `wxc-exec --adjustacls` | ~822 ms | ~20 ms |
| `wxc-exec --remove-acls` | ~800 ms | (no Windows-level shortcut) |
| raw `Set-Acl` add | ~822 ms | ~822 ms (no shortcut) |

From `test_scripts/Measure-AclWalkCost.ps1`:
- Walk cost is ~0.1 ms per object regardless of inheritance flag.
- `(OI)(CI)` and `None` inheritance flags have effectively identical
  Set-Acl cost on directory trees of this shape.

## Why I switched away from the filesystem-based access-check test

`Investigate-T3AppContainerSidAccess.ps1` (kept on the branch for
reference) was the first attempt: create a real file with a stripped
DACL, spawn a real AppContainer process, observe whether it can read.
It needs `ALL APP PKGS:(X)` on the drive root for traversal — the
non-admin shell I had can't add that, and the auto-classifier blocks
the agent from adding it. So I pivoted to the in-memory
`NtCreateLowBoxToken` + `AccessCheck` approach
(`Test-LowBoxSidOnlyAccess.ps1`), which answers the same question
with no filesystem, no process spawn, and no admin needed.
