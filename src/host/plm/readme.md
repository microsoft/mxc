# PLM - Permissive Learning Mode

> **Audience:** MXC developers

`plm.exe` is the Windows-only standalone WPR helper for Learning Mode.
`plm log` captures an operator-selected workload interactively; `plm stop`
analyzes an existing ETL. Both use the shared actionable-denial analyzer.
Native ProcessContainer `captureDenials` and `wxc-exec --audit` use the OS
Learning Mode APIs, not a PLM/WPR fallback. See
[native capture support](../../../docs/backends/process-container/os-version-support.md#learning-mode-capture-compatibility).

## CLI

### Interactive capture

```powershell
plm.exe log
plm.exe log --verbose-logging
```

Press Enter to start a host-wide trace, run the selected workload, then press
Enter again to stop. The elevated guardian analyzes the source trace in its
protected scratch directory and returns bounded actionable findings. The
host-wide source ETL does not cross the privilege boundary.

The command synthesizes a blank config, applies the compatibility filesystem
merge, and prints a diff against that blank config. Review generated policy
before using it; permissive Learning Mode records access without enforcing
deny-by-default.

### Existing ETL analysis

Use `plm stop --trace-file <trace.etl>` to analyze an existing trace under the
caller's identity. Run `plm stop --help` for output/configuration options.
`plm extract-caps` remains a low-level ACE diagnostic.

Actionable findings are written to `denials.json`; bounded sanitized
diagnostics are written to `denials.verbose.json`. File and capability findings
feed the compatibility adjusted-config generator. Registry writes and unknown
registry accesses remain non-actionable diagnostics.

Capability merging applies only to the `processContainer` section. Backends
that cannot express those capabilities are left unchanged and the discoveries
are reported separately. Reserved `learningModeLogging` and
`permissiveLearningMode` capability names are never written into consumer
requests.

## Privilege boundary

The public CLI runs `asInvoker`; caller-selected file operations, existing-ETL
analysis, and adjusted-config output remain under the caller token. There is
no service. Interactive logging requests UAC once for a retained guardian,
using an authenticated local named pipe.

The guardian:

- resolves `wpr.exe` from the system directory and uses the embedded profile;
- authenticates both pipe endpoints and rejects remote clients;
- requires the invoking and elevating Windows identities to match;
- retains the protected `Global\Mxc_Plm_Audit` singleton while WPR may be armed;
- uses protected scratch storage and bounded control/analysis responses;
- preserves a protected recovery marker when cleanup cannot be proven; and
- never cancels an unverified host-wide recording after losing its owner or
  control connection.

Before elevation, the runtime verifies the pinned executable's Authenticode
trust and Microsoft signer, resolves its canonical local path, and checks the
ownership and write/delete permissions of its directory and ancestors. The
pinned handle remains open across launch. The elevated child restricts DLL
loading to system locations. Unsigned or user-replaceable development binaries
are refused; use an approved signed deployment for interactive validation.
These checks belong to standalone PLM elevation, not native sandbox creation.

### Recovering guarded WPR state

The recovery marker normally lives at
`%ProgramData%\Microsoft\MXC\PLM\active.marker`. PLM resolves ProgramData through
the Windows known-folder API and reports the actual path in start errors.
A stale marker means cleanup was uncertain, not that WPR is necessarily active.

If start continues to fail, an administrator must:

1. Inspect `wpr -status profiles` and `wpr -status collectors -details`.
2. Identify any recording that belongs to another tool or must be preserved.
3. Preserve the recording with `wpr -stop <chosen-output.etl>`, or deliberately
   use `wpr -cancel` only when it is known to be disposable.
4. Confirm that WPR reports no active recording.
5. Delete only the exact recovery-marker path reported by PLM, then retry.

Deleting the marker first hides ownership uncertainty without stopping WPR.
PLM intentionally does not automate this recovery because the marker cannot
prove which host-wide recording is currently active.

## Building

```powershell
# From src/
cargo build -p plm
cargo build -p plm --release
```

The WPR profile is embedded in `plm.exe` and materialized only in the guardian's
protected scratch directory.

## Limitations

- Windows-only, with WPR and elevation requirements.
- Compatibility policy merging uses lexical path normalization, not reparse
  point resolution. Review junction/symlink aliases before using generated
  policy; a lexically different alias may not match a denied canonical path.
- File and capability findings feed the compatibility generator; UI findings
  remain available in the denials document.
