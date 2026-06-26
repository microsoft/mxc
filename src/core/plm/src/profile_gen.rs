//! Materialize `plm.wprp` next to the running `plm` binary on demand.
//!
//! The canonical profile lives inline below as `EMBEDDED_WPRP`. There
//! is no checked-in `plm.wprp` file and no build-time staging — the
//! binary writes the file itself on first use of `plm start` /
//! `plm log` when one isn't already next to the exe.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Canonical WPR profile. Edited here directly — there is no
/// sibling `plm.wprp` file to keep in sync. `start.rs`'s
/// `plm_wprp_resource_is_well_formed_…` test pins the parser
/// contract on these exact bytes.
pub const EMBEDDED_WPRP: &str = r#"<!--

    This WPRP (WPR profile) is defined to collect access failure events in learning mode.

    Prefixes in the WPRP:
    SC_  - System Collector controlling kernel event tracing
    EC_  - Event Collector controlling user mode event tracing

    SP_  - System Provider

    EP_  - Event Provider

-->
<WindowsPerformanceRecorder Version="1.0" Comments="Profile for recording access failure events in learning mode" Company="Microsoft Corporation" Copyright="Microsoft Corporation">
    <Profiles>
        <SystemCollector
            Id="SC_Kernel"
            Name="NT Kernel Logger">
            <BufferSize Value="1024"/>
            <Buffers Value="100"/>
        </SystemCollector>
        <EventCollector
            Id="EC_Secure"
            Name="Secure Realtime Event Collector"
            Secure="true">
            <BufferSize Value="1024"/>
            <Buffers Value="100"/>
        </EventCollector>
        <SystemProvider Id="SP_AccessFailure_Light" Base="">
            <Keywords>
                <Keyword Value="ProcessThread"/>
                <Keyword Value="Loader"/>
            </Keywords>
        </SystemProvider>
        <EventProvider
            Id="EP_Microsoft-Windows-Kernel-General"
            Name="a68ca8b7-004f-d7b6-a698-07e2de0f1f5d"
            Stack="true"
            NonPagedMemory="true">
            <Keywords>
                <Keyword Value="0x00"/>
            </Keywords>
        </EventProvider>
        <EventProvider
            Id="EP_Microsoft-Windows-Privacy-Auditing-PermissiveLearningMode"
            Name="811a1ddb-2e69-5f25-adc0-4b186170e760"
            Stack="true"
            NonPagedMemory="true">
            <Keywords>
                <Keyword Value="0x1"/>
            </Keywords>
        </EventProvider>
        <Profile Id="AccessFailureProfile.Verbose.File" LoggingMode="File" Name="AccessFailureProfile" DetailLevel="Verbose" Description="Profile for recording access failure events in learning mode" Default="true">
            <Collectors>
                <SystemCollectorId Value="SC_Kernel">
                    <SystemProviderId Value="SP_AccessFailure_Light"/>
                </SystemCollectorId>
                <EventCollectorId Value="EC_Secure">
                    <EventProviders>
                        <EventProviderId Value="EP_Microsoft-Windows-Kernel-General"/>
                        <EventProviderId Value="EP_Microsoft-Windows-Privacy-Auditing-PermissiveLearningMode"/>
                    </EventProviders>
                </EventCollectorId>
            </Collectors>
        </Profile>
    </Profiles>
</WindowsPerformanceRecorder>
"#;

/// Default filename for the staged profile. Lowercase to match what
/// `build.rs` writes and what `main.rs` defaults to (case-sensitive
/// trees fail opaquely otherwise).
pub const WPRP_FILENAME: &str = "plm.wprp";

/// Ensure `plm.wprp` exists in `exe_dir`. If a file is already
/// present there, leave it untouched (an operator may have hand-
/// edited it) and return its path. Otherwise write `EMBEDDED_WPRP`
/// to that path and return it.
///
/// Uses `create_new` to avoid clobbering a file that appeared
/// between the existence check and the write (TOCTOU); the loser of
/// that race silently adopts the winner's copy.
pub fn ensure_wprp_next_to_exe(exe_dir: &Path) -> io::Result<PathBuf> {
    let dst = exe_dir.join(WPRP_FILENAME);
    if dst.exists() {
        return Ok(dst);
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&dst)
    {
        Ok(mut f) => {
            f.write_all(EMBEDDED_WPRP.as_bytes())?;
            Ok(dst)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(dst),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_wprp_declares_access_failure_profile() {
        assert!(EMBEDDED_WPRP.contains("<WindowsPerformanceRecorder"));
        assert!(EMBEDDED_WPRP.contains("AccessFailureProfile"));
    }

    #[test]
    fn writes_file_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let p = ensure_wprp_next_to_exe(tmp.path()).unwrap();
        assert!(p.exists());
        assert_eq!(p.file_name().unwrap(), WPRP_FILENAME);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), EMBEDDED_WPRP);
    }

    #[test]
    fn preserves_existing_file_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join(WPRP_FILENAME);
        std::fs::write(&dst, "operator-edited contents").unwrap();
        let p = ensure_wprp_next_to_exe(tmp.path()).unwrap();
        assert_eq!(p, dst);
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "operator-edited contents"
        );
    }
}
