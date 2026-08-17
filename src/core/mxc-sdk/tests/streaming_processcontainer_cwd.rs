// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows ProcessContainer working-directory integration tests.
//!
//! A sandboxed shell must start in — and be able to *resolve* — the working
//! directory it was given. The policy under test is deliberately minimal: the
//! caller grants read/write on the working directory and nothing else, which is
//! exactly what a consumer does when it sandboxes a shell in a project folder.
//!
//! # Known failure (BaseContainer filesystem policy)
//!
//! [`pwd_reports_the_granted_working_directory`] and
//! [`set_location_into_the_granted_working_directory_succeeds`] currently fail.
//! The container's filesystem policy grants the working directory itself, so
//! opening and reading it works, but PowerShell cannot resolve the directory it
//! was started in and silently falls back to the drive root:
//!
//! ```text
//! Set-Location: Access to the path 'C:\mxc-cwd-tests' is denied.
//! ```
//!
//! Note that the denied path in that message is an **ancestor** of the granted
//! directory, not the directory itself. With a deeper working directory the
//! name reported is the *topmost* denied ancestor (the first component under
//! the drive root), and granting only the immediate parent does not help — the
//! whole ancestor chain has to be accessible.
//!
//! Granting the ancestors through `readonlyPaths` does make it work, but those
//! rules are recursive, so it also exposes everything beside them;
//! [`granting_the_working_directory_does_not_expose_its_siblings`] pins that
//! boundary and is expected to keep passing.
//!
//! # Isolating the layer at fault: the cmd.exe counterparts
//!
//! Every test below is written twice — once through PowerShell and once
//! through `cmd.exe` — against an identical policy, working directory and
//! assertion, so the *only* variable is the shell. That pairing is what says
//! which layer is at fault:
//!
//! | Pair | PowerShell | cmd.exe | Resolves the path? |
//! |------|-----------|---------|--------------------|
//! | report cwd | [`pwd_reports_the_granted_working_directory`] (fails) | [`cmd_cd_reports_the_granted_working_directory`] (passes) | pwsh yes, cmd no |
//! | enter cwd | [`set_location_into_the_granted_working_directory_succeeds`] (fails) | [`cmd_chdir_into_the_granted_working_directory_succeeds`] (passes) | both yes |
//! | sibling stays denied | [`granting_the_working_directory_does_not_expose_its_siblings`] (passes) | [`cmd_granting_the_working_directory_does_not_expose_its_siblings`] (passes) | n/a |
//!
//! The first pair is asymmetric on purpose: bare `cd` prints the process's
//! stored current-directory string without opening or resolving anything, so
//! it passes even when the directory is unreachable. That makes it the control
//! — it shows the container really did start the child in the requested
//! directory, so the PowerShell failure is a *resolution* bug and not a
//! wrong-cwd bug, and it is why sanity-checking a sandbox with `cmd /c cd`
//! hides the symptom entirely.
//!
//! The second pair is the load-bearing one, and it is what attributes the bug:
//! `cd /d` and `Set-Location` both end in an OS call that takes the absolute
//! path, yet **`cd /d` succeeds where `Set-Location` fails**. The container
//! does let a process open and enter the granted directory by absolute path —
//! the NT path parse from the drive root is not what is blocked. The same holds
//! one layer up, in .NET: with no ancestor grants at all,
//! `Directory.GetCurrentDirectory`, `Directory.SetCurrentDirectory`,
//! `Path.GetFullPath` and `Directory.Exists` all report the granted directory
//! correctly *in the very same pwsh process* whose `Get-Location` says `C:\`.
//!
//! What fails is specific to PowerShell's `FileSystem` provider, which
//! validates a location by walking the ancestor chain from the drive root and
//! touching each component. Those ancestors are genuinely denied by the policy,
//! so the walk fails — and PowerShell then falls back to the drive root instead
//! of surfacing the failure. The denial is real; treating it as fatal to the
//! whole path is PowerShell's choice, which is why `cmd.exe` and .NET are
//! unaffected.
//!
//! Note also that `C:\` is *not* enterable under this policy (`cd /d C:\`
//! returns `Access is denied.`), so the location PowerShell falls back to is
//! not one it could have entered either.
//!
//! These require an elevated Windows host that can run the ProcessContainer
//! backend (see docs/host-prep.md), so they are `#[ignore]`d.

#![cfg(target_os = "windows")]

use mxc_sdk::{build_request, spawn_sandbox, SandboxPolicy};
use std::io::Read;
use std::path::{Path, PathBuf};

/// PowerShell is the shell the sandbox consumers actually run.
const PWSH: &str = r"C:\Program Files\PowerShell\7\pwsh.exe";

/// `cmd.exe`, the second shell each test is run through (see the module docs).
///
/// Read from `ComSpec` rather than hard-coded so the tests do not assume a
/// `C:\Windows` install. The lookup is host-side because the command line is
/// built on the host and passed to the container verbatim.
fn cmd_exe() -> String {
    std::env::var("ComSpec").unwrap_or_else(|_| r"C:\Windows\System32\cmd.exe".to_string())
}

/// Removes the temp tree it owns when the test ends, pass or fail.
struct TempDir(PathBuf);

impl TempDir {
    /// Create the working directory under a drive-root base rather than
    /// `%TEMP%`.
    ///
    /// This keeps the reproduction independent of the user profile: `%TEMP%`
    /// sits under `C:\Users`, whose permissions differ per host, whereas a base
    /// the current user creates (and therefore owns) shows that the failure is
    /// about *any* ancestor of the granted directory rather than one specific
    /// system-owned path. Returns `None` when the base cannot be created, so
    /// the caller skips instead of failing.
    fn new(tag: &str) -> Option<Self> {
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        let path = PathBuf::from(format!("{drive}\\")).join(format!(
            "mxc-cwd-tests\\{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&path).ok()?;
        Some(Self(dunce_canonicalize(&path)))
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn to_str(&self) -> &str {
        self.0.to_str().expect("utf-8 temp path")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `std::fs::canonicalize` returns a `\\?\` path; strip that prefix so the
/// value matches what a shell prints.
fn dunce_canonicalize(path: &Path) -> PathBuf {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let text = canonical.to_string_lossy();
    PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text).to_string())
}

struct RunResult {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
}

/// Run `script` in a sandbox whose **only** filesystem grant is read/write on
/// `cwd`, started in `cwd`.
///
/// `ui.allow_windows` is set because PowerShell fails to initialize at all
/// (`STATUS_DLL_INIT_FAILED`, `0xC0000142`) under full UI lockdown; that is a
/// separate concern from the working directory being resolvable. `cmd.exe`
/// does not need it, but the cmd.exe tests go through this same helper so that
/// the policy is byte-for-byte identical across the two shells and the shell
/// stays the only variable.
fn run_in_sandbox(cwd: &str, script: &str) -> RunResult {
    let policy = SandboxPolicy {
        version: "0.7.0-alpha".to_string(),
        filesystem: Some(mxc_sdk::policy::FilesystemSection {
            readwrite_paths: vec![cwd.to_string()],
            readonly_paths: vec![],
            denied_paths: vec![],
            clear_policy_on_exit: None,
        }),
        network: None,
        ui: Some(mxc_sdk::policy::UiSection {
            allow_windows: true,
            ..Default::default()
        }),
        timeout_ms: Some(60_000),
        capture_denials: None,
    };

    let mut request = build_request(&policy, None).expect("build_request");
    request.set_script(script).set_working_directory(cwd);

    let mut sandbox = spawn_sandbox(request).expect("spawn_sandbox");
    let mut stdout = sandbox.take_stdout().expect("stdout");
    let mut stderr = sandbox.take_stderr().expect("stderr");
    let out_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stdout.read_to_string(&mut buf);
        buf
    });
    let err_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        buf
    });

    let exit_code = match sandbox.wait().expect("wait") {
        mxc_sdk::WaitOutcome::Exited(code) => Some(code),
        mxc_sdk::WaitOutcome::TimedOut => None,
    };

    RunResult {
        stdout: out_thread.join().expect("stdout thread"),
        stderr: err_thread.join().expect("stderr thread"),
        exit_code,
    }
}

/// A shell granted read/write on its working directory must report that
/// directory as its working directory.
///
/// Regression guard for the sandboxed shell silently starting at the drive
/// root: the child's raw process cwd can be correct while the shell still
/// reports `C:\`, because resolving a path walks it from the drive root and
/// every ancestor (`C:\Users`, ...) is denied. `cmd /c cd` cannot catch this —
/// it prints the process's stored cwd string without resolving it — so this
/// asserts through PowerShell's `pwd`, which does resolve.
#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn pwd_reports_the_granted_working_directory() {
    let Some(dir) = TempDir::new("pwd") else {
        println!("SKIPPED: cannot create a drive-root test directory");
        return;
    };
    let cwd = dir.to_str();

    let result = run_in_sandbox(
        cwd,
        &format!(r#""{PWSH}" -NoProfile -NoLogo -Command "(pwd).Path""#),
    );

    let reported = result.stdout.trim();
    assert_eq!(
        result.exit_code,
        Some(0),
        "pwsh should exit 0\nstdout: {reported:?}\nstderr: {:?}",
        result.stderr.trim()
    );
    assert_eq!(
        reported.to_ascii_lowercase(),
        cwd.to_ascii_lowercase(),
        "the sandboxed shell must report the working directory it was given, \
         not the drive root\n  requested: {cwd}\n  reported:  {reported:?}\n  stderr: {:?}",
        result.stderr.trim()
    );
}

/// The working directory must also be usable as a location, not merely
/// printable. `Set-Location` resolves the path through the provider, which is
/// where an inaccessible ancestor surfaces as
/// `Access to the path 'C:\Users' is denied`.
#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn set_location_into_the_granted_working_directory_succeeds() {
    let Some(dir) = TempDir::new("setloc") else {
        println!("SKIPPED: cannot create a drive-root test directory");
        return;
    };
    let cwd = dir.to_str();

    let result = run_in_sandbox(
        cwd,
        &format!(
            r#""{PWSH}" -NoProfile -NoLogo -Command "Set-Location -LiteralPath '{cwd}' -ErrorAction Stop; Write-Output (pwd).Path""#
        ),
    );

    assert_eq!(
        result.exit_code,
        Some(0),
        "Set-Location into the granted working directory must succeed\nstdout: {:?}\nstderr: {:?}",
        result.stdout.trim(),
        result.stderr.trim()
    );
    assert_eq!(
        result.stdout.trim().to_ascii_lowercase(),
        cwd.to_ascii_lowercase(),
        "stderr: {:?}",
        result.stderr.trim()
    );
}

/// The grant must not be widened into the ancestors to make the two tests
/// above pass: a sibling of the working directory must stay unreadable.
///
/// Adding each ancestor to `readonlyPaths` would satisfy `pwd`, but those rules
/// are **recursive**, so granting `C:\Users` would expose every user's files.
/// This pins that boundary.
#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn granting_the_working_directory_does_not_expose_its_siblings() {
    let Some(base) = TempDir::new("sibling") else {
        println!("SKIPPED: cannot create a drive-root test directory");
        return;
    };
    let work = base.path().join("work");
    std::fs::create_dir_all(&work).expect("create work dir");
    let secret = base.path().join("SECRET.txt");
    std::fs::write(&secret, b"TOP-SECRET-CONTENT").expect("write secret");

    let result = run_in_sandbox(
        work.to_str().expect("utf-8"),
        &format!(
            r#""{PWSH}" -NoProfile -NoLogo -Command "try {{ Get-Content -LiteralPath '{}' -Raw -ErrorAction Stop }} catch {{ Write-Output 'DENIED' }}""#,
            secret.display()
        ),
    );

    assert!(
        !result.stdout.contains("TOP-SECRET-CONTENT"),
        "a sibling of the working directory must not be readable\nstdout: {:?}",
        result.stdout.trim()
    );
}

// ---------------------------------------------------------------------------
// cmd.exe counterparts
//
// Identical policy, working directory and assertions as the PowerShell tests
// above — only the shell differs. See the module docs for what each pairing
// isolates.
// ---------------------------------------------------------------------------

/// `cmd /c cd` must report the granted working directory.
///
/// The counterpart to [`pwd_reports_the_granted_working_directory`], and the
/// control of the two: bare `cd` prints the process's stored current-directory
/// string, so it neither opens nor resolves the directory. Passing here while
/// `pwd` reports the drive root is what proves the container *did* start the
/// child where it was asked to and that the fault is in resolving that path
/// afterwards. It is also why `cmd /c cd` must never be used to sanity-check a
/// sandbox's working directory — it cannot observe the failure.
#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn cmd_cd_reports_the_granted_working_directory() {
    let Some(dir) = TempDir::new("cmdcd") else {
        println!("SKIPPED: cannot create a drive-root test directory");
        return;
    };
    let cwd = dir.to_str();

    let result = run_in_sandbox(cwd, &format!(r#""{}" /c cd"#, cmd_exe()));

    let reported = result.stdout.trim();
    assert_eq!(
        result.exit_code,
        Some(0),
        "cmd should exit 0\nstdout: {reported:?}\nstderr: {:?}",
        result.stderr.trim()
    );
    assert_eq!(
        reported.to_ascii_lowercase(),
        cwd.to_ascii_lowercase(),
        "the sandboxed shell must report the working directory it was given, \
         not the drive root\n  requested: {cwd}\n  reported:  {reported:?}\n  stderr: {:?}",
        result.stderr.trim()
    );
}

/// `cd /d <dir>` into the granted working directory must succeed.
///
/// The counterpart to [`set_location_into_the_granted_working_directory_succeeds`]
/// and the load-bearing half of the comparison: unlike bare `cd`, `cd /d` calls
/// `SetCurrentDirectory` on the absolute path, so the OS opens the target and
/// parses the path from the drive root — the same OS-level work `Set-Location`
/// bottoms out in. This is the test that attributes the bug, and it **passes**
/// while its PowerShell counterpart fails, which puts the fault in the extra
/// resolution PowerShell layers on top of the OS call rather than in the
/// container's rights over the ancestors.
///
/// The child already starts *in* the target directory, so it first chdirs into
/// a subdirectory; otherwise `cd /d` could be satisfied without ever entering
/// the granted directory and the test would prove nothing. Staging through a
/// child rather than the drive root is deliberate: `cd /d C:\` is itself denied
/// under this policy, which would make the chain fail for a reason that has
/// nothing to do with the directory under test.
///
/// The trailing `&& cd` re-prints the directory so a silent no-op cannot pass
/// either — each `cd /d` sets `ERRORLEVEL` on failure, short-circuiting the
/// `&&` chain and leaving stdout empty.
#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn cmd_chdir_into_the_granted_working_directory_succeeds() {
    let Some(dir) = TempDir::new("cmdchdir") else {
        println!("SKIPPED: cannot create a drive-root test directory");
        return;
    };
    let cwd = dir.to_str();
    let staging = dir.path().join("staging");
    std::fs::create_dir_all(&staging).expect("create staging dir");

    let result = run_in_sandbox(
        cwd,
        &format!(
            r#""{}" /c cd /d "{}" && cd /d "{cwd}" && cd"#,
            cmd_exe(),
            staging.display()
        ),
    );

    assert_eq!(
        result.exit_code,
        Some(0),
        "cd /d into the granted working directory must succeed\nstdout: {:?}\nstderr: {:?}",
        result.stdout.trim(),
        result.stderr.trim()
    );
    assert_eq!(
        result.stdout.trim().to_ascii_lowercase(),
        cwd.to_ascii_lowercase(),
        "stderr: {:?}",
        result.stderr.trim()
    );
}

/// The containment boundary must hold for `cmd.exe` too: a sibling of the
/// working directory stays unreadable.
///
/// The counterpart to
/// [`granting_the_working_directory_does_not_expose_its_siblings`]. Whatever
/// fix makes the two tests above pass must not be reachable around by picking
/// a different shell, so the boundary is pinned once per shell.
#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn cmd_granting_the_working_directory_does_not_expose_its_siblings() {
    let Some(base) = TempDir::new("cmdsibling") else {
        println!("SKIPPED: cannot create a drive-root test directory");
        return;
    };
    let work = base.path().join("work");
    std::fs::create_dir_all(&work).expect("create work dir");
    let secret = base.path().join("SECRET.txt");
    std::fs::write(&secret, b"TOP-SECRET-CONTENT").expect("write secret");

    let result = run_in_sandbox(
        work.to_str().expect("utf-8"),
        &format!(
            r#""{}" /c type "{}" || echo DENIED"#,
            cmd_exe(),
            secret.display()
        ),
    );

    assert!(
        !result.stdout.contains("TOP-SECRET-CONTENT"),
        "a sibling of the working directory must not be readable\nstdout: {:?}",
        result.stdout.trim()
    );
}
