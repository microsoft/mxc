// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build-time helpers for staging NanVix micro-VM binaries next to the
//! consuming executable.
//!
//! This crate is **build-only**: it is consumed exclusively as a
//! `[build-dependencies]` entry by the `nanvix_binaries`, `wxc`, and `lxc`
//! build scripts and is never linked into the shipping runtime binary. The
//! file-staging logic lives here (rather than in the runtime `nanvix_common`
//! crate) so it adds no weight to mainline code.

use std::io;
use std::path::{Path, PathBuf};

use nanvix_common::{
    BIN_SUBDIR, BIN_SUBDIR_FILES, REQUIRED_BINARIES, SNAPSHOTS_SUBDIR, SNAPSHOT_FILES,
};

/// Category of a staged NanVix artifact.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ArtifactKind {
    /// Flat binary next to the executable (e.g. `nanvixd.exe`).
    Binary,
    /// File under the `bin/` subdirectory (e.g. `bin/kernel.elf`).
    BinFile,
    /// WHP warm-start snapshot under `snapshots/` (used by the Windows runner).
    Snapshot,
}

/// Relative paths (from the nanvix binary directory) of every artifact the
/// backend stages, paired with its [`ArtifactKind`].
///
/// This is the single source of truth that drives both copying
/// ([`copy_artifacts_to_target`]) and `cargo:rerun-if-changed` emission
/// ([`emit_rerun_for_copied_artifacts`]) so the two can never drift apart.
pub fn artifact_rel_paths() -> Vec<(ArtifactKind, PathBuf)> {
    let mut paths = Vec::new();
    for name in REQUIRED_BINARIES {
        paths.push((ArtifactKind::Binary, PathBuf::from(name)));
    }
    for name in BIN_SUBDIR_FILES {
        paths.push((ArtifactKind::BinFile, Path::new(BIN_SUBDIR).join(name)));
    }
    for name in SNAPSHOT_FILES {
        paths.push((
            ArtifactKind::Snapshot,
            Path::new(SNAPSHOTS_SUBDIR).join(name),
        ));
    }
    paths
}

/// Resolve the directory of NanVix binaries to use for a build, and report
/// whether it came from an externally supplied (prefetched) location.
///
/// When `NANVIX_BIN` is set to a non-empty value, that directory is used
/// directly (no network downloads) and the returned boolean is `true`. An
/// empty `NANVIX_BIN` is treated as unset, matching the online/cached default.
/// Otherwise a `nanvix-binaries` subdirectory of `out_dir` is created and
/// returned with `false`.
///
/// The prefetched directory is made absolute via [`std::path::absolute`] (not
/// `fs::canonicalize`) so it is stable regardless of the build script's working
/// directory while still letting an atomic symlink swap of the cache be noticed
/// by Cargo.
pub fn resolve_bin_dir(out_dir: &Path) -> (PathBuf, bool) {
    let prefetched = std::env::var_os("NANVIX_BIN")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);

    match prefetched {
        Some(dir) => {
            if !dir.is_dir() {
                panic!(
                    "nanvix_binaries: NANVIX_BIN is set to '{}', but that directory \
                     does not exist. Point NANVIX_BIN at a directory containing the \
                     pre-fetched NanVix binaries.",
                    dir.display()
                );
            }
            let dir = std::path::absolute(&dir).unwrap_or_else(|e| {
                panic!(
                    "nanvix_binaries: failed to resolve NANVIX_BIN '{}' to an \
                     absolute path: {}",
                    dir.display(),
                    e
                )
            });
            eprintln!(
                "nanvix_binaries: NANVIX_BIN set — using pre-fetched binaries from '{}' (offline)",
                dir.display()
            );
            (dir, true)
        }
        None => {
            let dir = out_dir.join("nanvix-binaries");
            std::fs::create_dir_all(&dir).expect("failed to create nanvix-binaries dir");
            (dir, false)
        }
    }
}

/// Copy NanVix artifacts from the build cache (`src_dir`) to the target
/// directory next to the output executable.
///
/// Binaries and `bin/` files are copied whenever the source exists (the build
/// script only re-runs when a tracked input changed, so this is not a
/// per-build cost — and a modification-time comparison would silently skip a
/// legitimate override or rollback to an older cache). A failure to copy a
/// binary is logged as a warning and does not abort the build (preserving the
/// historical behavior).
///
/// `trust_snapshots` governs WHP warm-start snapshots, which are **not**
/// covered by `checksums.json` (they are normally host-generated, not pinned
/// release artifacts):
/// - `true` (normal online build, snapshots produced locally): snapshots are
///   mirrored — present ones are copied and target snapshots absent from the
///   source are purged, so a stale warm-start image is never used against
///   mismatched binaries.
/// - `false` (source is an externally supplied `NANVIX_BIN` prefetch dir):
///   snapshots are never copied and any stale target snapshot is removed, so
///   the runtime falls back to a verified cold boot instead of warm-booting an
///   unverified VM memory image.
///
/// Returns `Err` on any snapshot integrity failure (a snapshot could not be
/// copied or a stale snapshot could not be removed) so the caller can decide
/// how to react. Build scripts should treat such an error as fatal — leaving a
/// mismatched/unverified snapshot next to the executable is unsafe.
pub fn copy_artifacts_to_target(
    src_dir: &Path,
    target_dir: &Path,
    trust_snapshots: bool,
) -> io::Result<()> {
    use std::fs;

    for (kind, rel) in artifact_rel_paths() {
        let src = src_dir.join(&rel);
        let dst = target_dir.join(&rel);

        // Snapshots from an untrusted (prefetched) source are never copied; we
        // must also guarantee no stale snapshot is left behind so the runtime
        // does not warm-boot an unverified image.
        if kind == ArtifactKind::Snapshot && !trust_snapshots {
            remove_stale_snapshot(&dst)?;
            continue;
        }

        if src.exists() {
            if let Some(parent) = dst.parent() {
                let _ = fs::create_dir_all(parent);
            }
            eprintln!("nanvix: copying {} -> {}", src.display(), dst.display());
            if let Err(e) = fs::copy(&src, &dst) {
                // Never leave a partial/stale file behind.
                let _ = fs::remove_file(&dst);
                if kind == ArtifactKind::Snapshot {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("nanvix: failed to copy {}: {}", rel.display(), e),
                    ));
                }
                eprintln!("nanvix: WARNING: failed to copy {}: {}", rel.display(), e);
            }
        } else if kind == ArtifactKind::Snapshot {
            // Trusted source is missing this snapshot — purge any stale target
            // copy so an incomplete set forces a clean cold boot.
            remove_stale_snapshot(&dst)?;
        }
    }
    Ok(())
}

/// Remove a target snapshot file if present, returning an error if it cannot be
/// removed. A leftover stale snapshot would be warm-booted by the runner
/// (which trusts a complete exe-side snapshot set on presence alone) against
/// mismatched binaries, so a failure here must be surfaced rather than ignored.
fn remove_stale_snapshot(dst: &Path) -> io::Result<()> {
    if dst.exists() {
        eprintln!(
            "nanvix: removing stale {} (absent or untrusted in source)",
            dst.display()
        );
        std::fs::remove_file(dst).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "nanvix: failed to remove stale snapshot {}: {} — refusing to \
                     leave an unverified warm-start image that would be booted \
                     against mismatched binaries",
                    dst.display(),
                    e
                ),
            )
        })?;
    }
    Ok(())
}

/// Emit `cargo:rerun-if-changed` for every artifact that
/// [`copy_artifacts_to_target`] reads from `src_dir`. Call this from a
/// consuming crate's build script so the copy reruns when the source contents
/// change in place — for example when an offline `NANVIX_BIN` prefetch
/// directory is updated at the same path. Without it, the consumer only reruns
/// when the source *path* changes, leaving stale artifacts next to the exe.
pub fn emit_rerun_for_copied_artifacts(src_dir: &Path) {
    for (_, rel) in artifact_rel_paths() {
        println!("cargo:rerun-if-changed={}", src_dir.join(rel).display());
    }
}

/// Stage NanVix artifacts from `nanvix_bin_dir` next to the executable being
/// built and emit the appropriate `cargo:rerun-*` triggers.
///
/// Intended to be called from a consumer (`wxc` / `lxc`) build script. The
/// target directory is derived from `OUT_DIR` (the binary lands in
/// `target/<profile>/`), and snapshot trust is read from the
/// `DEP_NANVIX_BINARIES_PREFETCHED` link var the `nanvix_binaries` build script
/// exports (defaulting to trusted when absent). Panics on a snapshot integrity
/// failure — acceptable in the build path, where leaving an unverified
/// warm-start image next to the executable must abort the build.
pub fn stage_artifacts_next_to_exe(nanvix_bin_dir: &Path) {
    // Cargo puts the output binary in OUT_DIR/../../.. (target/<profile>/).
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let target_dir = Path::new(&out_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("could not determine target dir from OUT_DIR");

    // WHP snapshots from a prefetched (externally supplied) directory are not
    // covered by checksums.json, so they must not be trusted/copied. Default to
    // trusting (online build) when the flag is absent.
    let trust_snapshots = std::env::var("DEP_NANVIX_BINARIES_PREFETCHED")
        .map(|v| v != "1")
        .unwrap_or(true);

    copy_artifacts_to_target(nanvix_bin_dir, target_dir, trust_snapshots)
        .expect("nanvix: failed to stage artifacts next to the executable");

    // Re-run when the source path changes (detected via nanvix_binaries
    // rebuild) and when the source artifacts themselves change in place (e.g.
    // an offline NANVIX_BIN prefetch dir updated at the same path).
    emit_rerun_for_copied_artifacts(nanvix_bin_dir);
    println!("cargo:rerun-if-env-changed=DEP_NANVIX_BINARIES_BIN_DIR");
    println!("cargo:rerun-if-env-changed=DEP_NANVIX_BINARIES_PREFETCHED");
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanvix_common::{SNAPSHOT_CBOR, SNAPSHOT_VMEM};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Create a unique, empty scratch directory under the OS temp dir.
    fn scratch(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "nanvix_copy_test_{}_{}_{}",
            tag,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_snapshot(root: &Path, name: &str, contents: &[u8]) {
        let dir = root.join(SNAPSHOTS_SUBDIR);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(name), contents).unwrap();
    }

    fn snapshot_path(root: &Path, name: &str) -> PathBuf {
        root.join(SNAPSHOTS_SUBDIR).join(name)
    }

    #[test]
    fn trusted_source_lacking_snapshot_purges_stale_target() {
        let src = scratch("purge_src");
        let target = scratch("purge_tgt");
        // Target has both snapshots; source has none.
        write_snapshot(&target, SNAPSHOT_VMEM, b"stale-vmem");
        write_snapshot(&target, SNAPSHOT_CBOR, b"stale-cbor");

        copy_artifacts_to_target(&src, &target, /* trust_snapshots = */ true).unwrap();

        assert!(!snapshot_path(&target, SNAPSHOT_VMEM).exists());
        assert!(!snapshot_path(&target, SNAPSHOT_CBOR).exists());

        fs::remove_dir_all(&src).ok();
        fs::remove_dir_all(&target).ok();
    }

    #[test]
    fn trusted_source_with_snapshots_copies_into_target() {
        let src = scratch("copy_src");
        let target = scratch("copy_tgt");
        write_snapshot(&src, SNAPSHOT_VMEM, b"new-vmem");
        write_snapshot(&src, SNAPSHOT_CBOR, b"new-cbor");

        copy_artifacts_to_target(&src, &target, true).unwrap();

        assert_eq!(
            fs::read(snapshot_path(&target, SNAPSHOT_VMEM)).unwrap(),
            b"new-vmem"
        );
        assert_eq!(
            fs::read(snapshot_path(&target, SNAPSHOT_CBOR)).unwrap(),
            b"new-cbor"
        );

        fs::remove_dir_all(&src).ok();
        fs::remove_dir_all(&target).ok();
    }

    #[test]
    fn trusted_partial_source_copies_present_and_purges_absent() {
        let src = scratch("partial_src");
        let target = scratch("partial_tgt");
        // Source has only vmem; target starts with both.
        write_snapshot(&src, SNAPSHOT_VMEM, b"fresh-vmem");
        write_snapshot(&target, SNAPSHOT_VMEM, b"old-vmem");
        write_snapshot(&target, SNAPSHOT_CBOR, b"old-cbor");

        copy_artifacts_to_target(&src, &target, true).unwrap();

        // Present-in-source file is overwritten; absent-in-source file purged.
        assert_eq!(
            fs::read(snapshot_path(&target, SNAPSHOT_VMEM)).unwrap(),
            b"fresh-vmem"
        );
        assert!(!snapshot_path(&target, SNAPSHOT_CBOR).exists());

        fs::remove_dir_all(&src).ok();
        fs::remove_dir_all(&target).ok();
    }

    #[test]
    fn untrusted_source_never_copies_snapshots_and_purges_target() {
        let src = scratch("untrusted_src");
        let target = scratch("untrusted_tgt");
        // Source ships snapshots, but they are untrusted (prefetched).
        write_snapshot(&src, SNAPSHOT_VMEM, b"attacker-vmem");
        write_snapshot(&src, SNAPSHOT_CBOR, b"attacker-cbor");
        // Target has stale snapshots from a prior build.
        write_snapshot(&target, SNAPSHOT_VMEM, b"stale-vmem");
        write_snapshot(&target, SNAPSHOT_CBOR, b"stale-cbor");

        copy_artifacts_to_target(&src, &target, /* trust_snapshots = */ false).unwrap();

        // Untrusted snapshots are neither copied nor left behind.
        assert!(!snapshot_path(&target, SNAPSHOT_VMEM).exists());
        assert!(!snapshot_path(&target, SNAPSHOT_CBOR).exists());

        fs::remove_dir_all(&src).ok();
        fs::remove_dir_all(&target).ok();
    }
}
