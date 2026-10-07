// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host probes for the multi-session store model (AB#64133563, spike PR 0).
//!
//! These answer four questions that decide whether the state-aware daemon can
//! hold more than one WSLc session, and what each session's image store must
//! look like. They need a live WSL2 host, so they are `#[ignore]`d and run
//! explicitly:
//!
//! ```text
//! cargo test -p mxc-sdk --features wslc store_model_probe -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `--test-threads=1` matters: every probe drives the same per-user WSL
//! service, and two of them deliberately contend for one store.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::ptr;

use super::container_steps::{create_daemon_session, sdk_error};
use crate::mxc_common::logger::{Logger, Mode};
use crate::mxc_common::models::ScriptResponse;
use crate::wslc_common::image::pull_image;
use crate::wslc_common::sdk_init::init_and_load_sdk;
use crate::wslc_common::wslc_bindings::{WslcImageInfo, WslcSdk, WslcSession, S_OK};

/// `ERROR_SHARING_VIOLATION` as an `HRESULT`. The symptom the work item reports
/// when a second live session opens a store another session already holds.
const E_SHARING_VIOLATION: i32 = 0x8007_0020u32 as i32;

/// Image the cache-persistence probe pulls. Small, and the same default the
/// state-aware backend uses, so a developer's warm cache likely already has it.
const PROBE_IMAGE: &str = "alpine:latest";

/// A scratch store directory that deletes itself on drop, so a probe run does
/// not leave VHDs behind in `%TEMP%`.
struct ScratchStore {
    path: PathBuf,
}

impl ScratchStore {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "mxc-store-probe-{tag}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&path).expect("create scratch store");
        Self { path }
    }

    fn as_str(&self) -> String {
        self.path.to_string_lossy().to_string()
    }
}

impl Drop for ScratchStore {
    fn drop(&mut self) {
        // Best-effort: the WSL service may still hold the VHD briefly after
        // release, and a probe must not fail during unwind.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Names of the images a session reports in its store.
///
/// This is the cheapest call that proves a session handle is actually usable
/// rather than merely non-null, and it is the exact call the work item names as
/// failing with `ERROR_SHARING_VIOLATION`.
///
/// # Safety
/// `sdk` must hold valid function pointers and `session` must be a live handle.
unsafe fn probe_list_images(
    sdk: &WslcSdk,
    session: WslcSession,
) -> Result<Vec<String>, ScriptResponse> {
    let mut images: *mut WslcImageInfo = ptr::null_mut();
    let mut count: u32 = 0;
    let hr = sdk.WslcListSessionImages(session, &mut images, &mut count);
    if hr != S_OK {
        return Err(sdk_error("WslcListSessionImages failed", hr, ""));
    }
    if images.is_null() {
        return Ok(Vec::new());
    }

    let mut names = Vec::with_capacity(count as usize);
    for info in std::slice::from_raw_parts(images, count as usize) {
        let bytes = std::slice::from_raw_parts(info.name.as_ptr().cast::<u8>(), info.name.len());
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        if let Ok(name) = std::str::from_utf8(&bytes[..end]) {
            names.push(name.to_string());
        }
    }
    windows::Win32::System::Com::CoTaskMemFree(Some(images as *const std::ffi::c_void));
    Ok(names)
}

fn logger() -> Logger {
    Logger::new(Mode::Console)
}

/// Q1 — can one process, on one MTA thread, hold two live sessions with
/// separate stores, use both, and release both cleanly?
///
/// This is the premise the whole multi-session design rests on. The work item
/// claims a probe confirmed it on SDK 2.9.3; this re-confirms it on the 2.9.9
/// the repo now vendors, through the daemon's own `create_daemon_session`.
#[test]
#[ignore = "requires a WSL2 host with the WSLc SDK installed"]
fn two_sessions_with_separate_stores_coexist_in_one_process() {
    let mut log = logger();
    let sdk = unsafe { init_and_load_sdk(&mut log) }.expect("load SDK");

    let store_a = ScratchStore::new("a");
    let store_b = ScratchStore::new("b");

    // SAFETY: `sdk` is live and both stores are distinct empty directories.
    let session_a =
        unsafe { create_daemon_session(sdk, "mxc-probe-a", &store_a.as_str(), &mut log) }
            .expect("first session must create");

    let session_b =
        unsafe { create_daemon_session(sdk, "mxc-probe-b", &store_b.as_str(), &mut log) }
            .expect("second concurrent session with its own store must create");

    // Both handles must be usable *while the other is live*, not merely
    // created: a handle that cannot list its store is not a working session.
    let images_a = unsafe { probe_list_images(sdk, session_a.as_raw()) }
        .expect("session A must stay usable while B is live");
    let images_b = unsafe { probe_list_images(sdk, session_b.as_raw()) }
        .expect("session B must be usable while A is live");

    let mut out = String::new();
    let _ = writeln!(
        out,
        "[probe] A store={} images={:?}",
        store_a.as_str(),
        images_a
    );
    let _ = writeln!(
        out,
        "[probe] B store={} images={:?}",
        store_b.as_str(),
        images_b
    );
    println!("{out}");

    // Interleave once more after both have been exercised, to catch a handle
    // that only works until the other session touches the SDK.
    unsafe { probe_list_images(sdk, session_a.as_raw()) }
        .expect("session A must still be usable after B was used");

    drop(session_b);
    // A must survive B's release — per-session teardown releasing the wrong
    // session is the specific hazard the daemon's current single-session
    // `shutdown()` cannot express.
    unsafe { probe_list_images(sdk, session_a.as_raw()) }
        .expect("session A must survive session B's release");
    drop(session_a);
}

/// Q2 — does a second live session on the *same* store really fail, and where?
///
/// The work item reports `WslcListSessionImages failed: HRESULT 0x80070020`.
/// Whether that fires at create time or only on first use decides whether the
/// daemon can detect the collision before it mints a sandbox id.
#[test]
#[ignore = "requires a WSL2 host with the WSLc SDK installed"]
fn a_second_live_session_on_one_store_is_a_sharing_violation() {
    let mut log = logger();
    let sdk = unsafe { init_and_load_sdk(&mut log) }.expect("load SDK");

    let shared = ScratchStore::new("shared");

    // SAFETY: `sdk` is live; both calls target the same store on purpose.
    let first = unsafe { create_daemon_session(sdk, "mxc-probe-1", &shared.as_str(), &mut log) }
        .expect("first session on an unheld store must create");
    unsafe { probe_list_images(sdk, first.as_raw()) }.expect("first session must be usable");

    let second = unsafe { create_daemon_session(sdk, "mxc-probe-2", &shared.as_str(), &mut log) };

    match second {
        Err(resp) => {
            println!("[probe] second create FAILED: {}", resp.error_message);
            println!("[probe] => collision is detectable at CREATE time");
        }
        Ok(guard) => {
            println!("[probe] second create SUCCEEDED; probing first use");
            let used = unsafe { probe_list_images(sdk, guard.as_raw()) };
            match used {
                Err(resp) => {
                    println!("[probe] first use FAILED: {}", resp.error_message);
                    println!("[probe] => collision only surfaces on USE");
                    assert!(
                        resp.error_message.contains("80070020")
                            || resp
                                .error_message
                                .contains(&format!("{E_SHARING_VIOLATION:#x}")),
                        "expected ERROR_SHARING_VIOLATION, got: {}",
                        resp.error_message
                    );
                }
                Ok(images) => {
                    println!("[probe] first use SUCCEEDED: images={images:?}");
                    println!(
                        "[probe] => NO collision on this SDK/host. The store-exclusivity \
                         premise does not hold as stated; re-scope the store design."
                    );
                }
            }
            drop(guard);
        }
    }
    drop(first);
}

/// Q3 — THE store-model question. After a session releases its store, can a
/// later session reopen that same store and still see the images the first one
/// cached?
///
/// Reopenability alone is not enough: a slot pool is only worth building if the
/// *cache survives* the lease. So this warms the store with a real pull, drops
/// the session, retakes the same store, and requires the image to still be
/// there.
///
/// If it survives, a bounded pool of reusable store slots works: a session
/// leases a warm slot and returns it, so N sessions cost N stores but not N
/// *cold* stores, and `--setup-wslc` can warm the pool ahead of time.
///
/// If it does not, every session is permanently cold and the only offline path
/// is `imageTarPath` — which would make per-session stores a serious regression
/// for the default no-egress posture.
#[test]
#[ignore = "requires a WSL2 host and network egress to pull alpine:latest"]
fn a_released_store_keeps_its_cache_for_the_next_session() {
    let mut log = logger();
    let sdk = unsafe { init_and_load_sdk(&mut log) }.expect("load SDK");

    let slot = ScratchStore::new("slot");
    let store = slot.as_str();

    // Lease 1: warm the slot with a real pull.
    // SAFETY: `sdk` is live and the store is a fresh directory.
    let first = unsafe { create_daemon_session(sdk, "mxc-probe-lease-1", &store, &mut log) }
        .expect("first lease must create");
    let cold = unsafe { probe_list_images(sdk, first.as_raw()) }.expect("list before pull");
    println!("[probe] lease 1 cold images={cold:?}");
    assert!(cold.is_empty(), "a fresh slot must start cold");

    unsafe {
        pull_image(
            sdk,
            first.as_raw(),
            PROBE_IMAGE,
            Some(&store),
            "[probe]",
            &mut log,
        )
    }
    .expect("pull must succeed; this probe needs egress");
    let warmed = unsafe { probe_list_images(sdk, first.as_raw()) }.expect("list after pull");
    println!("[probe] lease 1 warmed images={warmed:?}");
    assert!(
        !warmed.is_empty(),
        "the pull must have populated the store; got {warmed:?}"
    );

    // Return the slot.
    drop(first);

    // Lease 2: take the same slot again, as a pool would.
    let second = unsafe { create_daemon_session(sdk, "mxc-probe-lease-2", &store, &mut log) }
        .expect("a released store must be reopenable by a later session");
    let reopened = unsafe { probe_list_images(sdk, second.as_raw()) }
        .expect("the reopened store must be readable");
    println!("[probe] lease 2 reopened images={reopened:?}");

    assert_eq!(
        warmed, reopened,
        "a reopened store must present the cache it had at release; losing it \
         would make a warm slot pool pointless and leave every new session cold"
    );
    drop(second);
}

/// Q4 — baseline: a brand-new store really is empty.
///
/// This is the premise behind `select_action`'s `RefuseNoEgress` arm: an
/// uncached image with no tar and no egress is refused. If a freshly minted
/// per-session store starts empty, then under the default deny-egress posture
/// every provision into a new session fails before it ever reaches the VM.
#[test]
#[ignore = "requires a WSL2 host with the WSLc SDK installed"]
fn a_fresh_store_starts_empty() {
    let mut log = logger();
    let sdk = unsafe { init_and_load_sdk(&mut log) }.expect("load SDK");

    let fresh = ScratchStore::new("fresh");
    // SAFETY: `sdk` is live and the store is a fresh directory.
    let session =
        unsafe { create_daemon_session(sdk, "mxc-probe-fresh", &fresh.as_str(), &mut log) }
            .expect("fresh store session must create");
    let images = unsafe { probe_list_images(sdk, session.as_raw()) }.expect("list fresh store");

    println!("[probe] fresh store images={images:?}");
    assert!(
        images.is_empty(),
        "a newly minted per-session store must start cold; found {images:?}"
    );
    drop(session);
}
