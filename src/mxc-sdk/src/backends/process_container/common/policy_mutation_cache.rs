// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard, OnceLock};
#[cfg(test)]
use std::{cell::RefCell, marker::PhantomData, rc::Rc, sync::Arc};

use windows::Win32::Foundation::{ERROR_NO_TOKEN, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, TokenStatistics, TOKEN_QUERY, TOKEN_STATISTICS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

use crate::mxc_common::process_util::OwnedHandle;

use super::MAX_CHANGE_TEXT_BYTES;
use crate::process_container_common::secenv_policy::MutationHint;

const MAX_ENTRIES: usize = 16;
const MAX_RETAINED_BYTES: usize = 4 * MAX_CHANGE_TEXT_BYTES;

type Creator = [(u32, i32); 4];

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Key {
    creator: Creator,
}

pub(super) struct Entry {
    key: Key,
    // Replay these through the normal repair validation against the fresh
    // request. Never retain its unrelated grants, proxy endpoints or secrets.
    pub hints: Vec<MutationHint>,
    retained_bytes: usize,
}

#[derive(Default)]
pub(super) struct Cache {
    entries: VecDeque<Entry>,
    retained_bytes: usize,
}

impl Cache {
    #[cfg(test)]
    pub fn get(&self, key: Key) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.key == key)
    }

    pub fn candidates(&self, key: Key) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(move |entry| entry.key == key)
    }

    pub fn remember(&mut self, key: Key, hints: &[MutationHint]) -> Result<(), String> {
        if hints.is_empty() {
            return Ok(());
        }
        if creator()? != key.creator {
            return Err("the caller identity changed during negotiation".into());
        }
        let retained_bytes = hints
            .iter()
            .map(|hint| {
                let text = match hint {
                    MutationHint::RemoveCapability(value) => value.len(),
                    MutationHint::RestrictPath { path, .. } => path.len(),
                    MutationHint::ReducePathCount { .. } => 0,
                };
                std::mem::size_of::<MutationHint>().saturating_add(text)
            })
            .fold(0usize, usize::saturating_add);
        let retained_bytes = retained_bytes.saturating_add(std::mem::size_of::<Entry>());
        if retained_bytes > MAX_RETAINED_BYTES {
            return Err("the remembered restrictions exceed the in-process cache budget".into());
        }
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.key == key && entry.hints == hints)
        {
            if let Some(previous) = self.entries.remove(index) {
                self.retained_bytes -= previous.retained_bytes;
            }
        }
        self.entries.push_front(Entry {
            key,
            hints: hints.to_vec(),
            retained_bytes,
        });
        self.retained_bytes += retained_bytes;
        while self.entries.len() > MAX_ENTRIES || self.retained_bytes > MAX_RETAINED_BYTES {
            if let Some(entry) = self.entries.pop_back() {
                self.retained_bytes -= entry.retained_bytes;
            }
        }
        Ok(())
    }
}

pub(super) fn shared() -> &'static Mutex<Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

pub(super) fn with_shared<T>(operation: impl FnOnce(&Mutex<Cache>) -> T) -> T {
    #[cfg(test)]
    if let Some(cache) = TEST_CACHE.with(|slot| slot.borrow().clone()) {
        return operation(&cache);
    }
    operation(shared())
}

#[cfg(test)]
thread_local! {
    static TEST_CACHE: RefCell<Option<Arc<Mutex<Cache>>>> = const { RefCell::new(None) };
}

#[cfg(test)]
pub(crate) struct TestCacheScope {
    previous: Option<Arc<Mutex<Cache>>>,
    _thread: PhantomData<Rc<()>>,
}

#[cfg(test)]
pub(crate) fn isolated_test_cache() -> TestCacheScope {
    let cache = Arc::new(Mutex::new(Cache::default()));
    TestCacheScope {
        previous: TEST_CACHE.with(|slot| slot.replace(Some(cache))),
        _thread: PhantomData,
    }
}

#[cfg(test)]
impl Drop for TestCacheScope {
    fn drop(&mut self) {
        TEST_CACHE.with(|slot| slot.replace(self.previous.take()));
    }
}

pub(super) fn lock<'a>(
    cache: &'a Mutex<Cache>,
    warnings: &mut Vec<String>,
) -> MutexGuard<'a, Cache> {
    match cache.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            // This is disposable optimization state, not a cached policy approval.
            let mut guard = poisoned.into_inner();
            *guard = Cache::default();
            cache.clear_poison();
            warnings.push(
                "Policy mutation cache reset after an interrupted negotiation; \
                 Windows will evaluate this creation again."
                    .into(),
            );
            guard
        }
    }
}

pub(super) fn key() -> Result<Key, String> {
    Ok(Key {
        creator: creator()?,
    })
}

fn token_identity(token: HANDLE) -> Result<[(u32, i32); 2], String> {
    let mut statistics = TOKEN_STATISTICS::default();
    let mut written = 0;
    let size = std::mem::size_of::<TOKEN_STATISTICS>() as u32;
    // SAFETY: token is an owned query-capable handle; storage is
    // writable and sized for the requested fixed TOKEN_STATISTICS structure.
    unsafe {
        GetTokenInformation(
            token,
            TokenStatistics,
            Some((&mut statistics as *mut TOKEN_STATISTICS).cast()),
            size,
            &mut written,
        )
    }
    .map_err(|error| format!("cannot query the caller token: {error}"))?;
    if written != size {
        return Err("the caller token query returned an invalid size".into());
    }
    Ok([
        (statistics.TokenId.LowPart, statistics.TokenId.HighPart),
        (
            statistics.ModifiedId.LowPart,
            statistics.ModifiedId.HighPart,
        ),
    ])
}

fn creator() -> Result<Creator, String> {
    let mut process = HANDLE::default();
    // SAFETY: current process is valid and output points to writable handle storage.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut process) }
        .map_err(|error| format!("cannot open the creator process token: {error}"))?;
    let process = OwnedHandle::new(process);
    let mut thread = HANDLE::default();
    // SAFETY: current thread is valid; request query access only, checked as self.
    let thread = match unsafe {
        OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut thread)
    } {
        Ok(()) => Some(OwnedHandle::new(thread)),
        Err(error) if error.code() == windows::core::HRESULT::from_win32(ERROR_NO_TOKEN.0) => None,
        Err(error) => return Err(format!("cannot open the effective creator token: {error}")),
    };
    let process = token_identity(process.get())?;
    let effective = match thread {
        Some(thread) => token_identity(thread.get())?,
        None => process,
    };
    Ok([process[0], process[1], effective[0], effective[1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_cache_partitions_creators_and_bounds_remembered_restrictions() {
        let mut cache = Cache::default();
        let first = key().unwrap();
        let hints = vec![MutationHint::RemoveCapability("first".into())];
        cache.remember(first, &hints).unwrap();
        let mut other = first;
        other.creator[0].0 ^= 1;
        assert!(cache.get(other).is_none());
        for index in 1..=MAX_ENTRIES {
            cache
                .remember(
                    first,
                    &[MutationHint::RemoveCapability(format!("cap-{index}"))],
                )
                .unwrap();
        }
        assert_eq!(cache.entries.len(), MAX_ENTRIES);
        assert!(cache.entries.iter().all(|entry| entry.hints != hints));
        assert!(cache.retained_bytes <= MAX_RETAINED_BYTES);
    }

    #[test]
    fn mutation_cache_rejects_oversized_state_without_losing_a_valid_entry() {
        let mut cache = Cache::default();
        let first = key().unwrap();
        let retained = [MutationHint::RemoveCapability("retained".into())];
        cache.remember(first, &retained).unwrap();
        let large = [MutationHint::RemoveCapability(
            "x".repeat(MAX_RETAINED_BYTES),
        )];
        assert!(cache.remember(first, &large).is_err());
        assert_eq!(cache.get(first).unwrap().hints, retained);
    }

    #[test]
    fn mutation_cache_recovers_by_discarding_interrupted_optimization_state() {
        let cache = std::sync::Arc::new(Mutex::new(Cache::default()));
        let writer = cache.clone();
        assert!(std::thread::spawn(move || {
            let _guard = writer.lock().unwrap();
            panic!("interrupt cache ownership");
        })
        .join()
        .is_err());
        let mut warnings = Vec::new();
        let guard = lock(&cache, &mut warnings);
        assert!(guard.entries.is_empty());
        assert!(!cache.is_poisoned());
        assert!(warnings[0].contains("cache reset"));
    }
}
