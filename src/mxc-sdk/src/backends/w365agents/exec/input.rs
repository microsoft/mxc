// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::mxc_common::sandbox_process::OwnedPipe;
use std::fs::File;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

pub(crate) struct InputRelay {
    worker: Option<JoinHandle<Result<(), InputError>>>,
    cancelled: Arc<AtomicBool>,
    #[cfg(unix)]
    host: Option<HostInput>,
}

pub(crate) struct CompletedInput {
    result: io::Result<()>,
    #[cfg(unix)]
    host: Option<HostInput>,
}

impl CompletedInput {
    pub(crate) fn result(self) -> io::Result<()> {
        #[cfg(unix)]
        let restored = self.host.as_ref().map_or(Ok(()), HostInput::restore);
        #[cfg(windows)]
        let restored = Ok(());
        self.result.and(restored)
    }
}

enum InputError {
    Read(io::Error),
    Write(io::Error),
}

impl InputRelay {
    pub(crate) fn start(input: OwnedPipe) -> io::Result<Self> {
        let input = File::from(input);
        #[cfg(unix)]
        let host = HostInput::new()?;
        #[cfg(unix)]
        let source = host.file.try_clone()?;
        #[cfg(unix)]
        nonblocking(&input)?;
        #[cfg(windows)]
        let source = {
            use std::io::IsTerminal;
            use std::os::windows::io::{AsRawHandle, BorrowedHandle};
            let handle = io::stdin().as_raw_handle();
            if handle.is_null() || handle as isize == -1 {
                return Err(io::Error::other("host stdin has no valid handle"));
            }
            let console = io::stdin().is_terminal();
            let file = if console {
                // A duplicate shares conhost's cooked-read context with host stdin;
                // cancelling it can leave that context consuming later commands.
                std::fs::OpenOptions::new().read(true).open("CONIN$")?
            } else {
                // SAFETY: the host retains stdin while its endpoint is duplicated.
                File::from(unsafe { BorrowedHandle::borrow_raw(handle) }.try_clone_to_owned()?)
            };
            (file, console)
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let stop = cancelled.clone();
        let worker = thread::Builder::new()
            .name("w365-host-input".into())
            .spawn(move || {
                #[cfg(unix)]
                {
                    use std::os::fd::AsRawFd;
                    let mut signals = nix::sys::signal::SigSet::empty();
                    signals.add(nix::sys::signal::Signal::SIGPIPE);
                    signals
                        .thread_block()
                        .map_err(|error| InputError::Write(error.into()))?;
                    let fd = source.as_raw_fd();
                    forward(source, input, &stop, fd)
                }
                #[cfg(windows)]
                {
                    let (source, console) = source;
                    if console {
                        forward(ConsoleInput::new(source), input, &stop)
                    } else {
                        forward(source, input, &stop)
                    }
                }
            })?;
        Ok(Self {
            worker: Some(worker),
            cancelled,
            #[cfg(unix)]
            host: Some(host),
        })
    }

    pub(crate) fn finish(mut self, confirmed_exit: bool) -> CompletedInput {
        self.cancel();
        let result = self.join();
        let result = match result {
            Ok(()) => Ok(()),
            Err(InputError::Write(error)) if confirmed_exit && pipe_closed(&error) => Ok(()),
            Err(InputError::Read(error)) => {
                Err(io::Error::other(format!("read host stdin: {error}")))
            }
            Err(InputError::Write(error)) => {
                Err(io::Error::other(format!("write execution stdin: {error}")))
            }
        };
        // stdout/stderr may share stdin's open description. Retain its original
        // flags until output workers have also stopped and restored their flags.
        CompletedInput {
            result,
            #[cfg(unix)]
            host: self.host.take(),
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows::Win32::Foundation::HANDLE;
            use windows::Win32::System::IO::CancelSynchronousIo;
            // Retry across the cancellation-check -> kernel-I/O window.
            while let Some(worker) = self.worker.as_ref().filter(|worker| !worker.is_finished()) {
                // SAFETY: JoinHandle owns this exact input worker's thread handle.
                unsafe {
                    let _ = CancelSynchronousIo(HANDLE(worker.as_raw_handle()));
                }
                thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }

    fn join(&mut self) -> Result<(), InputError> {
        self.worker.take().map_or(Ok(()), |worker| {
            worker.join().unwrap_or_else(|_| {
                Err(InputError::Read(io::Error::other(
                    "host input relay panicked",
                )))
            })
        })
    }
}

impl Drop for InputRelay {
    fn drop(&mut self) {
        self.cancel();
        let _ = self.join();
    }
}

#[cfg(windows)]
struct ConsoleInput {
    file: File,
    pending: std::collections::VecDeque<u8>,
    high_surrogate: Option<u16>,
}

#[cfg(windows)]
impl ConsoleInput {
    fn new(file: File) -> Self {
        Self {
            file,
            pending: Default::default(),
            high_surrogate: None,
        }
    }
}

#[cfg(windows)]
impl Read for ConsoleInput {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::{
            GetLastError, SetLastError, ERROR_OPERATION_ABORTED, HANDLE, WIN32_ERROR,
        };
        use windows::Win32::System::Console::{ReadConsoleW, CONSOLE_READCONSOLE_CONTROL};
        if bytes.is_empty() {
            return Ok(0);
        }
        while self.pending.is_empty() {
            let mut wide = [0u16; 2048];
            let prefix = usize::from(self.high_surrogate.is_some());
            if let Some(high) = self.high_surrogate.take() {
                wide[0] = high;
            }
            let mut read = 0;
            let control = CONSOLE_READCONSOLE_CONTROL {
                nLength: std::mem::size_of::<CONSOLE_READCONSOLE_CONTROL>() as u32,
                dwCtrlWakeupMask: 1 << 26,
                ..Default::default()
            };
            // Use a direct console read: global buffered stdin can retry an
            // interrupted read internally, hiding cancellation from our worker.
            // SAFETY: file owns the console handle; wide and read are valid buffers.
            unsafe {
                SetLastError(WIN32_ERROR(0));
                if ReadConsoleW(
                    HANDLE(self.file.as_raw_handle()),
                    wide[prefix..].as_mut_ptr().cast(),
                    (wide.len() - prefix) as u32,
                    &mut read,
                    Some(&control),
                )
                .is_err()
                {
                    return Err(io::Error::last_os_error());
                }
                if read == 0 && GetLastError() == ERROR_OPERATION_ABORTED {
                    return Err(io::Error::from_raw_os_error(
                        ERROR_OPERATION_ABORTED.0 as i32,
                    ));
                }
            }
            if read == 0 {
                return if prefix == 0 {
                    Ok(0)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "host console ended within a UTF-16 surrogate pair",
                    ))
                };
            }
            let mut count = read as usize + prefix;
            if wide[count - 1] == 26 {
                count -= 1;
            }
            if count == 0 {
                return Ok(0);
            }
            if (0xd800..=0xdbff).contains(&wide[count - 1]) {
                self.high_surrogate = Some(wide[count - 1]);
                count -= 1;
            }
            let text = String::from_utf16(&wide[..count])
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            self.pending.extend(text.bytes());
        }
        let count = bytes.len().min(self.pending.len());
        for (destination, byte) in bytes[..count].iter_mut().zip(self.pending.drain(..count)) {
            *destination = byte;
        }
        Ok(count)
    }
}

fn forward(
    mut source: impl Read,
    mut input: File,
    stop: &AtomicBool,
    #[cfg(unix)] source_fd: std::os::fd::RawFd,
) -> Result<(), InputError> {
    #[cfg(unix)]
    use std::os::fd::AsRawFd;
    let mut bytes = [0; 8192];
    while !stop.load(Ordering::Acquire) {
        let count = match source.read(&mut bytes) {
            Ok(0) => return Ok(()),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            #[cfg(unix)]
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_ready(source_fd, libc::POLLIN).map_err(InputError::Read)?;
                continue;
            }
            Err(error) if cancelled_io(&error, stop) => return Ok(()),
            Err(error) => return Err(InputError::Read(error)),
        };
        let mut pending = &bytes[..count];
        while !pending.is_empty() && !stop.load(Ordering::Acquire) {
            match input.write(pending) {
                Ok(0) => return Err(InputError::Write(io::ErrorKind::WriteZero.into())),
                Ok(count) => pending = &pending[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                #[cfg(unix)]
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait_ready(input.as_raw_fd(), libc::POLLOUT).map_err(InputError::Write)?;
                }
                Err(error) if cancelled_io(&error, stop) => return Ok(()),
                Err(error) => return Err(InputError::Write(error)),
            }
        }
    }
    Ok(())
}

fn cancelled_io(error: &io::Error, stop: &AtomicBool) -> bool {
    #[cfg(windows)]
    {
        stop.load(Ordering::Acquire)
            && error.raw_os_error()
                == Some(windows::Win32::Foundation::ERROR_OPERATION_ABORTED.0 as i32)
    }
    #[cfg(unix)]
    {
        let _ = (error, stop);
        false
    }
}

fn pipe_closed(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::BrokenPipe {
        return true;
    }
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{ERROR_BROKEN_PIPE, ERROR_NO_DATA};
        matches!(error.raw_os_error(), Some(code)
            if code == ERROR_BROKEN_PIPE.0 as i32 || code == ERROR_NO_DATA.0 as i32)
    }
    #[cfg(unix)]
    {
        false
    }
}

#[cfg(unix)]
struct HostInput {
    file: File,
    flags: i32,
}

#[cfg(unix)]
impl HostInput {
    fn new() -> io::Result<Self> {
        use std::os::fd::{AsRawFd, BorrowedFd};
        // SAFETY: the host retains stdin while its endpoint is duplicated.
        let file = File::from(
            unsafe { BorrowedFd::borrow_raw(io::stdin().as_raw_fd()) }.try_clone_to_owned()?,
        );
        // SAFETY: file owns this descriptor.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let host = Self { file, flags };
        nonblocking(&host.file)?;
        Ok(host)
    }

    fn restore(&self) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        // Duplicates share flags with host stdin; restore only after the worker joins.
        // SAFETY: file owns this descriptor, including during setup-failure cleanup.
        if unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_SETFL, self.flags) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(unix)]
impl Drop for HostInput {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(unix)]
fn nonblocking(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: file owns the descriptor for both flag operations.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn wait_ready(fd: std::os::fd::RawFd, events: i16) -> io::Result<()> {
    let mut poll = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    // SAFETY: poll is a valid single descriptor entry for the bounded wait.
    let result = unsafe { libc::poll(&mut poll, 1, 5) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    Ok(())
}
