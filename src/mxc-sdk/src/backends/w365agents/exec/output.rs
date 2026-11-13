// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const FINAL_DRAIN: Duration = Duration::from_secs(5);

pub(crate) struct OutputRelays {
    workers: [OutputWorker; 2],
    #[cfg(unix)]
    destinations: UnixOutputs,
}

pub(crate) struct OutputResult {
    pub(crate) writes: io::Result<()>,
    pub(crate) undelivered: [bool; 2],
}

impl OutputRelays {
    pub(crate) fn start_native(
        stdout: crate::mxc_common::sandbox_process::OwnedPipe,
        stderr: crate::mxc_common::sandbox_process::OwnedPipe,
    ) -> io::Result<Self> {
        let (stdout, close_stdout) = native_reader(stdout)?;
        let (stderr, close_stderr) = native_reader(stderr)?;
        Self::start(
            stdout,
            stderr,
            move || close_stdout.close(),
            move || close_stderr.close(),
        )
    }

    pub(crate) fn start(
        stdout: Box<dyn Read + Send>,
        stderr: Box<dyn Read + Send>,
        close_stdout: impl Fn() + Send + 'static,
        close_stderr: impl Fn() + Send + 'static,
    ) -> io::Result<Self> {
        #[cfg(unix)]
        let mut destinations = UnixOutputs::new()?;
        #[cfg(unix)]
        let out_file = destinations.files[0].try_clone()?;
        #[cfg(unix)]
        let err_file = destinations.files[1].try_clone()?;
        #[cfg(unix)]
        destinations.activate()?;
        let out = OutputWorker::start(
            stdout,
            close_stdout,
            false,
            #[cfg(unix)]
            out_file,
        )?;
        let err = OutputWorker::start(
            stderr,
            close_stderr,
            true,
            #[cfg(unix)]
            err_file,
        )?;
        Ok(Self {
            workers: [out, err],
            #[cfg(unix)]
            destinations,
        })
    }

    pub(crate) fn finish(mut self) -> OutputResult {
        let deadline = Instant::now() + FINAL_DRAIN;
        while self.workers.iter().any(|worker| !worker.finished()) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        let undelivered = self.workers.each_ref().map(|worker| !worker.finished());
        for worker in &self.workers {
            worker.cancel();
        }
        let out = self.workers[0].join();
        let err = self.workers[1].join();
        #[cfg(unix)]
        let restored = self.destinations.restore();
        #[cfg(windows)]
        let restored = Ok(());
        OutputResult {
            writes: if undelivered.iter().any(|value| *value) {
                Err(io::Error::other(
                    "host_output_undelivered: host output did not drain within 5 seconds after execution completed",
                ))
            } else {
                out.and(err).and(restored)
            },
            undelivered,
        }
    }
}

fn native_reader(
    pipe: crate::mxc_common::sandbox_process::OwnedPipe,
) -> io::Result<(
    Box<dyn Read + Send>,
    Box<dyn crate::mxc_common::sandbox_process::StreamCloser>,
)> {
    #[cfg(unix)]
    let reader = crate::mxc_common::interruptible_reader::InterruptibleReader::new(pipe)?;
    #[cfg(windows)]
    let reader = {
        use crate::mxc_common::process_util::{InterruptiblePipeReader, OwnedHandle};
        use std::os::windows::io::IntoRawHandle;
        InterruptiblePipeReader::new(OwnedHandle::new(windows::Win32::Foundation::HANDLE(
            pipe.into_raw_handle(),
        )))
    };
    let closer = reader.canceller();
    Ok((Box::new(reader), Box::new(closer)))
}

struct OutputWorker {
    thread: Option<JoinHandle<io::Result<()>>>,
    cancelled: Arc<AtomicBool>,
    close_source: Box<dyn Fn() + Send>,
}

impl OutputWorker {
    fn start(
        mut source: Box<dyn Read + Send>,
        close_source: impl Fn() + Send + 'static,
        stderr: bool,
        #[cfg(unix)] mut destination: std::fs::File,
    ) -> io::Result<Self> {
        #[cfg(windows)]
        let destination = {
            use std::io::IsTerminal;
            use std::os::windows::io::{AsRawHandle, BorrowedHandle};
            let (terminal, handle) = if stderr {
                let output = io::stderr();
                (output.is_terminal(), output.as_raw_handle())
            } else {
                let output = io::stdout();
                (output.is_terminal(), output.as_raw_handle())
            };
            if terminal {
                None
            } else {
                if handle.is_null() || handle as isize == -1 {
                    return Err(io::Error::other("host output has no valid handle"));
                }
                // Do not buffer redirected writes in global stdio: a cancelled
                // flush must not be retried by process-exit stdio cleanup.
                // SAFETY: the host retains the original endpoint during duplication.
                Some(std::fs::File::from(
                    unsafe { BorrowedHandle::borrow_raw(handle) }.try_clone_to_owned()?,
                ))
            }
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&cancelled);
        let thread = thread::Builder::new()
            .name("w365-host-output".into())
            .spawn(move || {
                #[cfg(windows)]
                {
                    if let Some(mut destination) = destination {
                        forward(&mut source, &mut destination, &stop)
                    } else if stderr {
                        forward(&mut source, &mut io::stderr().lock(), &stop)
                    } else {
                        forward(&mut source, &mut io::stdout().lock(), &stop)
                    }
                }
                #[cfg(unix)]
                {
                    use std::os::fd::AsRawFd;
                    let mut signals = nix::sys::signal::SigSet::empty();
                    signals.add(nix::sys::signal::Signal::SIGPIPE);
                    signals.thread_block().map_err(io::Error::from)?;
                    let _ = stderr;
                    let fd = destination.as_raw_fd();
                    forward(&mut source, &mut destination, &stop, fd)
                }
            })?;
        Ok(Self {
            thread: Some(thread),
            cancelled,
            close_source: Box::new(close_source),
        })
    }

    fn finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }

    fn cancel(&self) {
        if self.finished() {
            return;
        }
        self.cancelled.store(true, Ordering::Release);
        (self.close_source)();
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows::Win32::Foundation::HANDLE;
            use windows::Win32::System::IO::CancelSynchronousIo;
            // Retry across the flag-check -> synchronous write window.
            while let Some(worker) = self.thread.as_ref().filter(|worker| !worker.is_finished()) {
                // SAFETY: JoinHandle owns this exact worker's thread handle.
                unsafe {
                    let _ = CancelSynchronousIo(HANDLE(worker.as_raw_handle()));
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
    }

    fn join(&mut self) -> io::Result<()> {
        self.thread.take().map_or(Ok(()), |worker| {
            worker
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("host output relay panicked")))
        })
    }
}

impl Drop for OutputWorker {
    fn drop(&mut self) {
        self.cancel();
        let _ = self.join();
    }
}

fn forward(
    source: &mut dyn Read,
    output: &mut dyn Write,
    cancelled: &AtomicBool,
    #[cfg(unix)] fd: libc::c_int,
) -> io::Result<()> {
    let mut bytes = [0; 8192];
    while !cancelled.load(Ordering::Acquire) {
        let count = match source.read(&mut bytes) {
            Ok(0) => return Ok(()),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let mut pending = &bytes[..count];
        while !pending.is_empty() {
            if cancelled.load(Ordering::Acquire) {
                return Err(io::Error::other(
                    "host_output_undelivered: output relay cancelled",
                ));
            }
            match output.write(pending) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => pending = &pending[count..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    #[cfg(windows)]
                    thread::sleep(Duration::from_millis(1));
                    #[cfg(unix)]
                    wait_writable(fd)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        output.flush()?;
    }
    Ok(())
}

#[cfg(unix)]
fn wait_writable(fd: libc::c_int) -> io::Result<()> {
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: the output worker owns this fd throughout the bounded wait.
    if unsafe { libc::poll(&mut descriptor, 1, 5) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    } else if descriptor.revents & libc::POLLNVAL != 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    Ok(())
}

#[cfg(unix)]
struct UnixOutputs {
    files: [std::fs::File; 2],
    flags: [libc::c_int; 2],
    restored: bool,
}

#[cfg(unix)]
impl UnixOutputs {
    fn new() -> io::Result<Self> {
        fn duplicate(fd: libc::c_int) -> io::Result<(std::fs::File, libc::c_int)> {
            use std::os::fd::BorrowedFd;
            // SAFETY: borrowing the host endpoint only to duplicate it.
            let file =
                std::fs::File::from(unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()?);
            // SAFETY: the duplicate keeps this endpoint live.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok((file, flags))
        }
        // Capture both before changing either: 2>&1 shares one open file description.
        let (out, out_flags) = duplicate(libc::STDOUT_FILENO)?;
        let (err, err_flags) = duplicate(libc::STDERR_FILENO)?;
        Ok(Self {
            files: [out, err],
            flags: [out_flags, err_flags],
            restored: false,
        })
    }

    fn activate(&mut self) -> io::Result<()> {
        self.set_flags(true)
    }

    fn restore(&mut self) -> io::Result<()> {
        if !self.restored {
            self.set_flags(false)?;
            self.restored = true;
        }
        Ok(())
    }

    fn set_flags(&self, nonblocking: bool) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        for (file, flags) in self.files.iter().zip(self.flags) {
            let flags = if nonblocking {
                flags | libc::O_NONBLOCK
            } else {
                flags
            };
            // SAFETY: the endpoints stay owned; restore only after both workers stop.
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for UnixOutputs {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
