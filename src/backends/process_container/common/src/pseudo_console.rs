// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread::JoinHandle;

use windows::Win32::System::Console::{
    ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, COORD, HPCON,
};

use wxc_common::process_util::{create_std_pipes, SendOwnedHandle};
use wxc_common::sandbox_process::{NativeStdio, PtySize};

pub(crate) struct PseudoConsole {
    handle: HPCON,
    input: Mutex<Option<SendOwnedHandle>>,
    output: SendOwnedHandle,
    output_claimed: AtomicBool,
    size: Mutex<PtySize>,
}

unsafe impl Send for PseudoConsole {}

impl PseudoConsole {
    pub(crate) fn new(size: PtySize) -> std::io::Result<Self> {
        let coord = coord(size)?;
        let (input_read, mut input_write) =
            create_std_pipes(false).map_err(std::io::Error::other)?;
        let (mut output_read, output_write) =
            create_std_pipes(true).map_err(std::io::Error::other)?;
        let handle = unsafe { CreatePseudoConsole(coord, input_read.get(), output_write.get(), 0) }
            .map_err(std::io::Error::other)?;

        Ok(Self {
            handle,
            input: Mutex::new(Some(SendOwnedHandle::take(&mut input_write))),
            output: SendOwnedHandle::take(&mut output_read),
            output_claimed: AtomicBool::new(false),
            size: Mutex::new(size),
        })
    }

    pub(crate) fn attribute_value(&self) -> *const core::ffi::c_void {
        self.handle.0 as *const core::ffi::c_void
    }

    pub(crate) fn clone_reader(&self) -> std::io::Result<Box<dyn Read + Send>> {
        let handle = self.output.try_clone_owned_handle()?;
        self.output_claimed.store(true, Ordering::Release);
        Ok(Box::new(std::fs::File::from(handle)))
    }

    pub(crate) fn take_writer(&self) -> std::io::Result<Box<dyn Write + Send>> {
        let writer = self
            .input
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "the PTY writer has already been taken",
                )
            })?;
        Ok(Box::new(std::fs::File::from(
            writer.into_std_owned_handle()?,
        )))
    }

    pub(crate) fn take_native_stdio(&self) -> std::io::Result<Option<NativeStdio>> {
        let stdout = self.output.try_clone_owned_handle()?;
        let Some(stdin) = self
            .input
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        else {
            return Ok(None);
        };
        self.output_claimed.store(true, Ordering::Release);
        Ok(Some(NativeStdio {
            stdin: Some(stdin.into_std_owned_handle()?),
            stdout: Some(stdout),
            stderr: None,
        }))
    }

    pub(crate) fn prepare_wait(&self) -> std::io::Result<Option<JoinHandle<()>>> {
        self.input
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();

        if self
            .output_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(None);
        }

        let output = match self.output.try_clone_owned_handle() {
            Ok(output) => output,
            Err(error) => {
                self.output_claimed.store(false, Ordering::Release);
                return Err(error);
            }
        };
        match std::thread::Builder::new()
            .name("mxc-process-container-pty-drain".to_string())
            .spawn(move || {
                let mut output = std::fs::File::from(output);
                let _ = std::io::copy(&mut output, &mut std::io::sink());
            }) {
            Ok(thread) => Ok(Some(thread)),
            Err(error) => {
                self.output_claimed.store(false, Ordering::Release);
                Err(error)
            }
        }
    }

    pub(crate) fn resize(&self, size: PtySize) -> std::io::Result<()> {
        unsafe { ResizePseudoConsole(self.handle, coord(size)?) }.map_err(std::io::Error::other)?;
        *self
            .size
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = size;
        Ok(())
    }

    pub(crate) fn size(&self) -> PtySize {
        *self
            .size
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub(crate) fn close_after_termination(
    pseudo_console: &mut Option<PseudoConsole>,
    output_thread: Option<JoinHandle<()>>,
) -> std::io::Result<()> {
    pseudo_console.take();
    if let Some(thread) = output_thread {
        thread
            .join()
            .map_err(|_| std::io::Error::other("PTY output drain thread panicked"))?;
    }
    Ok(())
}

impl Drop for PseudoConsole {
    fn drop(&mut self) {
        unsafe { ClosePseudoConsole(self.handle) };
    }
}

fn coord(size: PtySize) -> std::io::Result<COORD> {
    size.validate()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    Ok(COORD {
        X: size.cols as i16,
        Y: size.rows as i16,
    })
}
