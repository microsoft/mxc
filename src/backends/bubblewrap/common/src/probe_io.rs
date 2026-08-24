// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deadline-safe output capture for the host probes.
//!
//! A pipe reports EOF only once *every* write end is closed, so a background
//! descendant holding the child's inherited descriptor can block a read past
//! the deadline the caller enforced -- and killing the child does not help.
//! An unlinked temp file always reports EOF, removing that failure mode along
//! with the pipe-buffer deadlock.

use std::fs::File;
use std::process::Stdio;

/// Cap on how much captured output is read into memory. Probes emit version
/// banners and help text, so this is generous.
const MAX_CAPTURE: u64 = 64 * 1024;

/// Create a capture file for a child's `stream`. Unlinked at creation, so it
/// needs no cleanup and cannot collide with a concurrent probe.
pub(crate) fn capture_file(stream: &str) -> Result<File, String> {
    tempfile::tempfile()
        .map_err(|error| format!("failed to create a temporary file for {stream}: {error}"))
}

/// Redirect a child's `stream` into `file` while keeping it readable here.
pub(crate) fn capture_target(file: &File, stream: &str) -> Result<Stdio, String> {
    file.try_clone()
        .map(Stdio::from)
        .map_err(|error| format!("failed to redirect {stream}: {error}"))
}

/// Read back what a child wrote into `file`.
///
/// Reads are positional: the child holds a dup that shares this file's offset,
/// so seeking would move it out from under a descendant still writing. Capture
/// is best-effort -- the caller already holds the exit status that matters.
pub(crate) fn read_capture(file: &File) -> Vec<u8> {
    let mut buffer = vec![0u8; MAX_CAPTURE as usize];
    let mut filled = 0;
    while filled < buffer.len() {
        match read_at(file, &mut buffer[filled..], filled as u64) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    buffer.truncate(filled);
    buffer
}

#[cfg(unix)]
fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buffer, offset)
}

#[cfg(windows)]
fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buffer, offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn capture_round_trips_child_output() {
        let file = capture_file("stdout").expect("capture file");
        let mut writer = file.try_clone().expect("dup");
        write!(writer, "bubblewrap 0.11.2").expect("write");
        assert_eq!(read_capture(&file), b"bubblewrap 0.11.2");
    }

    #[test]
    fn capture_is_bounded() {
        let file = capture_file("stdout").expect("capture file");
        let mut writer = file.try_clone().expect("dup");
        writer
            .write_all(&vec![b'x'; (MAX_CAPTURE as usize) + 4096])
            .expect("write");
        assert_eq!(read_capture(&file).len(), MAX_CAPTURE as usize);
    }

    /// Reading must not depend on the writer being closed -- the
    /// descendant-held-descriptor case the pipe version could not survive.
    #[test]
    fn capture_reads_while_a_writer_is_still_open() {
        let file = capture_file("stdout").expect("capture file");
        let mut writer = file.try_clone().expect("dup");
        write!(writer, "partial").expect("write");
        assert_eq!(read_capture(&file), b"partial");
        drop(writer);
    }

    /// The dup shares this file's offset, so a read must not rewind it and make
    /// a still-running writer overwrite what it already emitted.
    #[test]
    fn reading_does_not_disturb_a_live_writer() {
        let file = capture_file("stdout").expect("capture file");
        let mut writer = file.try_clone().expect("dup");
        write!(writer, "one").expect("write");
        assert_eq!(read_capture(&file), b"one");
        write!(writer, "two").expect("write");
        assert_eq!(read_capture(&file), b"onetwo");
    }
}
