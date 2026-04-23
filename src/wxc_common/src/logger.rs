// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Console,
    Buffer,
}

#[derive(Debug)]
pub struct Logger {
    mode: Mode,
    buffer: String,
    file: Option<File>,
}

impl Logger {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            buffer: String::new(),
            file: None,
        }
    }

    /// Enable writing to a log file in addition to console/buffer output.
    pub fn enable_file_sink(&mut self, path: &Path) -> std::io::Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        self.file = Some(file);
        Ok(())
    }

    pub fn log(&mut self, msg: &str) {
        match self.mode {
            Mode::Console => print!("{}", msg),
            Mode::Buffer => self.buffer.push_str(msg),
        }
        if let Some(ref mut f) = self.file {
            let _ = write!(f, "{}", msg);
        }
    }

    pub fn log_line(&mut self, msg: &str) {
        match self.mode {
            Mode::Console => println!("{}", msg),
            Mode::Buffer => {
                self.buffer.push_str(msg);
                self.buffer.push('\n');
            }
        }
        if let Some(ref mut f) = self.file {
            let _ = writeln!(f, "{}", msg);
        }
    }

    pub fn get_buffer(&self) -> &str {
        &self.buffer
    }
}

impl fmt::Write for Logger {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.log(s);
        Ok(())
    }
}
