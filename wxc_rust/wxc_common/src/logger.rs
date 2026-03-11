use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Console,
    Buffer,
}

#[derive(Debug)]
pub struct Logger {
    mode: Mode,
    buffer: String,
}

impl Logger {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            buffer: String::new(),
        }
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn log(&mut self, msg: &str) {
        match self.mode {
            Mode::Console => print!("{}", msg),
            Mode::Buffer => self.buffer.push_str(msg),
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
    }

    pub fn get_buffer(&self) -> &str {
        &self.buffer
    }

    pub fn clear_buffer(&mut self) {
        self.buffer.clear();
    }
}

impl fmt::Write for Logger {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.log(s);
        Ok(())
    }
}
