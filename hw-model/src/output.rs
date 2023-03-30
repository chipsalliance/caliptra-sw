// Licensed under the Apache-2.0 license

use std::io::LineWriter;
use std::{
    cell::{Cell, RefCell},
    io::Write,
    rc::Rc,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitStatus {
    Passed,
    Failed,
}

struct OutputSinkImpl {
    exit_status: Cell<Option<ExitStatus>>,
    new_uart_output: Cell<String>,
    log_writer: RefCell<LineWriter<Box<dyn std::io::Write>>>,
    at_start_of_line: Cell<bool>,
}

#[derive(Clone)]
pub struct OutputSink(Rc<OutputSinkImpl>);
impl OutputSink {
    pub fn push_uart_char(&self, ch: u8) {
        const UART_LOG_PREFIX: &[u8] = b"UART: ";

        const TESTCASE_FAILED: u8 = 0x01;
        const TESTCASE_PASSED: u8 = 0xff;

        match ch {
            TESTCASE_PASSED => {
                // This is the same string as printed by the verilog test-bench
                self.0
                    .log_writer
                    .borrow_mut()
                    .write_all(b"* TESTCASE PASSED\n")
                    .unwrap();
                self.0.exit_status.set(Some(ExitStatus::Passed));
            }
            TESTCASE_FAILED => {
                // This is the same string as printed by the verilog test-bench
                self.0
                    .log_writer
                    .borrow_mut()
                    .write_all(b"* TESTCASE FAILED\n")
                    .unwrap();
                self.0.exit_status.set(Some(ExitStatus::Failed));
            }
            0x20..=0x7f | b'\r' | b'\n' | b'\t' => {
                let mut s = self.0.new_uart_output.take();
                s.push(ch as char);
                self.0.new_uart_output.set(s);

                let log_writer = &mut self.0.log_writer.borrow_mut();
                if self.0.at_start_of_line.get() {
                    log_writer.flush().unwrap();
                    log_writer.write_all(UART_LOG_PREFIX).unwrap();
                    self.0.at_start_of_line.set(false);
                }
                log_writer.write_all(&[ch]).unwrap();
                if ch == b'\n' {
                    self.0.at_start_of_line.set(true);
                }
            }
            _ => {
                writeln!(
                    self.0.log_writer.borrow_mut(),
                    "Unknown generic load 0x{ch:02x}"
                )
                .unwrap();
            }
        }
    }
}
impl std::io::Write for &OutputSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.log_writer.borrow_mut().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.log_writer.borrow_mut().flush()
    }
}

pub struct Output {
    output: String,
    sink: OutputSink,
}
impl Output {
    pub fn new(log_writer: impl std::io::Write + 'static) -> Self {
        Self::new_internal(Box::new(log_writer))
    }
    fn new_internal(log_writer: Box<dyn std::io::Write>) -> Self {
        Self {
            output: "".into(),
            sink: OutputSink(Rc::new(OutputSinkImpl {
                new_uart_output: Default::default(),
                log_writer: RefCell::new(LineWriter::new(log_writer)),
                exit_status: Cell::new(None),
                at_start_of_line: Cell::new(true),
            })),
        }
    }
    pub fn sink(&self) -> &OutputSink {
        &self.sink
    }
    pub fn logger(&self) -> impl std::io::Write + '_ {
        &self.sink
    }

    /// Peek at all the output captured so far
    pub fn peek(&mut self) -> &str {
        self.process_new_data();
        &self.output
    }

    /// Take at most `limit` characters from the output
    pub fn take(&mut self, limit: usize) -> String {
        self.process_new_data();
        if self.output.len() <= limit {
            std::mem::take(&mut self.output)
        } else {
            let remaining = self.output[limit..].to_string();
            let mut result = std::mem::replace(&mut self.output, remaining);
            result.truncate(limit);
            result
        }
    }

    fn process_new_data(&mut self) {
        let new_data = self.sink.0.new_uart_output.take();
        if self.output.is_empty() {
            self.output = new_data;
        } else {
            self.output.push_str(&new_data);
        }
    }

    /// Returns true if the caliptra microcontroller has signalled that it wants to exit
    /// (this only makes sense when running test cases on the microcontroller)
    pub fn exit_requested(&self) -> bool {
        self.exit_status().is_some()
    }

    pub fn exit_status(&self) -> Option<ExitStatus> {
        self.sink.0.exit_status.get()
    }
}

#[cfg(test)]
mod tests {

    use std::io::Sink;

    use super::*;

    #[derive(Clone)]
    pub struct Log {
        log: Rc<RefCell<Vec<u8>>>,
    }
    impl Log {
        /// Construct an empty `Log`.
        pub fn new() -> Self {
            Self {
                log: Rc::new(RefCell::new(vec![])),
            }
        }
        fn into_string(self) -> String {
            String::from_utf8(self.log.take()).unwrap()
        }
    }
    impl Default for Log {
        fn default() -> Self {
            Self::new()
        }
    }
    impl std::io::Write for Log {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            std::io::Write::write(&mut *self.log.borrow_mut(), buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            std::io::Write::flush(&mut *self.log.borrow_mut())
        }
    }

    #[test]
    fn test_take() {
        let log = Log::new();
        let mut out = Output::new(log.clone());

        out.sink().push_uart_char(b'h');
        out.sink().push_uart_char(b'i');
        out.sink().push_uart_char(b'!');
        out.sink().push_uart_char(b'\n');

        assert_eq!(&out.take(2), "hi");
        assert_eq!(&out.take(10), "!\n");
        assert_eq!(&out.take(10), "");

        assert_eq!(log.into_string(), "UART: hi!\n");
    }

    #[test]
    fn test_peek() {
        let mut out = Output::new(Sink::default());

        out.sink().push_uart_char(b'h');
        out.sink().push_uart_char(b'i');
        assert_eq!(out.peek(), "hi");
        out.sink().push_uart_char(b'!');
        assert_eq!(out.peek(), "hi!");
    }

    #[test]
    fn test_passed() {
        let log = Log::new();
        let mut out = Output::new(log.clone());

        out.sink().push_uart_char(b'h');
        out.sink().push_uart_char(b'i');
        out.sink().push_uart_char(b'\n');
        assert_eq!(&out.take(10), "hi\n");

        out.sink().push_uart_char(0xff);
        assert_eq!(out.exit_status(), Some(ExitStatus::Passed));
        assert_eq!(&out.take(10), "");

        assert_eq!(log.into_string(), "UART: hi\n* TESTCASE PASSED\n");
    }

    #[test]
    fn test_failed() {
        let log = Log::new();
        let mut out = Output::new(log.clone());

        out.sink().push_uart_char(b'h');
        out.sink().push_uart_char(b'i');
        out.sink().push_uart_char(b'\n');
        out.sink().push_uart_char(0x01);
        assert_eq!(out.exit_status(), Some(ExitStatus::Failed));
        assert_eq!(&out.take(10), "hi\n");

        assert_eq!(log.into_string(), "UART: hi\n* TESTCASE FAILED\n");
    }

    #[test]
    fn test_unknown_generic_load() {
        let log = Log::new();
        let mut out = Output::new(log.clone());
        out.sink().push_uart_char(0xd3);

        assert_eq!(&out.take(30), "");
        assert_eq!(log.into_string(), "Unknown generic load 0xd3\n");
    }
}
