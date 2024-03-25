// Licensed under the Apache-2.0 license

use std::fmt::Display;
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
    now: Cell<u64>,
    next_write_needs_time_prefix: Cell<bool>,
}

struct PrettyU64(u64);
impl Display for PrettyU64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const RANKS: [u64; 7] = [
            1_000_000_000_000_000_000,
            1_000_000_000_000_000,
            1_000_000_000_000,
            1_000_000_000,
            1_000_000,
            1_000,
            1,
        ];
        const PADDING_RANK: u64 = 1_000_000_000;
        let mut prev_numbers = false;
        for rank in RANKS {
            if (self.0 / rank) > 0 || rank == 1 {
                if prev_numbers {
                    write!(f, "{:03}", (self.0 / rank) % 1000)?;
                } else if rank >= PADDING_RANK {
                    write!(f, "{}", (self.0 / rank) % 1000)?;
                } else {
                    write!(f, "{:>3}", (self.0 / rank) % 1000)?;
                }
                if rank > 1 {
                    write!(f, ",")?;
                }
                prev_numbers = true;
            } else if rank < PADDING_RANK {
                write!(f, "    ")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[test]
fn test_pretty_u64() {
    assert_eq!(PrettyU64(0).to_string(), "          0");
    assert_eq!(PrettyU64(1).to_string(), "          1");
    assert_eq!(PrettyU64(999).to_string(), "        999");
    assert_eq!(PrettyU64(1_000).to_string(), "      1,000");
    assert_eq!(PrettyU64(1_001).to_string(), "      1,001");
    assert_eq!(PrettyU64(999_999).to_string(), "    999,999");
    assert_eq!(PrettyU64(1_000_000).to_string(), "  1,000,000");
    assert_eq!(PrettyU64(1_000_001).to_string(), "  1,000,001");
    assert_eq!(PrettyU64(999_999_999).to_string(), "999,999,999");
    assert_eq!(PrettyU64(1_999_999_999).to_string(), "1,999,999,999");
}

#[derive(Clone)]
pub struct OutputSink(Rc<OutputSinkImpl>);
impl OutputSink {
    pub fn set_now(&self, now: u64) {
        self.0.now.set(now);
    }
    pub fn now(&self) -> u64 {
        self.0.now.get()
    }
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
                    write!(log_writer, "{} ", PrettyU64(self.0.now.get())).unwrap();
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
        let log_writer = &mut self.0.log_writer.borrow_mut();
        // Write a time prefix in front of every line
        for line in buf.split_inclusive(|ch| *ch == b'\n') {
            if self.0.next_write_needs_time_prefix.get() {
                write!(log_writer, "{} ", PrettyU64(self.0.now.get())).unwrap();
                self.0.next_write_needs_time_prefix.set(false);
            }
            log_writer.write_all(line)?;
            if line.ends_with(b"\n") {
                self.0.next_write_needs_time_prefix.set(true);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.log_writer.borrow_mut().flush()
    }
}

pub struct Output {
    output: String,
    sink: OutputSink,

    search_term: Option<String>,
    search_pos: usize, // Position to start searching from
    search_matched: bool,
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
                now: Cell::new(0),
                next_write_needs_time_prefix: Cell::new(true),
            })),
            search_term: None,
            search_pos: 0,
            search_matched: false,
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
        let new_data_len = new_data.len();
        if new_data_len == 0 {
            return;
        }

        if self.output.is_empty() {
            self.output = new_data;
        } else {
            self.output.push_str(&new_data);
        }

        if let Some(term) = &self.search_term {
            if !self.search_matched {
                self.search_matched = self.output[self.search_pos..].contains(term);
                self.search_pos = self.output.len().saturating_sub(term.len());
                if self.search_matched {
                    self.search_term = None;
                }
            }
        }
    }

    pub(crate) fn set_search_term(&mut self, search_term: &str) {
        self.process_new_data();
        self.search_term = Some(search_term.to_string());
        self.search_pos = self.output.len();
        self.search_matched = false;
    }

    pub(crate) fn search_matched(&mut self) -> bool {
        self.process_new_data();
        self.search_matched
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

        out.sink().set_now(0);
        out.sink().push_uart_char(b'h');
        out.sink().set_now(1);
        out.sink().push_uart_char(b'i');
        out.sink().push_uart_char(b'!');
        out.sink().push_uart_char(b'\n');

        assert_eq!(&out.take(2), "hi");
        assert_eq!(&out.take(10), "!\n");
        assert_eq!(&out.take(10), "");

        assert_eq!(log.into_string(), "          0 UART: hi!\n");
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

        out.sink().set_now(1000);
        out.sink().push_uart_char(b'h');
        out.sink().set_now(2000);
        out.sink().push_uart_char(b'i');
        out.sink().push_uart_char(b'\n');
        assert_eq!(&out.take(10), "hi\n");

        out.sink().push_uart_char(0xff);
        assert_eq!(out.exit_status(), Some(ExitStatus::Passed));
        assert_eq!(&out.take(10), "");

        assert_eq!(
            log.into_string(),
            "      1,000 UART: hi\n* TESTCASE PASSED\n"
        );
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

        assert_eq!(
            log.into_string(),
            "          0 UART: hi\n* TESTCASE FAILED\n"
        );
    }

    #[test]
    fn test_unknown_generic_load() {
        let log = Log::new();
        let mut out = Output::new(log.clone());
        out.sink().push_uart_char(0xd3);

        assert_eq!(&out.take(30), "");
        assert_eq!(log.into_string(), "Unknown generic load 0xd3\n");
    }

    #[test]
    fn test_search() {
        let mut out = Output::new(Log::new());
        out.set_search_term("foobar");
        assert!(!out.search_matched);
        for &ch in b"this is my foobar string!" {
            out.sink.push_uart_char(ch);
        }
        out.process_new_data();
        assert!(out.search_matched);
        out.set_search_term("foobar");
        out.process_new_data();
        assert!(!out.search_matched);

        for &ch in b"hello world strin" {
            out.sink.push_uart_char(ch);
        }
        out.set_search_term("string");
        for &ch in b"g no match" {
            out.sink.push_uart_char(ch);
        }
        out.process_new_data();
        assert!(!out.search_matched);

        for &ch in b" matching string" {
            out.sink.push_uart_char(ch);
        }
        out.process_new_data();
        assert!(out.search_matched);
        out.set_search_term("string");
        assert!(!out.search_matched);
    }
}
