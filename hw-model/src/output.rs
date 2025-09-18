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
    char_buffer: Cell<PartialUtf8>, // it's faster to copy than to manage a RefCell
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

#[derive(Clone, Copy)]
struct PartialUtf8 {
    len: usize,
    buf: [u8; 4],
}

impl Default for PartialUtf8 {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialUtf8 {
    fn new() -> Self {
        Self {
            len: 0,
            buf: [0; 4],
        }
    }

    fn push(&mut self, ch: u8) {
        self.buf[self.len] = ch;
        self.len += 1;
    }

    fn next(&mut self) -> Option<char> {
        if self.len == 0 {
            return None;
        }
        // check partial sequences
        for l in 1..=self.len {
            let v = &self.buf[..l];
            // avoid extra borrow
            let ch = match std::str::from_utf8(v) {
                Ok(s) => s.chars().next(),
                _ => None,
            };
            if let Some(ch) = ch {
                self.buf.copy_within(l..4, 0);
                self.len -= l;
                return Some(ch);
            }
        }
        if self.len == 4 {
            // Invalid UTF-8 sequence, just output one character and shift the rest down
            let ch = self.buf[0] as char;
            self.buf.copy_within(1..4, 0);
            self.len -= 1;
            Some(ch)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_utf8_buffer() {
        let mut p = PartialUtf8::new();
        p.push(0x20);
        assert!(p.next() == Some(' '));
        assert!(p.next() == None);

        for ch in 0..0x7f {
            // all ASCII characters are single byte
            p.push(ch);
            assert!(p.next() == Some(ch as char));
            assert!(p.next() == None);
        }

        // 2-byte UTF-8 character
        p.push(0xCE);
        assert_eq!(p.next(), None);
        p.push(0x92);
        assert_eq!(p.next(), Some('Β'));
        assert_eq!(p.next(), None);

        // 3-byte UTF-8 character
        p.push(0xEC);
        assert_eq!(p.next(), None);
        p.push(0x9C);
        assert_eq!(p.next(), None);
        p.push(0x84);
        assert_eq!(p.next(), Some('위'));
        assert_eq!(p.next(), None);

        // 4-byte UTF-8 character
        p.push(0xF0);
        assert_eq!(p.next(), None);
        p.push(0x90);
        assert_eq!(p.next(), None);
        p.push(0x8D);
        assert_eq!(p.next(), None);
        p.push(0x85);
        assert_eq!(p.next(), Some('𐍅'));
        assert_eq!(p.next(), None);

        // invalid UTF-8 sequence
        p.push(0xF0);
        assert_eq!(p.next(), None);
        p.push(0x20);
        assert_eq!(p.next(), None);
        p.push(0x21);
        assert_eq!(p.next(), None);
        p.push(0x22);
        assert_eq!(p.next(), Some(0xF0 as char));
        assert_eq!(p.next(), Some(0x20 as char));
        assert_eq!(p.next(), Some(0x21 as char));
        assert_eq!(p.next(), Some(0x22 as char));
    }
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

    fn push_char_valid(&self, ch: char) {
        const UART_LOG_PREFIX: &[u8] = b"UART: ";
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
        let mut buffer = [0; 4];
        let s = ch.encode_utf8(&mut buffer);
        log_writer.write_all(s.as_bytes()).unwrap();
        if ch == '\n' {
            self.0.at_start_of_line.set(true);
        }
    }

    pub fn push_uart_char(&self, ch: u8) {
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
            0x02..=0x7f => self.push_char_valid(ch as char),
            0x80..=0xf4 => {
                let mut partial = self.0.char_buffer.take();
                partial.push(ch);

                while let Some(c) = partial.next() {
                    self.push_char_valid(c);
                }
                self.0.char_buffer.set(partial);
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
                char_buffer: Cell::new(PartialUtf8::new()),
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

    pub fn set_search_term(&mut self, search_term: &str) {
        self.process_new_data();
        self.search_term = Some(search_term.to_string());
        self.search_pos = self.output.len();
        self.search_matched = false;
    }

    pub fn search_matched(&mut self) -> bool {
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
        out.sink().push_uart_char(0xe2);
        out.sink().push_uart_char(0x98);
        out.sink().push_uart_char(0x83);
        out.sink().push_uart_char(b'\n');

        assert_eq!(&out.take(2), "hi");
        assert_eq!(&out.take(10), "!☃\n");
        assert_eq!(&out.take(10), "");

        assert_eq!(log.into_string(), "          0 UART: hi!☃\n");
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
        out.sink().push_uart_char(0xf8);

        assert_eq!(&out.take(30), "");
        assert_eq!(log.into_string(), "Unknown generic load 0xf8\n");
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
