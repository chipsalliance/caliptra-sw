/*++

Licensed under the Apache-2.0 license.

File Name:

    log.rs

Abstract:

    File contains code useful for logging inside unit tests.

--*/
use std::{
    cell::{Ref, RefCell},
    fmt::Write,
    ops::Deref,
};

/// A type for logging actions without needing &mut self. Useful for logging
/// actions that occur in "fake" Bus trait implementations in unit tests.
///
/// * Example
///
/// ```
/// use caliptra_emu_bus::testing::Log;
/// use std::fmt::Write;
///
/// let log = Log::new();
/// writeln!(log.w(), "Line 1").unwrap();
/// writeln!(log.w(), "Line 2").unwrap();
/// assert_eq!("Line 1\nLine 2\n", &*log.as_str());
/// assert_eq!("Line 1\nLine 2\n", log.take());
/// assert_eq!("", log.take());
/// ```
pub struct Log {
    log: RefCell<String>,
}
impl Log {
    /// Construct an empty `Log`.
    pub fn new() -> Self {
        Self {
            log: RefCell::new(String::new()),
        }
    }

    /// Access the contents of the log without modifying it.
    pub fn as_str<'a>(&'a self) -> (impl Deref<Target = str> + 'a) {
        Ref::map(self.log.borrow(), String::as_str)
    }

    /// Replaces the existing contents of the log with an empty string, and
    /// returns the previous contents. Useful for writing assertions for recent
    /// actions.
    pub fn take(&self) -> String {
        let mut result = String::new();
        std::mem::swap(&mut *self.log.borrow_mut(), &mut result);
        result
    }

    /// returns a writer that can be use with write!() or writeln!().
    pub fn w<'a>(&'a self) -> (impl Write + 'a) {
        LogWriter { log: &self.log }
    }
}

struct LogWriter<'a> {
    log: &'a RefCell<String>,
}
impl<'a> Write for LogWriter<'a> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        Write::write_str(&mut *self.log.borrow_mut(), s)
    }
    fn write_char(&mut self, c: char) -> std::fmt::Result {
        Write::write_char(&mut *self.log.borrow_mut(), c)
    }
    fn write_fmt(&mut self, args: std::fmt::Arguments<'_>) -> std::fmt::Result {
        Write::write_fmt(&mut *self.log.borrow_mut(), args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;

    #[test]
    fn test() {
        let log = Log::new();
        writeln!(log.w(), "Line 1").unwrap();
        writeln!(log.w(), "Line 2").unwrap();
        assert_eq!("Line 1\nLine 2\n", &*log.as_str());
        assert_eq!("Line 1\nLine 2\n", log.take());
        assert_eq!("", log.take());
    }
}
