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
    rc::Rc,
};

/// A type for logging actions without needing &mut self. Useful for logging
/// actions that occur in "fake" Bus trait implementations in unit tests.
///
/// When `Log` is cloned, the clones all share the same underlying buffer. This
/// allows tests to introspect logs that are not accessible directly.
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
#[derive(Clone)]
pub struct Log {
    log: Rc<RefCell<String>>,
}
impl Log {
    /// Construct an empty `Log`.
    pub fn new() -> Self {
        Self {
            log: Rc::new(RefCell::new(String::new())),
        }
    }

    /// Access the contents of the log without modifying it.
    pub fn as_str(&self) -> (impl Deref<Target = str> + '_) {
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
    pub fn w(&self) -> (impl Write + '_) {
        LogWriter { log: &self.log }
    }
}
impl Default for Log {
    fn default() -> Self {
        Self::new()
    }
}

struct LogWriter<'a> {
    log: &'a RefCell<String>,
}
impl Write for LogWriter<'_> {
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

    #[test]
    #[allow(clippy::redundant_clone)]
    fn test_clone() {
        let log = Log::new();
        writeln!(log.clone().w(), "Line 1").unwrap();
        writeln!(log.clone().w(), "Line 2").unwrap();
        assert_eq!("Line 1\nLine 2\n", &*log.as_str());
        assert_eq!("Line 1\nLine 2\n", log.take());
        assert_eq!("", log.take());
    }
}
