// Licensed under the Apache-2.0 license

#[derive(Clone, Copy)]
pub enum ExitStatus {
    Passed,
    Failed,
}

#[derive(Default)]
pub struct Output {
    output: String,
    exit_status: Option<ExitStatus>,
}
impl Output {
    pub fn new() -> Self {
        Self::default()
    }
    #[allow(dead_code)]
    pub(crate) fn process_generic_load(&mut self, ch: u8) {
        // For a complete list of special characters:
        // https://github.com/Project-Caliptra/rtl-caliptra/blob/884240d062c44b4aced96b7d58f33683687743f7/src/integration/tb/caliptra_top_tb_services.sv#L141
        const TESTCASE_FAILED: u8 = 0x01;
        const TESTCASE_PASSED: u8 = 0xff;

        match ch {
            TESTCASE_PASSED => {
                // This is the same string as printed by the verilog test-bench
                self.output.push_str("* TESTCASE PASSED\n");
                self.exit_status = Some(ExitStatus::Passed);
            }
            TESTCASE_FAILED => {
                // This is the same string as printed by the verilog test-bench
                self.output.push_str("* TESTCASE FAILED\n");
                self.exit_status = Some(ExitStatus::Failed);
            }
            0x20..=0x7f | b'\r' | b'\n' | b'\t' => {
                self.output.push(ch as char);
            }
            _ => {
                self.output
                    .push_str(&format!("Unknown generic load 0x{ch:02x}\n"));
            }
        }
    }

    /// Peek at all the output captured so far
    pub fn peek(&self) -> &str {
        &self.output
    }

    /// Take at most `limit` characters from the output
    pub fn take(&mut self, limit: usize) -> String {
        if self.output.len() <= limit {
            std::mem::take(&mut self.output)
        } else {
            let remaining = self.output[limit..].to_string();
            let mut result = std::mem::replace(&mut self.output, remaining);
            result.truncate(limit);
            result
        }
    }

    /// Returns true if the caliptra microcontroller has signalled that it wants to exit
    /// (this only makes sense when running test cases on the microcontroller)
    pub fn exit_requested(&self) -> bool {
        self.exit_status.is_some()
    }

    pub fn exit_status(&self) -> Option<ExitStatus> {
        self.exit_status
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_take() {
        let mut out = Output::new();

        out.process_generic_load(b'h');
        out.process_generic_load(b'i');
        out.process_generic_load(b'!');
        assert_eq!(&out.take(2), "hi");
        assert_eq!(&out.take(10), "!");
        assert_eq!(&out.take(10), "");
    }

    #[test]
    fn test_peek() {
        let mut out = Output::new();

        out.process_generic_load(b'h');
        out.process_generic_load(b'i');
        assert_eq!(out.peek(), "hi");
        out.process_generic_load(b'!');
        assert_eq!(out.peek(), "hi!");
    }

    #[test]
    fn test_generic_loads() {
        let mut out = Output::new();

        out.process_generic_load(b'h');
        out.process_generic_load(b'i');
        assert_eq!(&out.take(10), "hi");

        out.process_generic_load(0xff);
        assert_eq!(&out.take(20), "* TESTCASE PASSED\n");

        out.process_generic_load(0x01);
        assert_eq!(&out.take(20), "* TESTCASE FAILED\n");

        out.process_generic_load(0xd3);
        assert_eq!(&out.take(30), "Unknown generic load 0xd3\n");
    }
}
