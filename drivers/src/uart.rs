/*++

Licensed under the Apache-2.0 license.

File Name:

    uart.rs

Abstract:

    File contains API for accessing the UART

References:
    https://os.phil-opp.com/vga-text-mode for output functionality.

--*/

use core::{fmt, ptr};

/// Caliptra UART
#[derive(Default, Debug)]
pub struct Uart {}

impl Uart {
    /// Create an instance of Caliptra UART
    pub fn new() -> Self {
        Self {}
    }

    /// Write the string to UART
    ///
    /// # Arguments
    ///
    /// `str` - String to write to UART
    pub fn write(&mut self, str: &str) {
        for byte in str.bytes() {
            match byte {
                0x20..=0x7e | b'\n' | b'\t' => self.write_byte(byte),
                _ => self.write_byte(0xfe),
            }
        }
    }

    /// Write the byte to UART
    ///
    /// # Arguments
    ///
    /// `byte` - Byte to write to UART
    pub fn write_byte(&mut self, byte: u8) {
        // Read TAG from test sw and include in write to generic_output write to inform sw there is new data
        const STDIN: *mut u32 = 0x3003_00C0 as *mut u32;
        let tag = unsafe { ptr::read_volatile(STDIN) };

        // TODO: cleanup after final UART RTL definition is in place
        const STDOUT: *mut u32 = 0x3003_00C8 as *mut u32;

        unsafe {
            ptr::write_volatile(STDOUT, 0x8000_0000 | (tag << 16) | (byte as u32));
        }
        // Wait for test to acknowledge that it has read the byte.
        while tag == unsafe {ptr::read_volatile(STDIN) } {}
    }
}

impl fmt::Write for Uart {
    /// Writes a [`char`] into this writer, returning whether the write succeeded.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s);
        Ok(())
    }
}
