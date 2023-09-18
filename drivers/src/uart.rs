/*++

Licensed under the Apache-2.0 license.

File Name:

    uart.rs

Abstract:

    File contains API for accessing the UART

References:
    https://os.phil-opp.com/vga-text-mode for output functionality.

--*/

use core::fmt;

use caliptra_registers::soc_ifc::SocIfcReg;

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
        let mut reg = unsafe { SocIfcReg::new() };
        let reg = reg.regs_mut();
        let output_reg = reg.cptra_generic_output_wires().at(0);

        let mut val = output_reg.read();

        for ch in str.bytes() {
            val = u32::from(match ch {
                0x20..=0x7e | b'\n' | b'\t' => ch,
                _ => 0xfe,
            }) | (val & 0xffff_ff00);

            // Toggle bit 8 every time a character is written, so the outside
            // world can tell when we've written a new character without having
            // to introspect internal signals.
            val ^= 0x100;

            output_reg.write(|_| val);
        }
    }
}

impl fmt::Write for Uart {
    /// Writes a [`char`] into this writer, returning whether the write succeeded.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s);
        Ok(())
    }
}
