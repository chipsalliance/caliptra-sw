/*++

Licensed under the Apache-2.0 license.

File Name:

    print.rs

Abstract:

    File contains support routines and macros to print to UART

--*/
use core::convert::Infallible;
use ufmt::{uDisplay, uWrite};

#[derive(Default)]
pub struct RomPrinter;

impl uWrite for RomPrinter {
    type Error = Infallible;

    /// Writes a string slice into this writer, returning whether the write succeeded.
    #[cfg(not(feature = "std"))]
    #[inline(never)]
    fn write_str(&mut self, _str: &str) -> Result<(), Self::Error> {
        #[cfg(feature = "emu")]
        caliptra_drivers::Uart::default().write(_str);
        Ok(())
    }

    /// Writes a string slice into this writer, returning whether the write succeeded.
    #[cfg(feature = "std")]
    fn write_str(&mut self, str: &str) -> Result<(), Self::Error> {
        print!("{str}");
        Ok(())
    }
}

#[macro_export]
macro_rules! cprint {
    ($($tt:tt)*) => {{
        let _ = ufmt::uwrite!(&mut $crate::print::RomPrinter::default(), $($tt)*);
    }}
}

#[macro_export]
macro_rules! cprintln {
    ($($tt:tt)*) => {{
        let _ = ufmt::uwriteln!(&mut $crate::print::RomPrinter::default(), $($tt)*);
    }}
}

pub struct HexBytes<'a>(pub &'a [u8]);
impl uDisplay for HexBytes<'_> {
    fn fmt<W>(&self, f: &mut ufmt::Formatter<'_, W>) -> Result<(), W::Error>
    where
        W: uWrite + ?Sized,
    {
        for byte in self.0.iter() {
            ufmt::uwrite!(f, "{:02X}", *byte)?;
        }
        Ok(())
    }
}
