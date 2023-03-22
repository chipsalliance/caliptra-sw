/*++

Licensed under the Apache-2.0 license.

File Name:

    pring.rs

Abstract:

    File contains support routines and macros to print to UART

--*/
use core::convert::Infallible;
use ufmt::uWrite;

#[derive(Default)]
pub struct MutablePrinter;

impl uWrite for MutablePrinter {
    type Error = Infallible;

    /// Writes a string slice into this writer, returning whether the write succeeded.
    #[cfg(not(feature = "std"))]
    fn write_str(&mut self, _str: &str) -> Result<(), Self::Error> {
        #[cfg(feature = "emu")]
        caliptra_lib::Uart::default().write(_str);
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
        let _ = ufmt::uwrite!(&mut $crate::printer::MutablePrinter::default(), $($tt)*);
    }}
}

#[macro_export]
macro_rules! cprintln {
    ($($tt:tt)*) => {{
        let _ = ufmt::uwriteln!(&mut $crate::printer::MutablePrinter::default(), $($tt)*);
    }}
}

#[macro_export]
macro_rules! cprint_slice  {
    ($name:expr, $arr:expr) => {
        $crate::cprint!("{} = ", $name);
        for byte in $arr {
            $crate::cprint!("{:02X}" byte);
        }
        $crate::cprintln!("");
    }
}
