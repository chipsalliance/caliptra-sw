/*++

Licensed under the Apache-2.0 license.

File Name:

    pring.rs

Abstract:

    File contains support routines and macros to print to UART

--*/
use core::convert::Infallible;
use ufmt::{uDisplay, uWrite};

#[derive(Default)]
pub struct Printer;

impl uWrite for Printer {
    type Error = Infallible;

    /// Writes a string slice into this writer, returning whether the write succeeded.
    #[cfg(not(feature = "std"))]
    #[inline(never)]
    fn write_str(&mut self, _str: &str) -> Result<(), Self::Error> {
        #[cfg(feature = "emu")]
        crate::Uart::default().write(_str);
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
        let _ = ufmt::uwrite!(&mut $crate::printer::Printer::default(), $($tt)*);
    }}
}

#[macro_export]
macro_rules! cprintln {
    ($($tt:tt)*) => {{
        let _ = ufmt::uwriteln!(&mut $crate::printer::Printer::default(), $($tt)*);
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

pub struct HexBytes<'a>(pub &'a [u8]);
impl uDisplay for HexBytes<'_> {
    fn fmt<W>(&self, f: &mut ufmt::Formatter<'_, W>) -> Result<(), W::Error>
    where
        W: uWrite + ?Sized,
    {
        for &x in self.0.iter() {
            let c = x >> 4;
            if c < 10 {
                f.write_char((c + b'0') as char)?;
            } else {
                f.write_char((c - 10 + b'A') as char)?;
            }
            let c = x & 0xf;
            if c < 10 {
                f.write_char((c + b'0') as char)?;
            } else {
                f.write_char((c - 10 + b'A') as char)?;
            }
        }
        Ok(())
    }
}
