/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains Uart Driver for bare-metal RISCV program

--*/
use core::ptr;
use ufmt;

#[macro_export]
macro_rules! uformat {
    // IMPORTANT use `tt` fragments instead of `expr` fragments (i.e. `$($exprs:expr),*`)
    ($($tt:tt)*) => {{
        let mut s = printer::Uart;
        ufmt::uwrite!(&mut s, $($tt)*).unwrap()
    }}
}

macro_rules! uformatln {
    // IMPORTANT use `tt` fragments instead of `expr` fragments (i.e. `$($exprs:expr),*`)
    ($($tt:tt)*) => {{
        let mut s = printer::Uart;
        ufmt::uwriteln!(&mut s, $($tt)*).unwrap()
    }}
}

pub struct Uart;
impl Uart {
    /// Transmit Data Register
    const ADDR_TX_DATA: u32 = 0x20001041;

    // Implement put_c
    pub fn put_c(chr: u8) -> () {
        unsafe {
            const UART_TX: *mut u8 = Uart::ADDR_TX_DATA as *mut u8;
            ptr::write_volatile(UART_TX, chr);
        }
    }
}

// Trait Implementation to redirect ufmt::uwriteln to UART
impl ufmt::uWrite for Uart {
    type Error = ();

    // Implement write_str
    fn write_str(&mut self, s: &str) -> Result<(), Self::Error> {
        for b in s.as_bytes().iter() {
            Uart::put_c(*b);
        }
        Ok(())
    }
}
