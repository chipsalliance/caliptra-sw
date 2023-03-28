/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains Macros and API for Caliptra Library Test Harness

References:
    https://os.phil-opp.com/vga-text-mode for print functionality.

--*/

use core::fmt;

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::harness::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use caliptra_drivers::Uart;
    use core::fmt::Write;
    Uart::new().write_fmt(args).unwrap();
}

#[macro_export]
macro_rules! test_suite {
    ($($test_case: ident,)*) => {
        use core::arch::global_asm;
        use core::panic::PanicInfo;
        use $crate::harness::Testable;

        global_asm!(include_str!("start.S"));

        #[panic_handler]
        pub fn panic(info: &PanicInfo) -> ! {
            println!("[failed]");
            println!("Error: {}\n", info);
            caliptra_drivers::ExitCtrl::exit(u32::MAX);
        }

        #[no_mangle]
        pub extern "C" fn main() {
            $(
                $test_case.run();
            )*
        }
    };
}

pub trait Testable {
    fn run(&self);
}

impl<T> Testable for T
where
    T: Fn(),
{
    fn run(&self) {
        print!("{}...\t", core::any::type_name::<T>());
        self();
        println!("[ok]");
    }
}
