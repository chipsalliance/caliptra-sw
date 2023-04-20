/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains Macros and API for Caliptra Library Test Harness

References:
    https://os.phil-opp.com/vga-text-mode for print functionality.

--*/
#![no_std]

use core::fmt;
use core::format_args;
use core::ops::Fn;

// If not using the runtime entrypoint, include a test start.S
#[cfg(all(feature = "riscv", not(feature = "runtime")))]
core::arch::global_asm!(include_str!("start.S"));

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    cfg_if::cfg_if! {
        if #[cfg(feature = "emu")] {
            use caliptra_drivers::Uart;
            use core::fmt::Write;
            Uart::new().write_fmt(args).unwrap();
        }
        else {
            let _ = args;
        }
    }
}

#[macro_export]
macro_rules! runtime_handlers {
    () => {
        use caliptra_cpu::TrapRecord;

        #[no_mangle]
        #[inline(never)]
        extern "C" fn exception_handler(trap_record: &TrapRecord) {
            println!(
                "TEST EXCEPTION mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
                trap_record.mcause, trap_record.mscause, trap_record.mepc
            );

            // Signal non-fatal error to SOC
            caliptra_drivers::report_fw_error_non_fatal(0xdead0);

            assert!(false);
        }

        #[no_mangle]
        #[inline(never)]
        extern "C" fn nmi_handler(trap_record: &TrapRecord) {
            println!(
                "TEST NMI mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
                trap_record.mcause, trap_record.mscause, trap_record.mepc
            );

            assert!(false);
        }
    };
}

#[macro_export]
macro_rules! test_suite {
    ($($test_case: ident,)*) => {
        use core::arch::global_asm;
        use core::panic::PanicInfo;
        use caliptra_test_harness::{println, Testable};

        #[panic_handler]
        pub fn panic(info: &PanicInfo) -> ! {
            println!("[failed]");
            println!("Error: {}\n", info);
            cfg_if::cfg_if! {
                if #[cfg(feature = "emu")] {
                    use caliptra_drivers::ExitCtrl;
                    ExitCtrl::exit(u32::MAX);
                } else {
                    loop {
                        use caliptra_drivers::Mailbox;
                        unsafe { Mailbox::abort_pending_soc_to_uc_transactions() };
                    }
                }
            }
        }

        #[no_mangle]
        pub extern "C" fn main() {
            $(
                $test_case.run();
            )*
        }

        #[no_mangle]
        pub extern "C" fn entry_point() {
            main();
            caliptra_drivers::ExitCtrl::exit(0);
        }

        #[cfg(feature = "runtime")]
        runtime_handlers! {}
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
