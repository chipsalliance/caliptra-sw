// Licensed under the Apache-2.0 license

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#[cfg(target_arch = "riscv32")]
core::arch::global_asm!(include_str!("zeros.S"));

#[cfg(feature = "std")]
pub fn main() {}

// Should not be linked
#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
