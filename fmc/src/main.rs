#![no_std]
#![no_main]

#[no_mangle]
pub extern "C" fn main() -> ! {
    loop {}
}

#[panic_handler]
#[inline(never)]
fn fmc_panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
