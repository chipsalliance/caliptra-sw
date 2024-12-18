// Licensed under the Apache-2.0 license

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#[cfg(feature = "std")]
pub fn main() {}

#[cfg(not(feature = "std"))]
core::arch::global_asm!(include_str!("../src/start.S"));

#[path = "../src/exception.rs"]
mod exception;

use caliptra_drivers::cprintln;
use caliptra_drivers::ExitCtrl;

#[no_mangle]
#[inline(never)]
extern "C" fn exception_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "EXCEPTION mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );

    ExitCtrl::exit(1);
}

#[no_mangle]
#[inline(never)]
extern "C" fn nmi_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "NMI mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );

    ExitCtrl::exit(1);
}

#[panic_handler]
#[inline(never)]
#[cfg(not(feature = "std"))]
fn handle_panic(pi: &core::panic::PanicInfo) -> ! {
    if let Some(loc) = pi.location() {
        cprintln!("Panic at file {} line {}", loc.file(), loc.line())
    }
    ExitCtrl::exit(1);
}

unsafe fn is_zeroed(mut ptr: *const u32, mut size: usize) -> bool {
    while size > 0 {
        if ptr.read_volatile() != 0 {
            cprintln!("Non-zero word found at 0x{:x}" ptr as usize);
            return false;
        }
        size -= 4;
        ptr = ptr.offset(1);
    }
    true
}

extern "C" {
    fn _zero_mem256(dest: *mut u32, len: usize);
    fn _copy_mem32(dest: *mut u32, src: *const u32, len: usize);
}

#[no_mangle]
pub extern "C" fn rom_entry() -> ! {
    const SIZEOF_U32: usize = core::mem::size_of::<u32>();
    unsafe {
        // Test that memory is cleared at startup
        assert!(is_zeroed(0x4000_0000 as *const u32, 1024 * 128));

        // Check everything but the last 3k, which might contain non-zero stack bytes
        assert!(is_zeroed(0x5000_0000 as *const u32, 1024 * (128 - 3)));

        // Test _zero_mem256

        let mut test_mem = [1; 64];

        test_mem[4..12].copy_from_slice(&[0x5555_5555u32; 8]);
        _zero_mem256(test_mem.as_mut_ptr().offset(4), 8 * SIZEOF_U32);
        assert_eq!(test_mem[3..13], [1, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        _zero_mem256(test_mem.as_mut_ptr().offset(13), 16 * SIZEOF_U32);
        assert_eq!(
            test_mem[12..30],
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );

        _zero_mem256(test_mem.as_mut_ptr().offset(33), 1);
        // len rounds up to the nearest 32-byte chunk
        assert_eq!(test_mem[32..42], [1, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        // Test _copy_mem32

        test_mem[45..48].copy_from_slice(&[0x0011_2233, 0x4455_6677, 0x8899_aabb]);

        _copy_mem32(
            test_mem.as_mut_ptr().offset(50),
            test_mem.as_ptr().offset(45),
            3 * SIZEOF_U32,
        );
        assert_eq!(
            test_mem[49..54],
            [1, 0x0011_2233, 0x4455_6677, 0x8899_aabb, 1]
        );

        cprintln!("test_mem: {:?}", &test_mem[..]);
    }

    ExitCtrl::exit(0)
}
