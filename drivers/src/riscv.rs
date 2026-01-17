// Licensed under the Apache-2.0 license.

/// Return the current stack pointer
///
/// Useful while debugging stack usage
#[inline(always)]
pub fn stack_pointer() -> usize {
    let sp: usize;
    #[cfg(any(target_arch = "riscv32", target_arch = "aarch64"))]
    unsafe {
        core::arch::asm!("mv {0}, sp", out(reg) sp);
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("mov {0}, rsp", out(reg) sp);
    }
    sp
}
