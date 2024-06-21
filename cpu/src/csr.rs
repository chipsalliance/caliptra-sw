// Licensed under the Apache-2.0 license

// Standard RISC-V MIE CSR
#[cfg(feature = "riscv")]
pub fn mie_enable_external_interrupts() {
    const MEIE: usize = 1 << 11;
    unsafe {
        core::arch::asm!("csrrs zero, mie, {r}", r = in(reg) MEIE);
    }
}

// VeeR EL2 PRM 5.5.1 Power Management Control Register
// If bit 1 is set, setting bit0 globally enables interrupts, i.e. MIE in mstatus CSR
#[cfg(feature = "riscv")]
pub fn mpmc_halt_and_enable_interrupts() {
    // Tell the core to go to sleep
    const HALT: usize = 1 << 0;
    const HALTIE: usize = 1 << 1;
    unsafe {
        core::arch::asm!("csrrs zero, 0x7c6, {r}", r = in(reg) HALT | HALTIE);
    }
}
