// Licensed under the Apache-2.0 license

#![no_std]
#[cfg(not(feature = "std"))]
#[cfg(feature = "riscv")]
core::arch::global_asm!(include_str!("start.S"));
#[cfg(feature = "riscv")]
core::arch::global_asm!(include_str!("nmi.S"));
#[cfg(feature = "riscv")]
core::arch::global_asm!(include_str!("trap.S"));

pub mod trap;

use caliptra_registers::soc_ifc::SocIfcReg;
pub use trap::{Exception, Interrupt, Trap, TrapRecord};

pub fn log_trap_record(trap_record: &TrapRecord, err_interrupt_status: Option<u32>) {
    let mut soc_ifc = unsafe { SocIfcReg::new() };
    let soc_ifc = soc_ifc.regs_mut();
    let ext_info = soc_ifc.cptra_fw_extended_error_info();
    ext_info.at(0).write(|_| trap_record.mcause);
    ext_info.at(1).write(|_| trap_record.mscause);
    ext_info.at(2).write(|_| trap_record.mepc);
    ext_info.at(3).write(|_| trap_record.ra);

    // The err_interrup_status is only avaiable on NMI.
    if let Some(err_interrupt_status) = err_interrupt_status {
        ext_info.at(4).write(|_| err_interrupt_status);
    }
}
