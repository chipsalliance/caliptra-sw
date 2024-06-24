// Licensed under the Apache-2.0 license

//! Simple tests to validate external interrupts both with a correct and incorrect setup

#![no_main]
#![no_std]

use caliptra_drivers::{cprintln, Pic, SocIfc};
use caliptra_registers::{el2_pic_ctrl::El2PicCtrl, soc_ifc::SocIfcReg};
use caliptra_test_harness::test_suite;

#[cfg(target_arch = "riscv32")]
core::arch::global_asm!(include_str!("ext_intr.S"));

#[macro_export]
macro_rules! runtime_handlers {
    () => {};
}

use caliptra_cpu::{log_trap_record, TrapRecord};

#[no_mangle]
#[inline(never)]
extern "C" fn exception_handler(trap_record: &TrapRecord) {
    cprintln!(
        "TEST EXCEPTION mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X} ra=0x{:08X}",
        trap_record.mcause,
        trap_record.mscause,
        trap_record.mepc,
        trap_record.ra,
    );
    log_trap_record(trap_record, None);

    // Signal non-fatal error to SOC
    caliptra_drivers::report_fw_error_fatal(
        caliptra_drivers::CaliptraError::RUNTIME_GLOBAL_EXCEPTION.into(),
    );

    assert!(false);
}

const MCAUSE_NON_DCCM_NMI: u32 = 0xF000_1002;
const MCAUSE_MACHINE_EXT_INT: u32 = 0x8000_000B;

#[no_mangle]
#[inline(never)]
extern "C" fn nmi_handler(trap_record: &TrapRecord) {
    let mut soc_ifc = unsafe { SocIfcReg::new() };

    // If the NMI was fired by caliptra instead of the uC, this register
    // contains the reason(s)
    let err_interrupt_status = u32::from(
        soc_ifc
            .regs()
            .intr_block_rf()
            .error_internal_intr_r()
            .read(),
    );
    log_trap_record(trap_record, Some(err_interrupt_status));
    if trap_record.mcause == MCAUSE_NON_DCCM_NMI {
        // Clear interrupt
        soc_ifc
            .regs_mut()
            .intr_block_rf()
            .notif_internal_intr_r()
            .write(|w| w.notif_cmd_avail_sts(true));
        return;
    }

    assert!(false);
}

#[no_mangle]
#[inline(never)]
extern "C" fn ext_int_handler(trap_record: &TrapRecord) {
    let mut soc_ifc = unsafe { SocIfcReg::new() };

    let notif_interrupt_status = u32::from(
        soc_ifc
            .regs()
            .intr_block_rf()
            .notif_internal_intr_r()
            .read(),
    );
    log_trap_record(trap_record, Some(notif_interrupt_status));
    #[cfg(target_arch = "riscv32")]
    let meihap: usize = unsafe {
        let csr;
        // Load a good address in DCCM this time
        core::arch::asm!(
            "csrr {rd}, 0xfc8",
            rd = out(reg) csr
        );
        csr
    };
    let claimid = (meihap >> 2) & 0xff;
    const MBOX_NOTIF_CLAIM_ID: usize = 20;
    assert_eq!(claimid, MBOX_NOTIF_CLAIM_ID);

    // Clear interrupt
    soc_ifc
        .regs_mut()
        .intr_block_rf()
        .notif_internal_intr_r()
        .write(|w| w.notif_cmd_avail_sts(true));
}

fn setup_mailbox_wfi(soc_ifc: &mut SocIfc, pic: &mut Pic) {
    use caliptra_drivers::IntSource;

    caliptra_cpu::csr::mie_enable_external_interrupts();

    // Set highest priority so that Int can wake CPU
    pic.int_set_max_priority(IntSource::SocIfcNotif);
    pic.int_enable(IntSource::SocIfcNotif);

    soc_ifc.enable_mbox_notif_interrupts();
}

#[cfg(feature = "riscv")]
fn global_enable_interrupts() {
    const MIE: usize = 1 << 3;
    unsafe {
        core::arch::asm!("csrrs zero, mstatus, {r}", r = in(reg) MIE);
    }
}

// Test if soft triggering an external interrupt results in an NMI
fn test_pic_nmi() {
    let (mut soc_ifc, mut pic) =
        unsafe { (SocIfc::new(SocIfcReg::new()), Pic::new(El2PicCtrl::new())) };
    setup_mailbox_wfi(&mut soc_ifc, &mut pic);

    // Clear up the status bit before triggering
    soc_ifc.clear_mbox_notif_status();

    println!("Running test against MEIVT in ICCM, using software generated interrupt");
    #[cfg(target_arch = "riscv32")]
    unsafe {
        // Write meivt (External Interrupt Vector Table Register)
        // VeeR has been instantiated with RV_FAST_INTERRUPT_REDIRECT,
        // so external interrupts always bypass the standard risc-v dispatch logic
        // and instead load the destination address from this table in DCCM.
        // Here we load a wrong address and expect an NMI
        core::arch::asm!(
            "la {tmp}, _ext_intr_vector_iccm",
            "csrw 0xbc8, {tmp}",
            tmp = out(reg) _,
        );
    }

    soc_ifc.soft_trigger_mbox_notif();
    global_enable_interrupts();

    // Do nothing for a few cycles to make sure int hits before the next code runs
    for _ in 0..100 {
        unsafe {
            #[cfg(target_arch = "riscv32")]
            core::arch::asm!("nop");
        }
    }

    let soc_ifc_regs = unsafe { SocIfcReg::new() };
    let fw_err = soc_ifc_regs.regs().cptra_fw_extended_error_info().read();
    let mcause = fw_err[0];
    assert_eq!(mcause, MCAUSE_NON_DCCM_NMI);
}

fn ext_int_was_handled() {
    let soc_ifc_regs = unsafe { SocIfcReg::new() };
    let fw_err = soc_ifc_regs.regs().cptra_fw_extended_error_info().read();
    let mcause = fw_err[0];
    let mbox_cmd_status = (fw_err[4] & 1) == 1;
    assert_eq!(mcause, MCAUSE_MACHINE_EXT_INT);
    assert!(mbox_cmd_status);
}

// Test soft triggering external interrupt with fast interrupt redirect
// Test if soft triggering an external interrupt results in waking from halt
fn test_pic_ext_int() {
    let mut soc_ifc = unsafe { SocIfc::new(SocIfcReg::new()) };

    #[cfg(target_arch = "riscv32")]
    unsafe {
        // Load a good address in DCCM this time
        core::arch::asm!(
            "la {tmp}, _ext_intr_vector",
            "csrw 0xbc8, {tmp}",
            tmp = out(reg) _,
        );
    }

    soc_ifc.soft_trigger_mbox_notif();
    global_enable_interrupts();
    // We are woken up by the interrupt if this is reached

    // Do nothing for a few cycles to make sure int hits before the next code runs
    for _ in 0..100 {
        unsafe {
            #[cfg(target_arch = "riscv32")]
            core::arch::asm!("nop");
        }
    }
    ext_int_was_handled();
}

// Test if soft triggering an external interrupt results in waking from halt
fn test_pic_ext_int_wake() {
    let mut soc_ifc = unsafe { SocIfc::new(SocIfcReg::new()) };

    soc_ifc.soft_trigger_mbox_notif();

    caliptra_cpu::csr::mpmc_halt_and_enable_interrupts();
    // We are woken up by the interrupt if this is reached

    // Do nothing for a few cycles to make sure int hits before the next code runs
    for _ in 0..100 {
        unsafe {
            #[cfg(target_arch = "riscv32")]
            core::arch::asm!("nop");
        }
    }

    ext_int_was_handled();
}

test_suite! {
    test_pic_nmi,
    test_pic_ext_int,
    test_pic_ext_int_wake,
}
