/*++

Licensed under the Apache-2.0 license.

File Name:

    boot_tests.rs

Abstract:

    File contains test cases for booting runtime firmware

--*/

#![no_std]
#![no_main]

use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_runtime::Drivers;
use caliptra_test_harness::test_suite;

fn test_mbox_cmd() {
    let mut fht = caliptra_common::FirmwareHandoffTable::default();
    let mut drivers = unsafe { Drivers::new_from_registers(&mut fht).unwrap() };
    let mut soc_ifc = unsafe { SocIfcReg::new() };

    // Unlock the sha_acc peripheral for use by the SoC
    drivers.sha_acc.regs_mut().lock().write(|w| w.lock(true));

    // Notify the SoC that we're ready for it to use sha_acc
    soc_ifc.regs_mut().cptra_boot_status().write(|_| 1);

    caliptra_runtime::handle_mailbox_commands(&mut drivers);
}

test_suite! {
    test_mbox_cmd,
}
