/*++

Licensed under the Apache-2.0 license.

File Name:

    locked_dv_test.rs

Abstract:

    File contains test case for writing to a locked DV slot.

--*/

#![no_std]
#![no_main]

use caliptra_runtime::Drivers;
use caliptra_test_harness::{runtime_handlers, test_suite};

fn test_locked_dv_slot() {
    let fht = caliptra_common::FirmwareHandoffTable::default();
    let mut drivers = unsafe { Drivers::new_from_registers(&fht).unwrap() };
    let min_svn: u32 = drivers.data_vault.rt_min_svn();
    drivers.data_vault.set_rt_min_svn(min_svn + 1);
}

test_suite! {
    test_locked_dv_slot,
}
