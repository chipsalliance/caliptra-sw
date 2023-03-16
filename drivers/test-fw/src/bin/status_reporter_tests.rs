/*++

Licensed under the Apache-2.0 license.

File Name:

    error_reporter_tests.rs

Abstract:

    File contains test cases for HMAC-384 API

--*/

#![no_std]
#![no_main]

use caliptra_lib::{report_boot_status, FlowStatus};
use caliptra_registers::soc_ifc;

mod harness;

fn retrieve_boot_status() -> u32 {
    let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc.cptra_boot_status().read()
}

fn test_report_boot_status() {
    let val: u32 = 0xbeef2;
    report_boot_status(val);
    assert_eq!(val, retrieve_boot_status());
}

fn test_report_idevid_csr_ready() {
    let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
    FlowStatus::default().set_idevid_csr_ready();
    assert_eq!(0x0800_0000, soc_ifc.cptra_flow_status().read().status());
}

fn test_report_ready_for_firmware() {
    let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
    FlowStatus::default().set_ready_for_firmware();
    assert!(soc_ifc.cptra_flow_status().read().ready_for_fw());
}

test_suite! {
    test_report_boot_status,
    test_report_idevid_csr_ready,
    test_report_ready_for_firmware,
}
