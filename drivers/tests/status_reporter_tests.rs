/*++

Licensed under the Apache-2.0 license.

File Name:

    error_reporter_tests.rs

Abstract:

    File contains test cases for HMAC-384 API

--*/

#![no_std]
#![no_main]

use caliptra_lib::{report_boot_status, report_flow_status};
use caliptra_registers::soc_ifc;

mod harness;

fn retrieve_boot_status() -> u32 {
    let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc.cptra_boot_status().read()
}

fn retrieve_flow_status() -> u32 {
    let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc.cptra_flow_status().read().status()
}

fn test_report_boot_status() {
    let val: u32 = 0xbeef2;
    report_boot_status(val);
    assert_eq!(val, retrieve_boot_status());
}

fn test_report_flow_status() {
    let val: u32 = 0xbeef3;
    report_flow_status(val);
    assert_eq!(val, retrieve_flow_status());
}

test_suite! {
    test_report_boot_status,
    test_report_flow_status,
}
