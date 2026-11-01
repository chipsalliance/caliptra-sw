/*++

Licensed under the Apache-2.0 license.

File Name:

    error_reporter_tests.rs

Abstract:

    File contains test cases for HMAC-384 API

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{report_boot_status, SocIfc};
use caliptra_registers::soc_ifc::SocIfcReg;

use caliptra_test_harness::test_suite;

fn retrieve_boot_status() -> u32 {
    let soc_ifc = unsafe { SocIfcReg::new() };
    soc_ifc.regs().cptra_boot_status().read()
}

fn test_report_boot_status() {
    let val: u32 = 0xbeef2;
    report_boot_status(val);
    assert_eq!(val, retrieve_boot_status());
}

fn test_report_idevid_csr_ready() {
    let soc_ifc = unsafe { SocIfcReg::new() };
    SocIfc::new(soc_ifc).flow_status_set_idevid_csr_ready();
    let soc_ifc = unsafe { SocIfcReg::new() };
    assert!(soc_ifc.regs().cptra_flow_status().read().idevid_csr_ready());
}

fn test_report_ready_for_firmware() {
    let soc_ifc = unsafe { SocIfcReg::new() };
    SocIfc::new(soc_ifc).flow_status_set_ready_for_mb_processing();
    let soc_ifc = unsafe { SocIfcReg::new() };
    assert!(soc_ifc
        .regs()
        .cptra_flow_status()
        .read()
        .ready_for_mb_processing());
}

fn test_named_firmware_configuration() {
    let soc_ifc = unsafe { SocIfcReg::new() };
    let regs = soc_ifc.regs();
    let otp_status = regs.ss_otp_fc_status_cfg().read();
    let otp_cmd = regs.ss_otp_fc_cmd_cfg().read();
    let features = regs.ss_fw_feature_cfg().read();
    let hw_config = regs.cptra_hw_config().read();
    let debug_intent = regs.ss_debug_intent().read().debug_intent();
    let soc_ifc = SocIfc::new(soc_ifc);

    assert_eq!(soc_ifc.otp_status_reg_offset(), otp_status.status_offset());
    assert_eq!(
        soc_ifc.otp_dai_idle_bit_num(),
        otp_status.dai_idle_bit_num()
    );
    assert_eq!(
        soc_ifc.otp_direct_access_cmd_reg_offset(),
        otp_cmd.direct_access_cmd_offset()
    );
    assert_eq!(
        soc_ifc.stable_owner_key_enabled(),
        features.stable_owner_key_en()
    );
    assert_eq!(
        soc_ifc.stable_owner_key_available(),
        hw_config.subsystem_mode_en()
            && features.stable_owner_key_en()
            && !hw_config.ocp_lock_mode_en()
    );
    assert_eq!(
        soc_ifc.vendor_debug_image_allowed(),
        hw_config.subsystem_mode_en() && debug_intent && !features.vendor_debug_images_dis()
    );
}

test_suite! {
    test_report_boot_status,
    test_report_idevid_csr_ready,
    test_report_ready_for_firmware,
    test_named_firmware_configuration,
}
