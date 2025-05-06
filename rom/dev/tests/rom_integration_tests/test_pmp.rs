// Licensed under the Apache-2.0 license

use crate::helpers;
use caliptra_api::SocManager;
use caliptra_builder::{
    firmware::{self, rom_tests::TEST_FMC_INTERACTIVE, APP_WITH_UART},
    ImageOptions,
};
use caliptra_common::RomBootStatus::*;
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams};
// From RISC-V_VeeR_EL2_PRM.pdf
// Exception causes
pub const EXCEPTION_CAUSE_STORE_ACCESS_FAULT: u32 = 0x0000_0007;

#[test]
fn test_pmp_enforced() {
    let rom = caliptra_builder::build_firmware_rom(&firmware::rom_tests::TEST_PMP_TESTS).unwrap();
    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            ..Default::default()
        },
        BootParams::default(),
    )
    .unwrap();
    hw.step_until_exit_failure().unwrap();
}

#[test]
fn test_datavault_pmp_enforcement() {
    for subsystem_mode in [false, true] {
        for pqc_key_type in helpers::PQC_KEY_TYPE.iter() {
            let image_options = ImageOptions {
                pqc_key_type: *pqc_key_type,
                ..Default::default()
            };
            let fuses = Fuses {
                fuse_pqc_key_type: *pqc_key_type as u32,
                ..Default::default()
            };
            let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
            let image_bundle = caliptra_builder::build_and_sign_image(
                &TEST_FMC_INTERACTIVE,
                &APP_WITH_UART,
                image_options,
            )
            .unwrap();

            let mut hw = caliptra_hw_model::new(
                InitParams {
                    rom: &rom,
                    subsystem_mode: false,
                    ..Default::default()
                },
                BootParams {
                    fw_image: Some(&image_bundle.to_bytes().unwrap()),
                    fuses: fuses.clone(),
                    ..Default::default()
                },
            )
            .unwrap();

            hw.step_until_boot_status(u32::from(ColdResetComplete), true);

            // Test PMP enforcement by writing to start of Data Vault.
            let result = hw.mailbox_execute(0x1000_0010, &[]);
            assert!(result.is_err());
            let mcause = hw.soc_ifc().cptra_fw_extended_error_info().at(0).read();
            assert_eq!(mcause, EXCEPTION_CAUSE_STORE_ACCESS_FAULT);

            // Test PMP enforcement by writing to end of Data Vault.
            let mut hw = caliptra_hw_model::new(
                InitParams {
                    rom: &rom,
                    subsystem_mode,
                    ..Default::default()
                },
                BootParams {
                    fw_image: Some(&image_bundle.to_bytes().unwrap()),
                    fuses,
                    ..Default::default()
                },
            )
            .unwrap();

            hw.step_until_boot_status(u32::from(ColdResetComplete), true);

            let result = hw.mailbox_execute(0x1000_0011, &[]);
            assert!(result.is_err());
            let mcause = hw.soc_ifc().cptra_fw_extended_error_info().at(0).read();
            assert_eq!(mcause, EXCEPTION_CAUSE_STORE_ACCESS_FAULT);
        }
    }
}
