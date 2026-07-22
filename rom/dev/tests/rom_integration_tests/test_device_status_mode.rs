// Licensed under the Apache-2.0 license

use caliptra_builder::{
    firmware::{rom_tests::TEST_FMC_INTERACTIVE, APP_WITH_UART},
    ImageOptions,
};
use caliptra_common::RomBootStatus::ColdResetComplete;
use caliptra_common::{PcrLogEntry, PcrLogEntryId};
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams, SecurityState};
use caliptra_image_types::FwVerificationPqcKeyType;
use zerocopy::{FromBytes, IntoBytes};

const PCR_ENTRY_SIZE: usize = core::mem::size_of::<PcrLogEntry>();
const DEVICE_STATUS_MODE_OFFSET: usize = 17;
const DEVICE_STATUS_MODE_PASSIVE: u8 = 0;
const DEVICE_STATUS_MODE_SUBSYSTEM: u8 = 1;

fn test_device_status_mode(subsystem_mode: bool, expected_mode: u8) {
    let fuses = Fuses {
        fuse_pqc_key_type: FwVerificationPqcKeyType::LMS as u32,
        ..Default::default()
    };
    let rom = caliptra_builder::build_firmware_rom(crate::helpers::rom_from_env()).unwrap();
    let life_cycle = fuses.life_cycle;
    let mut hw = caliptra_hw_model::new(
        InitParams {
            fuses,
            rom: &rom,
            security_state: SecurityState::from(life_cycle as u32),
            subsystem_mode,
            ..Default::default()
        },
        BootParams::default(),
    )
    .unwrap();

    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_INTERACTIVE,
        &APP_WITH_UART,
        ImageOptions {
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            ..Default::default()
        },
    )
    .unwrap();

    crate::helpers::test_upload_firmware(
        &mut hw,
        &image_bundle.to_bytes().unwrap(),
        FwVerificationPqcKeyType::LMS,
    );

    hw.step_until_boot_status(u32::from(ColdResetComplete), true);

    let pcr_entry_arr = hw.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();
    let (device_status, _) =
        PcrLogEntry::ref_from_prefix(pcr_entry_arr[0..PCR_ENTRY_SIZE].as_bytes()).unwrap();

    assert_eq!(device_status.id, PcrLogEntryId::DeviceStatus as u16);
    assert_eq!(
        device_status.measured_data()[DEVICE_STATUS_MODE_OFFSET],
        expected_mode
    );
}

#[test]
fn test_device_status_mode_passive() {
    test_device_status_mode(false, DEVICE_STATUS_MODE_PASSIVE);
}

#[test]
fn test_device_status_mode_subsystem() {
    test_device_status_mode(true, DEVICE_STATUS_MODE_SUBSYSTEM);
}
