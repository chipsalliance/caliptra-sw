// Licensed under the Apache-2.0 license

use arrayref::array_ref;
use caliptra_builder::{FwId, ImageOptions, APP_WITH_UART, ROM_WITH_UART};
use caliptra_drivers::Array4x12;
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams, ModelError, SecurityState};
use caliptra_image_types::IMAGE_BYTE_SIZE;
use zerocopy::{AsBytes, FromBytes};

pub mod helpers;

// [TODO] Use the error codes from the common library.
const INVALID_IMAGE_SIZE: u32 = 0x02000003;

// TODO: Make this a common type.
/// Caliptra DPE Measurement    
#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug)]
struct Measurement {
    /// Checksum
    pub checksum: u32,

    /// Metadata
    pub metadata: [u8; 4],

    /// Measurement
    pub measurement: [u32; 12],
}

#[test]
fn test_zero_firmware_size() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Zero-sized firmware.
    assert_eq!(
        hw.upload_firmware(&[]).unwrap_err(),
        ModelError::MailboxCmdFailed
    );
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_non_fatal().read(),
        INVALID_IMAGE_SIZE
    );
}

#[test]
fn test_firmware_gt_max_size() {
    const FW_LOAD_CMD_OPCODE: u32 = 0x4657_4C44;

    // Firmware size > 128 KB.

    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Manually put the oversize data in the mailbox because
    // HwModel::upload_firmware won't let us.
    assert!(!hw.soc_mbox().lock().read().lock());
    hw.soc_mbox().cmd().write(|_| FW_LOAD_CMD_OPCODE);
    hw.soc_mbox().dlen().write(|_| (IMAGE_BYTE_SIZE + 1) as u32);
    for i in 0..((IMAGE_BYTE_SIZE + 1 + 3) / 4) {
        hw.soc_mbox().datain().write(|_| i as u32);
    }
    hw.soc_mbox().execute().write(|w| w.execute(true));
    while hw.soc_mbox().status().read().status().cmd_busy() {
        hw.step();
    }
    hw.soc_mbox().execute().write(|w| w.execute(false));

    assert_eq!(
        hw.soc_ifc().cptra_fw_error_non_fatal().read(),
        INVALID_IMAGE_SIZE
    );
}

#[test]
fn test_upload_single_measurement() {
    pub const TEST_FMC_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu"],
    };

    let fuses = Fuses::default();
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        fw_image: None,
    })
    .unwrap();

    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let mut output = vec![];

    // Upload measurement.
    let measurement = Measurement {
        measurement: [0xdeadbeef; 12],
        ..Default::default()
    };
    let result = hw.upload_measurement(measurement.as_bytes());
    assert!(result.is_ok());

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    hw.step_until_output_contains("[exit] Launching FMC")
        .unwrap();

    let result = hw.mailbox_execute(0x1000_1000, &[1u8; 12]);
    assert!(result.is_ok());

    let mailbox_data = result.unwrap().unwrap();
    let pcr1 = Array4x12::from(array_ref!(mailbox_data, 0, 48));
    let result = hw.copy_output_until_exit_success(&mut output);
    assert!(result.is_ok());

    // Check that the measurement was extended to PCR1
    let mut data: [u8; 96] = [0u8; 96];
    data[48..].copy_from_slice(measurement.measurement.as_bytes());
    let out = openssl::sha::sha384(&data);
    assert_eq!(pcr1.0.as_bytes(), out);
}

#[test]
fn test_upload_measurement_limit() {
    pub const TEST_FMC_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu"],
    };

    let fuses = Fuses::default();
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        fw_image: None,
    })
    .unwrap();

    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let mut output = vec![];

    let measurement = Measurement {
        measurement: [0xdeadbeef; 12],
        ..Default::default()
    };

    // Upload 8 measurements.
    for _ in 0..8 {
        let result = hw.upload_measurement(measurement.as_bytes());
        assert!(result.is_ok());
    }

    // Upload a 9th measurement, which should fail.
    let result = hw.upload_measurement(measurement.as_bytes());
    assert!(result.is_err());

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    hw.step_until_output_contains("[exit] Launching FMC")
        .unwrap();

    let result = hw.mailbox_execute(0x1000_1000, &[1u8; 12]);
    assert!(result.is_ok());

    let mailbox_data = result.unwrap().unwrap();
    let pcr1 = Array4x12::from(array_ref!(mailbox_data, 0, 48));
    let result = hw.copy_output_until_exit_success(&mut output);
    assert!(result.is_ok());

    // Check that only 8 measurements were extended to PCR1
    let mut out: [u8; 48] = [0u8; 48];
    let mut data: [u8; 96] = [0u8; 96];
    for _ in 0..8 {
        data[0..48].copy_from_slice(&out);
        data[48..].copy_from_slice(measurement.measurement.as_bytes());
        out = openssl::sha::sha384(&data);
    }
    assert_eq!(pcr1.0.as_bytes(), out);
}
