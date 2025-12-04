// Licensed under the Apache-2.0 license

use caliptra_api::soc_mgr::SocManager;
use caliptra_api_types::{DeviceLifecycle, Fuses};
use caliptra_auth_man_gen::default_test_manifest::{default_test_soc_manifest, DEFAULT_MCU_FW};
use caliptra_builder::{
    firmware::{APP_WITH_UART, APP_WITH_UART_FPGA, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::CommandId;
use caliptra_hw_model::{mbox_write_fifo, BootParams, HwModel, InitParams, SecurityState};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_test::image_pk_desc_hash;
use zerocopy::IntoBytes;

fn default_soc_manifest_bytes(pqc_key_type: FwVerificationPqcKeyType, svn: u32) -> Vec<u8> {
    let manifest = default_test_soc_manifest(&DEFAULT_MCU_FW, pqc_key_type, svn, Crypto::default());
    manifest.as_bytes().to_vec()
}

// Helper function to upload firmware, handling both regular and subsystem modes
fn test_upload_firmware<T: HwModel>(
    model: &mut T,
    fw_image: &[u8],
    pqc_key_type: FwVerificationPqcKeyType,
) {
    if model.subsystem_mode() {
        model
            .upload_firmware_rri(
                fw_image,
                Some(&default_soc_manifest_bytes(pqc_key_type, 1)),
                Some(&DEFAULT_MCU_FW),
            )
            .unwrap();
    } else {
        model.upload_firmware(fw_image).unwrap();
    }
}

#[test]
fn warm_reset_basic() {
    let pqc_key_type = FwVerificationPqcKeyType::LMS; // Default for test
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::rom_for_fw_integration_tests_fpga(cfg!(feature = "fpga_subsystem"))
        .unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &if cfg!(feature = "fpga_subsystem") {
            APP_WITH_UART_FPGA
        } else {
            APP_WITH_UART
        },
        ImageOptions {
            fw_svn: 9,
            pqc_key_type,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let mut hw = caliptra_hw_model::new(
        InitParams {
            fuses: Fuses {
                vendor_pk_hash: vendor_pk_desc_hash,
                owner_pk_hash,
                fw_svn: [0x7F, 0, 0, 0], // Equals 7
                fuse_pqc_key_type: pqc_key_type as u32,
                ..Default::default()
            },
            rom: &rom,
            security_state,
            ..Default::default()
        },
        BootParams {
            ..Default::default()
        },
    )
    .unwrap();

    // Upload firmware using the helper function that handles subsystem mode
    test_upload_firmware(&mut hw, &image.to_bytes().unwrap(), pqc_key_type);

    // Wait for boot
    while !hw.soc_ifc().cptra_flow_status().read().ready_for_runtime() {
        hw.step();
    }

    // Perform warm reset
    hw.warm_reset_flow().unwrap();

    // Wait for boot
    while !hw.soc_ifc().cptra_flow_status().read().ready_for_runtime() {
        hw.step();
    }
}

#[test]
fn warm_reset_during_fw_load() {
    let pqc_key_type = FwVerificationPqcKeyType::LMS; // Default for test
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::rom_for_fw_integration_tests_fpga(cfg!(feature = "fpga_subsystem"))
        .unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &if cfg!(feature = "fpga_subsystem") {
            APP_WITH_UART_FPGA
        } else {
            APP_WITH_UART
        },
        ImageOptions {
            fw_svn: 9,
            pqc_key_type,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let boot_params = BootParams {
        ..Default::default()
    };

    let mut hw = caliptra_hw_model::new(
        InitParams {
            fuses: Fuses {
                vendor_pk_hash: vendor_pk_desc_hash,
                owner_pk_hash,
                fw_svn: [0x7F, 0, 0, 0], // Equals 7
                fuse_pqc_key_type: pqc_key_type as u32,
                ..Default::default()
            },
            rom: &rom,
            security_state,
            ..Default::default()
        },
        boot_params.clone(),
    )
    .unwrap();

    // Start the FW load
    // Wait for rom to be ready for firmware
    while !hw.ready_for_fw() {
        hw.step();
    }

    let buf = image.to_bytes().unwrap();

    if hw.subsystem_mode() {
        // In subsystem mode, use put_firmware_in_rri to stage the firmware
        hw.upload_firmware_rri(
            &buf,
            Some(&default_soc_manifest_bytes(pqc_key_type, 1)),
            Some(&DEFAULT_MCU_FW),
        )
        .unwrap();
        hw.step_until_output_contains("Running Caliptra FMC ...")
            .unwrap();
    } else {
        // For non-subsystem mode, manually start the firmware load
        assert!(!hw.soc_mbox().lock().read().lock());
        hw.soc_mbox()
            .cmd()
            .write(|_| CommandId::FIRMWARE_LOAD.into());
        assert!(mbox_write_fifo(&hw.soc_mbox(), &buf).is_ok());
        hw.soc_mbox().execute().write(|w| w.execute(true));
    }

    // Perform warm reset while ROM is executing the firmware load
    hw.warm_reset_flow().unwrap();

    // Wait for error
    while hw.soc_ifc().cptra_fw_error_fatal().read() == 0 {
        hw.step();
    }
    assert_ne!(hw.soc_ifc().cptra_fw_error_fatal().read(), 0);
}
