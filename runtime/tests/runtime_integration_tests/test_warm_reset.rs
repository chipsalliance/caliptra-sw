// Licensed under the Apache-2.0 license

use caliptra_api::soc_mgr::SocManager;
use caliptra_builder::{
    firmware::{self, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART},
    ImageOptions,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, DeviceLifecycle, Fuses, HwModel, InitParams, SecurityState};
use caliptra_registers::mbox::enums::MboxStatusE;
use dpe::DPE_PROFILE;
use openssl::sha::sha384;
use zerocopy::AsBytes;

fn swap_word_bytes_inplace(words: &mut [u32]) {
    for word in words.iter_mut() {
        *word = word.swap_bytes()
    }
}

fn bytes_to_be_words_48(buf: &[u8; 48]) -> [u32; 12] {
    let mut result: [u32; 12] = zerocopy::transmute!(*buf);
    swap_word_bytes_inplace(&mut result);
    result
}

#[test]
fn test_rt_journey_pcr_validation() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &firmware::runtime_tests::MBOX,
        ImageOptions {
            fmc_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();
    let vendor_pk_desc_hash = bytes_to_be_words_48(&sha384(
        image.manifest.preamble.vendor_pub_key_info.as_bytes(),
    ));
    let owner_pk_desc_hash = bytes_to_be_words_48(&sha384(
        image.manifest.preamble.owner_pub_key_info.as_bytes(),
    ));

    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        BootParams {
            fuses: Fuses {
                key_manifest_pk_hash: vendor_pk_desc_hash,
                owner_pk_hash: owner_pk_desc_hash,
                fmc_key_manifest_svn: 0b1111111,
                ..Default::default()
            },
            fw_image: Some(&image.to_bytes().unwrap()),
            ..Default::default()
        },
    )
    .unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    let _ = model
        .mailbox_execute(0xD000_0000, &[0u8; DPE_PROFILE.get_tci_size()])
        .unwrap()
        .unwrap();

    // Perform warm reset
    model.warm_reset_flow(&Fuses {
        key_manifest_pk_hash: vendor_pk_desc_hash,
        owner_pk_hash: owner_pk_desc_hash,
        fmc_key_manifest_svn: 0b1111111,
        ..Default::default()
    });

    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_RT_JOURNEY_PCR_VALIDATION_FAILED)
    });

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());
}

#[test]
fn test_mbox_busy_during_warm_reset() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions {
            fmc_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();
    let vendor_pk_desc_hash = bytes_to_be_words_48(&sha384(
        image.manifest.preamble.vendor_pub_key_info.as_bytes(),
    ));
    let owner_pk_desc_hash = bytes_to_be_words_48(&sha384(
        image.manifest.preamble.owner_pub_key_info.as_bytes(),
    ));

    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        BootParams {
            fuses: Fuses {
                key_manifest_pk_hash: vendor_pk_desc_hash,
                owner_pk_hash: owner_pk_desc_hash,
                fmc_key_manifest_svn: 0b1111111,
                ..Default::default()
            },
            fw_image: Some(&image.to_bytes().unwrap()),
            ..Default::default()
        },
    )
    .unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    model
        .soc_mbox()
        .status()
        .write(|w| w.status(|_| MboxStatusE::CmdBusy));

    // Perform warm reset
    model.warm_reset_flow(&Fuses {
        key_manifest_pk_hash: vendor_pk_desc_hash,
        owner_pk_hash: owner_pk_desc_hash,
        fmc_key_manifest_svn: 0b1111111,
        ..Default::default()
    });

    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_CMD_BUSY_DURING_WARM_RESET)
    });

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());
}
