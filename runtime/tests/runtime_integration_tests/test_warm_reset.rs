// Licensed under the Apache-2.0 license

use caliptra_api::soc_mgr::SocManager;
use caliptra_builder::{
    firmware::{self, runtime_tests::MBOX, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART},
    ImageOptions,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, DeviceLifecycle, Fuses, HwModel, InitParams, SecurityState};
use caliptra_test::image_pk_desc_hash;
use dpe::DPE_PROFILE;

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
            fw_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        BootParams {
            fuses: Fuses {
                vendor_pk_hash: vendor_pk_desc_hash,
                owner_pk_hash,
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
        vendor_pk_hash: vendor_pk_desc_hash,
        owner_pk_hash,
        ..Default::default()
    });

    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_RT_JOURNEY_PCR_VALIDATION_FAILED)
    });

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());
}

// TODO: https://github.com/chipsalliance/caliptra-sw/issues/2225
#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_mbox_busy_during_warm_reset() {
    // This test uses the mailbox responder binary to set the mailbox_flow_done register to
    // false.
    // A warm reset is then performed, since the mailbox responder binary never sets mailbox_flow_done
    // to true, we verify that the mailbox_flow_done register remains false through the warm reset.
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &MBOX,
        ImageOptions {
            fw_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        BootParams {
            fuses: Fuses {
                vendor_pk_hash: vendor_pk_desc_hash,
                owner_pk_hash,
                ..Default::default()
            },
            fw_image: Some(&image.to_bytes().unwrap()),
            ..Default::default()
        },
    )
    .unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    // 0xE000_0000 == OPCODE_HOLD_COMMAND_BUSY
    model.mailbox_execute(0xE000_0000, &[]).unwrap();

    assert!(!model
        .soc_ifc()
        .cptra_flow_status()
        .read()
        .mailbox_flow_done());

    // Perform warm reset
    model.warm_reset_flow(&Fuses {
        vendor_pk_hash: vendor_pk_desc_hash,
        owner_pk_hash,
        ..Default::default()
    });

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().mailbox_flow_done());
    assert_eq!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(CaliptraError::RUNTIME_CMD_BUSY_DURING_WARM_RESET)
    );
}

// TODO: https://github.com/chipsalliance/caliptra-sw/issues/2225
#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_mbox_idle_during_warm_reset() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions {
            fw_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        BootParams {
            fuses: Fuses {
                vendor_pk_hash: vendor_pk_desc_hash,
                owner_pk_hash,
                fw_svn: [0b1111111, 0, 0, 0],
                ..Default::default()
            },
            fw_image: Some(&image.to_bytes().unwrap()),
            ..Default::default()
        },
    )
    .unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    // Perform warm reset
    model.warm_reset_flow(&Fuses {
        vendor_pk_hash: vendor_pk_desc_hash,
        owner_pk_hash,
        fw_svn: [0b1111111, 0, 0, 0],
        ..Default::default()
    });

    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().mailbox_flow_done());

    assert_ne!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(CaliptraError::RUNTIME_CMD_BUSY_DURING_WARM_RESET)
    );
}
