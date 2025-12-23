// Licensed under the Apache-2.0 license

use caliptra_api::soc_mgr::SocManager;
use caliptra_builder::{
    firmware::{APP_WITH_UART, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    BootParams, DeviceLifecycle, Fuses, HwModel, InitParams, SecurityState, SubsystemInitParams,
};
use caliptra_test::image_pk_desc_hash;
use dpe::DPE_PROFILE;

#[test]
fn test_rt_journey_pcr_validation() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = crate::common::rom_for_fw_integration_tests().unwrap();

    let fw_svn = 9;
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        crate::test_update_reset::mbox_test_image(),
        ImageOptions {
            fw_svn,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let binding = image.to_bytes().unwrap();
    let soc_manifest = crate::common::default_soc_manifest_bytes(Default::default(), fw_svn);
    let boot_params = BootParams {
        fw_image: Some(&binding),
        soc_manifest: Some(&soc_manifest),
        mcu_fw_image: Some(crate::common::DEFAULT_MCU_FW),
        ..Default::default()
    };

    let mut model = caliptra_hw_model::new(
        InitParams {
            fuses: Fuses {
                vendor_pk_hash: vendor_pk_desc_hash,
                owner_pk_hash,
                ..Default::default()
            },
            rom: &rom,
            security_state,
            ss_init_params: SubsystemInitParams {
                enable_mcu_uart_log: cfg!(feature = "fpga_subsystem"),
                ..Default::default()
            },
            ..Default::default()
        },
        boot_params.clone(),
    )
    .unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    let _ = model
        .mailbox_execute(0xD000_0000, &[0u8; DPE_PROFILE.tci_size()])
        .unwrap()
        .unwrap();

    // Perform warm reset
    model.warm_reset_flow().unwrap();

    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_RT_JOURNEY_PCR_VALIDATION_FAILED)
    });

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());
}

#[test]
fn test_rt_current_pcr_validation() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = crate::common::rom_for_fw_integration_tests().unwrap();

    let fw_svn = 9;
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        crate::test_update_reset::mbox_test_image(),
        ImageOptions {
            fw_svn,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let binding = image.to_bytes().unwrap();
    let soc_manifest = crate::common::default_soc_manifest_bytes(Default::default(), fw_svn);
    let boot_params = BootParams {
        fw_image: Some(&binding),
        soc_manifest: Some(&soc_manifest),
        mcu_fw_image: Some(crate::common::DEFAULT_MCU_FW),
        ..Default::default()
    };

    let mut model = caliptra_hw_model::new(
        InitParams {
            fuses: Fuses {
                vendor_pk_hash: vendor_pk_desc_hash,
                owner_pk_hash,
                ..Default::default()
            },
            rom: &rom,
            security_state,
            ss_init_params: SubsystemInitParams {
                enable_mcu_uart_log: cfg!(feature = "fpga_subsystem"),
                ..Default::default()
            },
            ..Default::default()
        },
        boot_params.clone(),
    )
    .unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    let _ = model
        .mailbox_execute(0xD000_0001, &[0u8; DPE_PROFILE.tci_size()])
        .unwrap()
        .unwrap();

    // Perform warm reset
    model.warm_reset_flow().unwrap();

    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_RT_CURRENT_PCR_VALIDATION_FAILED)
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

    let rom = crate::common::rom_for_fw_integration_tests().unwrap();

    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        crate::test_update_reset::mbox_test_image(),
        ImageOptions {
            fw_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let binding = image.to_bytes().unwrap();
    let boot_params = BootParams {
        fw_image: Some(&binding),
        ..Default::default()
    };

    let mut model = caliptra_hw_model::new(
        InitParams {
            fuses: Fuses {
                vendor_pk_hash: vendor_pk_desc_hash,
                owner_pk_hash,
                ..Default::default()
            },
            rom: &rom,
            security_state,
            ss_init_params: SubsystemInitParams {
                enable_mcu_uart_log: cfg!(feature = "fpga_subsystem"),
                ..Default::default()
            },
            ..Default::default()
        },
        boot_params.clone(),
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
    model.warm_reset_flow().unwrap();

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

    let rom = crate::common::rom_for_fw_integration_tests().unwrap();

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

    let binding = image.to_bytes().unwrap();
    let boot_params = BootParams {
        fw_image: Some(&binding),
        ..Default::default()
    };

    let mut model = caliptra_hw_model::new(
        InitParams {
            fuses: Fuses {
                vendor_pk_hash: vendor_pk_desc_hash,
                owner_pk_hash,
                fw_svn: [0b1111111, 0, 0, 0],
                ..Default::default()
            },
            rom: &rom,
            security_state,
            ss_init_params: SubsystemInitParams {
                enable_mcu_uart_log: cfg!(feature = "fpga_subsystem"),
                ..Default::default()
            },
            ..Default::default()
        },
        boot_params.clone(),
    )
    .unwrap();

    // Wait for boot
    model.step_until(|m| {
        let status = m.soc_ifc().cptra_flow_status().read();
        status.ready_for_runtime() && status.mailbox_flow_done()
    });

    // Perform warm reset
    model.warm_reset_flow().unwrap();

    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().mailbox_flow_done());

    assert_ne!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(CaliptraError::RUNTIME_CMD_BUSY_DURING_WARM_RESET)
    );
}
