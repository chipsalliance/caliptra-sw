// Licensed under the Apache-2.0 license

use caliptra_builder::{
    firmware::{self, APP_WITH_UART, FMC_WITH_UART},
    version, ImageOptions,
};
use caliptra_common::{
    mailbox_api::{CommandId, MailboxReq, MailboxReqHeader, StashMeasurementReq},
    RomBootStatus,
};
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams, SecurityState};
use caliptra_runtime::RtBootStatus;
use sha2::{Digest, Sha384};
use zerocopy::AsBytes;

use crate::common::{run_rt_test, DEFAULT_APP_VERSION, DEFAULT_FMC_VERSION};

const RT_READY_FOR_COMMANDS: u32 = 0x600;

#[test]
fn test_standard() {
    // Test that the normal runtime firmware boots.
    // Ultimately, this will be useful for exercising Caliptra end-to-end
    // via the mailbox.
    let mut model = run_rt_test(None, None, None);

    model.step_until_boot_status(RT_READY_FOR_COMMANDS, true);
}

#[test]
fn test_boot() {
    let mut model = run_rt_test(Some(&firmware::runtime_tests::BOOT), None, None);

    model.step_until_exit_success().unwrap();
}

#[test]
/// This test differs from the drivers' test_persistent() in that it is ran with the "runtime" flag so
/// it allows us to test conditionally compiled runtime-only persistent data that ROM/FMC may have corrupted.
fn test_persistent_data() {
    let mut model = run_rt_test(Some(&firmware::runtime_tests::PERSISTENT_RT), None, None);

    model.step_until_exit_success().unwrap();
}

#[test]
fn test_fw_version() {
    let mut model = run_rt_test(None, None, None);
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let fw_rev = model.soc_ifc().cptra_fw_rev_id().read();
    // fw_rev[0] is FMC version at 31:16 and ROM version at 15:0
    assert_eq!(
        fw_rev[0],
        ((DEFAULT_FMC_VERSION as u32) << 16) | (version::get_rom_version() as u32)
    );
    assert_eq!(fw_rev[1], DEFAULT_APP_VERSION);
}

#[test]
fn test_update() {
    let image_options = ImageOptions {
        app_version: 0xaabbccdd,
        ..Default::default()
    };
    // Make image to update to. On the FPGA this needs to be done before executing the test,
    // otherwise the test will fail because processor is too busy building to be able to respond to
    // the TRNG call during the initial boot.
    let image =
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_options)
            .unwrap()
            .to_bytes()
            .unwrap();

    // Test that the normal runtime firmware boots.
    // Ultimately, this will be useful for exercising Caliptra end-to-end
    // via the mailbox.
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &image)
        .unwrap();

    model.step_until_boot_status(RT_READY_FOR_COMMANDS, true);

    let fw_rev = model.soc_ifc().cptra_fw_rev_id().read();
    assert_eq!((fw_rev[0] >> 16) as u16, DEFAULT_FMC_VERSION);
    assert_eq!(fw_rev[1], 0xaabbccdd);
}

///This test will be run for 500 times if feature "slow_tests" is enabled and just once if the feature is absent
#[test]
fn test_stress_update() {
    let app_versions = [0xaaabbbbc, 0xaaabbbbd];
    let image_options_0 = ImageOptions {
        app_version: app_versions[0],
        ..Default::default()
    };
    let image_options_1 = ImageOptions {
        app_version: app_versions[1],
        ..Default::default()
    };

    let image = [
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_options_0)
            .unwrap()
            .to_bytes()
            .unwrap(),
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_options_1)
            .unwrap()
            .to_bytes()
            .unwrap(),
    ];

    let mut model = run_rt_test(None, None, None);

    let stress_num = if cfg!(feature = "slow_tests") { 500 } else { 1 };
    let mut image_select = 0;

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    for _ in 0..stress_num {
        if image_select == 0 {
            image_select = 1;
        } else {
            image_select = 0;
        };

        model
            .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &image[image_select])
            .unwrap();

        model.step_until_boot_status(RT_READY_FOR_COMMANDS, true);

        //Check if the new firmware is actually the one we built
        let fw_rev = model.soc_ifc().cptra_fw_rev_id().read();
        assert_eq!((fw_rev[0] >> 16) as u16, DEFAULT_FMC_VERSION);
        assert_eq!(fw_rev[1], app_versions[image_select]);
    }
}

#[test]
fn test_boot_tci_data() {
    let mut model = run_rt_test(Some(&firmware::runtime_tests::MBOX), None, None);

    let rt_journey_pcr_resp = model.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();
    let rt_journey_pcr: [u8; 48] = rt_journey_pcr_resp.as_bytes().try_into().unwrap();

    let valid_pauser_hash_resp = model.mailbox_execute(0x2000_0000, &[]).unwrap().unwrap();
    let valid_pauser_hash: [u8; 48] = valid_pauser_hash_resp.as_bytes().try_into().unwrap();

    // hash expected DPE measurements in order
    let mut hasher = Sha384::new();
    hasher.update(rt_journey_pcr);
    hasher.update(valid_pauser_hash);
    let expected_measurement_hash = hasher.finalize();

    let dpe_measurement_hash = model.mailbox_execute(0x3000_0000, &[]).unwrap().unwrap();
    assert_eq!(expected_measurement_hash.as_bytes(), dpe_measurement_hash);
}

#[test]
fn test_measurement_in_measurement_log_added_to_dpe() {
    let fuses = Fuses::default();
    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let mut model = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        ..Default::default()
    })
    .unwrap();

    let image_bundle = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &firmware::runtime_tests::MBOX,
        ImageOptions::default(),
    )
    .unwrap();

    // Upload measurement to measurement log
    let measurement: [u8; 48] = [0xdeadbeef_u32; 12].as_bytes().try_into().unwrap();
    let mut measurement_log_entry = MailboxReq::StashMeasurement(StashMeasurementReq {
        measurement,
        hdr: MailboxReqHeader { chksum: 0 },
        metadata: [0xAB; 4],
        context: [0xCD; 48],
        svn: 0xEF01,
    });
    measurement_log_entry.populate_chksum().unwrap();

    model
        .upload_measurement(measurement_log_entry.as_bytes().unwrap())
        .unwrap();

    model
        .upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    model.step_until_boot_status(u32::from(RomBootStatus::ColdResetComplete), true);

    let rt_journey_pcr_resp = model.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();
    let rt_journey_pcr: [u8; 48] = rt_journey_pcr_resp.as_bytes().try_into().unwrap();

    let valid_pauser_hash_resp = model.mailbox_execute(0x2000_0000, &[]).unwrap().unwrap();
    let valid_pauser_hash: [u8; 48] = valid_pauser_hash_resp.as_bytes().try_into().unwrap();

    // hash expected DPE measurements in order
    let mut hasher = Sha384::new();
    hasher.update(rt_journey_pcr);
    hasher.update(valid_pauser_hash);
    hasher.update(measurement);
    let expected_measurement_hash = hasher.finalize();

    let dpe_measurement_hash = model.mailbox_execute(0x3000_0000, &[]).unwrap().unwrap();
    assert_eq!(expected_measurement_hash.as_bytes(), dpe_measurement_hash);
}
