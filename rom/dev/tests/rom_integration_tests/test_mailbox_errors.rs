// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::ImageOptions;
use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader, StashMeasurementReq};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams, ModelError, SecurityState};
use zerocopy::IntoBytes;

use crate::helpers;

// Since the boot takes less than 30M cycles, we know something is wrong if
// we're stuck at the same state for that duration.
const MAX_WAIT_CYCLES: u32 = 30_000_000;

#[test]
fn test_unknown_command_is_fatal() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // This command does not exist
    // Calculate checksum for unknown command with empty payload (no bytes after header)
    let checksum = caliptra_common::checksum::calc_checksum(
        0xabcd_1234,
        &[], // No payload after header
    );

    // Create final header with correct checksum
    let header = MailboxReqHeader { chksum: checksum };

    // This command does not exist
    assert_eq!(
        hw.mailbox_execute(0xabcd_1234, header.as_bytes()),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::FW_PROC_MAILBOX_INVALID_COMMAND.into()
        ))
    );

    hw.step_until_fatal_error(
        CaliptraError::FW_PROC_MAILBOX_INVALID_COMMAND.into(),
        MAX_WAIT_CYCLES,
    );
}

#[test]
#[cfg_attr(
    any(feature = "fpga_realtime", feature = "fpga_subsystem"),
    ignore = "requires SS_STRAP_GENERIC_3 strap override, which is not supported on FPGA"
)]
fn test_fatal_error_ignores_reserved_reset_strap() {
    const UNKNOWN_COMMAND: u32 = 0xabcd_1234;
    const RESERVED_RESET_STRAP: u32 = 1 << 1;

    let rom = caliptra_builder::build_firmware_rom(helpers::rom_from_env()).unwrap();
    let expected_error = u32::from(CaliptraError::FW_PROC_MAILBOX_INVALID_COMMAND);
    let header = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(UNKNOWN_COMMAND, &[]),
    };

    for subsystem_mode in [false, true] {
        for strap in [0, RESERVED_RESET_STRAP] {
            let mut hw = caliptra_hw_model::new(
                InitParams {
                    rom: &rom,
                    subsystem_mode,
                    security_state: *SecurityState::default().set_debug_locked(true),
                    ..Default::default()
                },
                BootParams {
                    initial_ss_strap_generic_3: Some(strap),
                    ..Default::default()
                },
            )
            .unwrap();

            assert_eq!(hw.soc_ifc().ss_strap_generic().at(3).read(), strap);
            hw.step_until_or_timeout("ready_for_mb_processing", MAX_WAIT_CYCLES, |m| {
                m.soc_ifc()
                    .cptra_flow_status()
                    .read()
                    .ready_for_mb_processing()
            });
            assert!(hw.soc_ifc().cptra_wdt_timer1_en().read().timer1_en());

            // Do not send a recovery DEVICE_RESET request, even with the former wait bit set.
            hw.start_mailbox_execute(UNKNOWN_COMMAND, header.as_bytes())
                .unwrap();
            hw.step_until_or_timeout("fatal error reporting", MAX_WAIT_CYCLES, |m| {
                m.soc_ifc().cptra_fw_error_fatal().read() == expected_error
                    && m.soc_ifc().cptra_fw_error_non_fatal().read() == expected_error
            });

            assert!(!hw.soc_ifc().cptra_wdt_timer1_en().read().timer1_en());
            assert_eq!(
                hw.finish_mailbox_execute(),
                Err(ModelError::MailboxCmdFailed(expected_error))
            );
        }
    }
}

#[test]
#[cfg(not(feature = "fpga_subsystem"))]
fn test_mailbox_command_aborted_after_handle_fatal_error() {
    for pqc_key_type in helpers::PQC_KEY_TYPE.iter() {
        let image_options = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };
        let fuses = Fuses {
            fuse_pqc_key_type: *pqc_key_type as u32,
            ..Default::default()
        };
        let (mut hw, image_bundle) = helpers::build_hw_model_and_image_bundle(fuses, image_options);
        assert_eq!(
            Err(ModelError::MailboxCmdFailed(
                CaliptraError::FW_PROC_INVALID_IMAGE_SIZE.into()
            )),
            hw.upload_firmware(&[])
        );

        // Make sure a new attempt to upload firmware is rejected (even though this
        // command would otherwise succeed)
        //
        // The original failure reason should still be in the register
        assert_eq!(
            hw.upload_firmware(&image_bundle.to_bytes().unwrap()),
            Err(ModelError::MailboxCmdFailed(
                CaliptraError::FW_PROC_INVALID_IMAGE_SIZE.into()
            ))
        );
    }
}

#[test]
fn test_mailbox_invalid_checksum() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Upload measurement.
    let payload = StashMeasurementReq {
        measurement: [0xdeadbeef_u32; 12].as_bytes().try_into().unwrap(),
        hdr: MailboxReqHeader { chksum: 0 },
        metadata: [0xAB; 4],
        context: [0xCD; 48],
        svn: 0xEF01,
    };

    // Calc and update checksum
    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::STASH_MEASUREMENT),
        &payload.as_bytes()[4..],
    );

    // Corrupt the checksum
    let checksum = checksum - 1;

    let payload = StashMeasurementReq {
        hdr: MailboxReqHeader { chksum: checksum },
        ..payload
    };

    assert_eq!(
        hw.mailbox_execute(CommandId::STASH_MEASUREMENT.into(), payload.as_bytes()),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::FW_PROC_MAILBOX_INVALID_CHECKSUM.into()
        ))
    );
}

#[test]
fn test_mailbox_invalid_req_size_large() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Upload measurement.
    let payload = StashMeasurementReq {
        measurement: [0xdeadbeef_u32; 12].as_bytes().try_into().unwrap(),
        hdr: MailboxReqHeader { chksum: 0 },
        metadata: [0xAB; 4],
        context: [0xCD; 48],
        svn: 0xEF01,
    };
    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::CAPABILITIES),
        &payload.as_bytes()[4..],
    );
    let payload = StashMeasurementReq {
        hdr: MailboxReqHeader { chksum: checksum },
        ..payload
    };

    // Send too much data (stash measurement is bigger than capabilities)
    assert_eq!(
        hw.mailbox_execute(CommandId::CAPABILITIES.into(), payload.as_bytes()),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH.into()
        ))
    );
}

#[test]
fn test_mailbox_invalid_req_size_small() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Upload measurement.
    let payload = StashMeasurementReq {
        measurement: [0xdeadbeef_u32; 12].as_bytes().try_into().unwrap(),
        hdr: MailboxReqHeader { chksum: 0 },
        metadata: [0xAB; 4],
        context: [0xCD; 48],
        svn: 0xEF01,
    };
    let payload_size = core::mem::size_of::<StashMeasurementReq>();
    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::STASH_MEASUREMENT),
        &payload.as_bytes()[4..payload_size - 4],
    );
    let payload = StashMeasurementReq {
        hdr: MailboxReqHeader { chksum: checksum },
        ..payload
    };

    // Drop a dword
    assert_eq!(
        hw.mailbox_execute(
            CommandId::STASH_MEASUREMENT.into(),
            &payload.as_bytes()[..payload_size - 4]
        ),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH.into()
        ))
    );
}

#[test]
fn test_mailbox_invalid_req_size_zero() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    assert_eq!(
        hw.mailbox_execute(CommandId::CAPABILITIES.into(), &[]),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH.into()
        ))
    );
}

#[test]
// Changing PAUSER not supported on sw emulator
#[cfg(any(feature = "verilator", feature = "fpga_realtime"))]
fn test_mailbox_reserved_pauser() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Set pauser to the reserved value
    hw.set_axi_user(0xffffffff);

    // Send anything
    assert_eq!(
        hw.mailbox_execute(0x0, &[]),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::FW_PROC_MAILBOX_RESERVED_PAUSER.into()
        ))
    );

    hw.step_until_fatal_error(
        CaliptraError::FW_PROC_MAILBOX_RESERVED_PAUSER.into(),
        MAX_WAIT_CYCLES,
    );
}

#[test]
#[cfg(feature = "stash-measurement-registers")]
fn test_stash_measurement_command_becomes_invalid_when_feature_is_on() {
    let security_state = *SecurityState::default()
        .set_device_lifecycle(caliptra_api_types::DeviceLifecycle::Production);
    let rom = caliptra_builder::build_firmware_rom(
        &caliptra_builder::firmware::rom_tests::ROM_WITH_STASH_MEASUREMENT_FEATURE,
    )
    .unwrap();
    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        BootParams::default(),
    )
    .unwrap();

    let measurement = StashMeasurementReq {
        measurement: [0xdeadbeef_u32; 12].as_bytes().try_into().unwrap(),
        hdr: MailboxReqHeader { chksum: 0 },
        metadata: [0xAB; 4],
        context: [0xCD; 48],
        svn: 0xEF01,
    };
    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::STASH_MEASUREMENT),
        &measurement.as_bytes()[4..],
    );
    let measurement = StashMeasurementReq {
        hdr: MailboxReqHeader { chksum: checksum },
        ..measurement
    };

    let result = hw.upload_measurement(measurement.as_bytes());
    assert_eq!(
        result,
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::FW_PROC_MAILBOX_INVALID_COMMAND.into()
        ))
    );
}
