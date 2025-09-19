// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    MailboxReq, ReportHekMetadataReq, ReportHekMetadataResp, ReportHekMetadataRespFlags,
};
use caliptra_builder::firmware::ROM_FPGA_WITH_UART;
use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader};
use caliptra_drivers::{CaliptraError, HekSeedState};
use caliptra_hw_model::{DeviceLifecycle, HwModel, ModelError, SecurityState};
use zerocopy::{FromBytes, IntoBytes};

const ALL_HEK_SEED_STATES: &[HekSeedState] = &[
    HekSeedState::Empty,
    HekSeedState::Zeroized,
    HekSeedState::Corrupted,
    HekSeedState::Programmed,
    HekSeedState::Unerasable,
];

/// NOTE: These tests assume that `ss_ocp_lock_en` is set to true in the Caliptra bitstream.

// TODO(clundin): Once runtime is complete, add tests based on `REPORT_HEK_METADATA` scenarios.
// Particularly what happens if `REPORT_HEK_METADATA` is never called.
// Tracked in https://github.com/chipsalliance/caliptra-sw/issues/2450.

#[test]
fn test_hek_seed_states() {
    // Split by lifecycle to avoid booting Caliptra for each test iteration.
    // Test PROD HEK seed states that allow HEK usage
    hek_seed_state_helper(
        DeviceLifecycle::Production,
        &[HekSeedState::Programmed, HekSeedState::Unerasable],
        true,
    );
    // Test PROD HEK seed states that disallow HEK usage
    hek_seed_state_helper(
        DeviceLifecycle::Production,
        &[
            HekSeedState::Empty,
            HekSeedState::Zeroized,
            HekSeedState::Corrupted,
        ],
        false,
    );
    // Manufacturing and Unprovisioned LC should allow HEK usage in all HEK seed states.
    hek_seed_state_helper(DeviceLifecycle::Manufacturing, ALL_HEK_SEED_STATES, true);
    hek_seed_state_helper(DeviceLifecycle::Unprovisioned, ALL_HEK_SEED_STATES, true);
}

#[test]
fn test_invalid_hek_seed_state() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_FPGA_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    // Skip this test if HW does not support OCP LOCK.
    if !hw.subsystem_mode() || !hw.supports_ocp_lock() {
        return;
    }

    let first_invalid_hek_seed_state: u16 = u16::from(HekSeedState::Unerasable) + 1;
    // Check that an unknown HEK Seed state returns an error
    for seed_state in first_invalid_hek_seed_state..first_invalid_hek_seed_state + 3 {
        let mut cmd = MailboxReq::ReportHekMetadata(ReportHekMetadataReq {
            hdr: MailboxReqHeader { chksum: 0 },
            seed_state,
            ..Default::default()
        });
        cmd.populate_chksum().unwrap();
        let response = hw.mailbox_execute(
            CommandId::REPORT_HEK_METADATA.into(),
            cmd.as_bytes().unwrap(),
        );
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::DRIVER_OCP_LOCK_COLD_RESET_INVALID_HEK_SEED.into(),
            )
        );
    }
}

fn hek_seed_state_helper(
    lifecycle: DeviceLifecycle,
    seed_states: &[HekSeedState],
    expects_hek_available: bool,
) {
    let rom = caliptra_builder::build_firmware_rom(&ROM_FPGA_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state: *SecurityState::default().set_device_lifecycle(lifecycle),
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();
    // Skip this test if HW does not support OCP LOCK.
    if !hw.subsystem_mode() || !hw.supports_ocp_lock() {
        return;
    }
    for seed_state in seed_states {
        let mut cmd = MailboxReq::ReportHekMetadata(ReportHekMetadataReq {
            hdr: MailboxReqHeader { chksum: 0 },
            seed_state: seed_state.into(),
            ..Default::default()
        });
        cmd.populate_chksum().unwrap();
        let response = hw
            .mailbox_execute(
                CommandId::REPORT_HEK_METADATA.into(),
                cmd.as_bytes().unwrap(),
            )
            .unwrap()
            .unwrap();
        let response = ReportHekMetadataResp::ref_from_bytes(response.as_bytes()).unwrap();
        assert_eq!(
            response
                .flags
                .contains(ReportHekMetadataRespFlags::HEK_AVAILABLE),
            expects_hek_available
        );
    }
}
