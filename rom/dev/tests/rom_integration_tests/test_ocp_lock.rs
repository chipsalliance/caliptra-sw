// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    MailboxReq, OcpLockReportHekMetadataReq, OcpLockReportHekMetadataResp,
    OcpLockReportHekMetadataRespFlags,
};
use caliptra_builder::firmware::ROM_FPGA_WITH_UART;
use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader};
use caliptra_drivers::HekSeedState;
use caliptra_hw_model::{DeviceLifecycle, Fuses, HwModel, SecurityState};
use zerocopy::{FromBytes, IntoBytes};

const ALL_HEK_SEED_STATES: &[HekSeedState] = &[
    HekSeedState::Programmed,
    HekSeedState::ProgrammedEmpty,
    HekSeedState::Unavailable,
];

/// NOTE: These tests assume that `ss_ocp_lock_en` is set to true in the Caliptra bitstream.

#[test]
fn test_hek_seed_states() {
    // Split by lifecycle to avoid booting Caliptra for each test iteration.
    // Test PROD HEK seed states that allow HEK usage
    hek_seed_state_helper(
        DeviceLifecycle::Production,
        &[HekSeedState::Programmed, HekSeedState::ProgrammedEmpty],
        true,
        [0xABDEu32; 8],
    );
    // Test PROD HEK seed states that disallow HEK usage
    hek_seed_state_helper(
        DeviceLifecycle::Production,
        &[HekSeedState::Unavailable],
        false,
        [0xABDEu32; 8],
    );
    // Manufacturing and Unprovisioned LC should allow HEK usage in all HEK seed states.
    hek_seed_state_helper(
        DeviceLifecycle::Manufacturing,
        ALL_HEK_SEED_STATES,
        true,
        [0xABDEu32; 8],
    );
    hek_seed_state_helper(
        DeviceLifecycle::Unprovisioned,
        ALL_HEK_SEED_STATES,
        true,
        [0xABDEu32; 8],
    );
    // A programmed HEK seed cannot be all zeros
    hek_seed_state_helper(
        DeviceLifecycle::Production,
        &[HekSeedState::Programmed],
        false,
        [0; 8],
    );
    // A programmed HEK seed cannot be all 1s
    hek_seed_state_helper(
        DeviceLifecycle::Production,
        &[HekSeedState::Programmed],
        false,
        [u32::MAX; 8],
    );
}

#[test]
fn test_invalid_hek_seed_state() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_FPGA_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state: *SecurityState::default()
                .set_device_lifecycle(DeviceLifecycle::Production),
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    // Skip this test if HW does not support OCP LOCK.
    if !hw.subsystem_mode() || !hw.supports_ocp_lock() {
        return;
    }

    // Check that an unknown HEK Seed state returns HEK unavailable
    for seed_state in 0..10 {
        let state = HekSeedState::from(seed_state);
        if state == HekSeedState::Programmed || state == HekSeedState::ProgrammedEmpty {
            continue;
        }

        let mut cmd = MailboxReq::OcpLockReportHekMetadata(OcpLockReportHekMetadataReq {
            hdr: MailboxReqHeader { chksum: 0 },
            seed_state,
            ..Default::default()
        });
        cmd.populate_chksum().unwrap();
        let response = hw
            .mailbox_execute(
                CommandId::OCP_LOCK_REPORT_HEK_METADATA.into(),
                cmd.as_bytes().unwrap(),
            )
            .unwrap()
            .unwrap();
        let response = OcpLockReportHekMetadataResp::ref_from_bytes(response.as_bytes()).unwrap();
        assert!(
            !response
                .flags
                .contains(OcpLockReportHekMetadataRespFlags::HEK_AVAILABLE),
            "HEK should be unavailable for seed_state 0x{:x}",
            seed_state
        );
    }
}

fn hek_seed_state_helper(
    lifecycle: DeviceLifecycle,
    seed_states: &[HekSeedState],
    expects_hek_available: bool,
    hek_seed: [u32; 8],
) {
    let rom = caliptra_builder::build_firmware_rom(&ROM_FPGA_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state: *SecurityState::default().set_device_lifecycle(lifecycle),
            fuses: Fuses {
                hek_seed,
                ..Default::default()
            },
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
        let mut cmd = MailboxReq::OcpLockReportHekMetadata(OcpLockReportHekMetadataReq {
            hdr: MailboxReqHeader { chksum: 0 },
            seed_state: seed_state.into(),
            ..Default::default()
        });
        cmd.populate_chksum().unwrap();
        let response = hw
            .mailbox_execute(
                CommandId::OCP_LOCK_REPORT_HEK_METADATA.into(),
                cmd.as_bytes().unwrap(),
            )
            .unwrap()
            .unwrap();
        let response = OcpLockReportHekMetadataResp::ref_from_bytes(response.as_bytes()).unwrap();
        assert_eq!(
            response
                .flags
                .contains(OcpLockReportHekMetadataRespFlags::HEK_AVAILABLE),
            expects_hek_available
        );
    }
}
