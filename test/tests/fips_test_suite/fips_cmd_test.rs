// Licensed under the Apache-2.0 license
use crate::common;

use caliptra_builder::firmware::ROM_FAKE_WITH_UART;
use caliptra_builder::{firmware, ImageOptions};
use caliptra_common::fips::FipsVersionCmd;
use caliptra_common::mailbox_api::{
    CommandId, FipsVersionResp, MailboxReqHeader, MailboxRespHeader,
};
use caliptra_drivers::CaliptraError;
use caliptra_hw_model::{BootParams, HwModel, InitParams, ModelError, SecurityState};
use caliptra_hw_model_types::{DeviceLifecycle, Fuses};
use caliptra_test::swap_word_bytes_inplace;
use common::*;
use openssl::sha::sha384;
use zerocopy::{AsBytes, FromBytes};

const HW_REV_ID: u32 = 0x1;

fn bytes_to_be_words_48(buf: &[u8; 48]) -> [u32; 12] {
    let mut result: [u32; 12] = zerocopy::transmute!(*buf);
    swap_word_bytes_inplace(&mut result);
    result
}

fn test_fips_cmds<T: HwModel>(hw: &mut T, fmc_version: u32, app_version: u32) {
    // VERSION
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::VERSION), &[]),
    };

    let fips_version_resp = hw
        .mailbox_execute(u32::from(CommandId::VERSION), payload.as_bytes())
        .unwrap()
        .unwrap();

    // Check command size
    let fips_version_bytes: &[u8] = fips_version_resp.as_bytes();

    // Check values against expected.
    let fips_version = FipsVersionResp::read_from(fips_version_bytes).unwrap();
    assert!(caliptra_common::checksum::verify_checksum(
        fips_version.hdr.chksum,
        0x0,
        &fips_version.as_bytes()[core::mem::size_of_val(&fips_version.hdr.chksum)..],
    ));
    assert_eq!(
        fips_version.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_eq!(fips_version.mode, FipsVersionCmd::MODE);
    assert_eq!(fips_version.fips_rev, [HW_REV_ID, fmc_version, app_version]);
    let name = &fips_version.name[..];
    assert_eq!(name, FipsVersionCmd::NAME.as_bytes());

    // SELF_TEST_START
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::SELF_TEST_START),
            &[],
        ),
    };

    let resp = hw
        .mailbox_execute(u32::from(CommandId::SELF_TEST_START), payload.as_bytes())
        .unwrap()
        .unwrap();

    let resp = MailboxRespHeader::read_from(resp.as_slice()).unwrap();
    // Verify checksum and FIPS status
    assert!(caliptra_common::checksum::verify_checksum(
        resp.chksum,
        0x0,
        &resp.as_bytes()[core::mem::size_of_val(&resp.chksum)..],
    ));
    assert_eq!(resp.fips_status, MailboxRespHeader::FIPS_STATUS_APPROVED);

    // Confirm we can't re-start the FIPS self test while it is in progress.
    let _resp = hw
        .mailbox_execute(u32::from(CommandId::SELF_TEST_START), payload.as_bytes())
        .unwrap_err();

    // SELF_TEST_GET_RESULTS
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::SELF_TEST_GET_RESULTS),
            &[],
        ),
    };

    loop {
        // Get self test results
        match hw.mailbox_execute(
            u32::from(CommandId::SELF_TEST_GET_RESULTS),
            payload.as_bytes(),
        ) {
            Ok(Some(resp)) => {
                let resp = MailboxRespHeader::read_from(resp.as_slice()).unwrap();
                // Verify checksum and FIPS status
                assert!(caliptra_common::checksum::verify_checksum(
                    resp.chksum,
                    0x0,
                    &resp.as_bytes()[core::mem::size_of_val(&resp.chksum)..],
                ));
                if resp.fips_status == MailboxRespHeader::FIPS_STATUS_APPROVED {
                    break;
                }
            }
            Ok(None)
            | Err(ModelError::MailboxCmdFailed(0xE0015))  // RUNTIME_SELF_TEST_IN_PROGRESS
            | Err(ModelError::MailboxCmdFailed(0xE0016))  // RUNTIME_SELF_TEST_NOT_STARTED
            | Err(ModelError::UnableToLockMailbox) => {
                // Give FW time to run
                for _ in 0..10000 {
                    hw.step();
                }
            }
            Err(e) => {
                assert_eq!(e, ModelError::MailboxCmdFailed(0));
            }
        }
    }

    // SHUTDOWN
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::SHUTDOWN), &[]),
    };

    let resp = hw.mailbox_execute(u32::from(CommandId::SHUTDOWN), payload.as_bytes());
    assert!(resp.is_ok());

    assert_eq!(
        hw.mailbox_execute(
            u32::from(CommandId::SELF_TEST_GET_RESULTS),
            payload.as_bytes()
        ),
        Err(ModelError::MailboxCmdFailed(0x000E0008))
    );

    // Check we are rejecting additional commands.
    assert_eq!(
        hw.mailbox_execute(u32::from(CommandId::SHUTDOWN), payload.as_bytes()),
        Err(ModelError::MailboxCmdFailed(0x000E0008))
    );
    assert_eq!(
        hw.mailbox_execute(u32::from(CommandId::VERSION), payload.as_bytes()),
        Err(ModelError::MailboxCmdFailed(0x000E0008))
    );
}

#[test]
pub fn fips_cmd_test_rom() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let boot_params = BootParams {
        init_params: InitParams {
            security_state,
            ..Default::default()
        },
        fuses: Fuses {
            fmc_key_manifest_svn: 0b1111111,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut hw = fips_test_init_to_rom(Some(boot_params));

    test_fips_cmds(&mut hw, 0, 0);
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn fips_cmd_test_fake_rom() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_FAKE_WITH_UART).unwrap();

    let boot_params = BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut hw = fips_test_init_to_rom(Some(boot_params));

    test_fips_cmds(&mut hw, 0, 0);
}

#[test]
pub fn fips_cmd_test_rt() {
    const FMC_VERSION: u32 = 0xFEFEFEFE;
    const APP_VERSION: u32 = 0xCECECECE;

    let security_state = *SecurityState::default()
        .set_debug_locked(false)
        .set_device_lifecycle(DeviceLifecycle::Unprovisioned);

    let image = caliptra_builder::build_and_sign_image(
        &firmware::FMC_WITH_UART,
        &firmware::APP_WITH_UART,
        ImageOptions {
            fmc_version: FMC_VERSION,
            fmc_svn: 9,
            app_version: APP_VERSION,
            ..Default::default()
        },
    )
    .unwrap();
    let vendor_pk_hash =
        bytes_to_be_words_48(&sha384(image.manifest.preamble.vendor_pub_keys.as_bytes()));
    let owner_pk_hash =
        bytes_to_be_words_48(&sha384(image.manifest.preamble.owner_pub_keys.as_bytes()));

    let mut hw = fips_test_init_to_rt(Some(BootParams {
        init_params: InitParams {
            security_state,
            ..Default::default()
        },
        fuses: Fuses {
            key_manifest_pk_hash: vendor_pk_hash,
            owner_pk_hash,
            fmc_key_manifest_svn: 0b1111111,
            ..Default::default()
        },
        fw_image: Some(&image.to_bytes().unwrap()),
        ..Default::default()
    }));

    while !hw.soc_ifc().cptra_flow_status().read().ready_for_runtime() {
        hw.step();
    }

    test_fips_cmds(&mut hw, FMC_VERSION, APP_VERSION);
}

#[test]
pub fn fips_cmd_bad_params_rom() {
    let mut hw = fips_test_init_to_rom(None);

    // Send invalid (incorrect size) command payload to cause a failure
    let resp = hw.mailbox_execute(u32::from(CommandId::VERSION), &[]);
    assert_eq!(
        resp,
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH.into()
        ))
    );
}

#[test]
pub fn fips_cmd_bad_params_rt() {
    let mut hw = fips_test_init_to_rt(None);

    // Send invalid (incorrect size) command payload to cause a failure
    let resp = hw.mailbox_execute(u32::from(CommandId::VERSION), &[]);
    assert_eq!(
        resp,
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS.into()
        ))
    );
}
