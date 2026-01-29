// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, MailboxReq, MailboxReqHeader, MailboxRespHeader, OcpLockUnloadMekReq,
    OcpLockUnloadMekResp, OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError};
use zerocopy::{FromBytes, IntoBytes};

use super::{init_model, TestConfig};

const TEST_METADATA: [u8; OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE] =
    [0xDE; OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE];

#[cfg(test)]
fn command_failure_test(config: TestConfig) {
    let mut model = init_model(config);

    let mut cmd = MailboxReq::OcpLockUnloadMek(OcpLockUnloadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        cmd_timeout: 0xFFFF_FFFFu32,
        rdy_timeout: 0xFFFF_FFFFu32,
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_UNLOAD_MEK.into(),
        cmd.as_bytes().unwrap(),
    );
    let error_code = response.unwrap_err();
    assert_eq!(
        error_code,
        ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_OCP_LOCK_UNSUPPORTED_COMMAND.into())
    );
}

#[test]
fn test_unload_mek_success() {
    // TODO: after implementing LOAD_MEK
}

#[test]
fn test_unload_mek_without_loading() {
    let mut model = init_model(TestConfig {
        subsystem_mode: true,
        ocp_lock_en: true,
    });

    let mut cmd = MailboxReq::OcpLockUnloadMek(OcpLockUnloadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        cmd_timeout: 0xFFFF_FFFFu32,
        rdy_timeout: 0xFFFF_FFFFu32,
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_UNLOAD_MEK.into(),
        cmd.as_bytes().unwrap(),
    );

    // behavior of unloading non-existing metadata might be dependent to encryption engine implementation
    if response.is_ok() {
        let response = response.unwrap().unwrap();
        let unload_mek_resp = OcpLockUnloadMekResp::ref_from_bytes(response.as_bytes()).unwrap();

        // Verify response checksum
        assert!(caliptra_common::checksum::verify_checksum(
            unload_mek_resp.hdr.chksum,
            0x0,
            &unload_mek_resp.as_bytes()[core::mem::size_of_val(&unload_mek_resp.hdr.chksum)..],
        ));

        // Verify FIPS status
        assert_eq!(
            unload_mek_resp.hdr.fips_status,
            MailboxRespHeader::FIPS_STATUS_APPROVED
        );

        assert_eq!(unload_mek_resp.reserved, 0);
    } else {
        let error_code = match response.unwrap_err() {
            ModelError::MailboxCmdFailed(code) => code & 0xFFFF_FF00u32, // filter-out encryption engine error codes
            _ => 0, // Map to invalid CaliptraError
        };
        assert_eq!(error_code, u32::from(CaliptraError::OCP_LOCK_ENGINE_ERR));
    }
}

#[test]
fn test_unload_mek_ready_timeout() {
    let mut model = init_model(TestConfig {
        subsystem_mode: true,
        ocp_lock_en: true,
    });

    let mut cmd = MailboxReq::OcpLockUnloadMek(OcpLockUnloadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        cmd_timeout: 0xFFFF_FFFF,
        rdy_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_UNLOAD_MEK.into(),
        cmd.as_bytes().unwrap(),
    );
    let error_code = response.unwrap_err();
    assert_eq!(
        error_code,
        ModelError::MailboxCmdFailed(CaliptraError::OCP_LOCK_ENGINE_TIMEOUT.into())
    );
}

#[test]
fn test_unload_mek_command_timeout() {
    let mut model = init_model(TestConfig {
        subsystem_mode: true,
        ocp_lock_en: true,
    });

    let mut cmd = MailboxReq::OcpLockUnloadMek(OcpLockUnloadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        cmd_timeout: 0,
        rdy_timeout: 0xFFFF_FFFF,
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_UNLOAD_MEK.into(),
        cmd.as_bytes().unwrap(),
    );
    let error_code = response.unwrap_err();
    assert_eq!(
        error_code,
        ModelError::MailboxCmdFailed(CaliptraError::OCP_LOCK_ENGINE_TIMEOUT.into())
    );
}

#[test]
fn test_unload_mek_truncated_request() {
    let mut model = init_model(TestConfig {
        subsystem_mode: true,
        ocp_lock_en: true,
    });

    let mut cmd = MailboxReq::OcpLockUnloadMek(OcpLockUnloadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        cmd_timeout: 0,
        rdy_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let payload = cmd.as_bytes().unwrap();

    let response = model.mailbox_execute(CommandId::OCP_LOCK_UNLOAD_MEK.into(), &payload[..28]);
    let error_code = response.unwrap_err();
    assert_eq!(
        error_code,
        ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_INVALID_REQUEST_LENGTH.into())
    );
}

#[test]
fn test_unload_mek_request_with_trailing_zero() {
    let mut model = init_model(TestConfig {
        subsystem_mode: true,
        ocp_lock_en: true,
    });

    let mut cmd = MailboxReq::OcpLockUnloadMek(OcpLockUnloadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        cmd_timeout: 0,
        rdy_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let mut payload = [0u8; size_of::<OcpLockUnloadMekReq>() + 4];
    payload[..size_of::<OcpLockUnloadMekReq>()].copy_from_slice(cmd.as_bytes().unwrap());

    let response = model.mailbox_execute(CommandId::OCP_LOCK_UNLOAD_MEK.into(), &payload);
    let error_code = response.unwrap_err();
    assert_eq!(
        error_code,
        ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_INVALID_REQUEST_LENGTH.into())
    );
}

#[test]
fn test_unload_mek_lock_disabled() {
    command_failure_test(TestConfig {
        subsystem_mode: true,
        ocp_lock_en: false,
    })
}

#[test]
fn test_unload_mek_subsystem_disabled() {
    command_failure_test(TestConfig {
        subsystem_mode: false,
        ocp_lock_en: true,
    })
}

#[test]
fn test_unload_mek_subsystem_lock_disabled() {
    command_failure_test(TestConfig {
        subsystem_mode: false,
        ocp_lock_en: false,
    })
}
