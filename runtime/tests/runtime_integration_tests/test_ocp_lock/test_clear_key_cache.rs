// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, MailboxReq, MailboxReqHeader, MailboxRespHeader, OcpLockClearKeyCacheReq,
    OcpLockClearKeyCacheResp,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError};
use zerocopy::{FromBytes, IntoBytes};

use super::{init_model, TestConfig};

#[cfg(test)]
fn command_failure_test(config: TestConfig) {
    let mut model = init_model(config);

    let mut cmd = MailboxReq::OcpLockClearKeyCache(OcpLockClearKeyCacheReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        cmd_timeout: 0xFFFF_FFFFu32,
        rdy_timeout: 0xFFFF_FFFFu32,
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_CLEAR_KEY_CACHE.into(),
        cmd.as_bytes().unwrap(),
    );
    let error_code = response.unwrap_err();
    assert_eq!(
        error_code,
        ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_OCP_LOCK_UNSUPPORTED_COMMAND.into())
    );
}

#[test]
fn test_clear_key_cache_success() {
    let mut model = init_model(TestConfig {
        subsystem_mode: true,
        ocp_lock_en: true,
    });

    let mut cmd = MailboxReq::OcpLockClearKeyCache(OcpLockClearKeyCacheReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        cmd_timeout: 0xFFFF_FFFFu32,
        rdy_timeout: 0xFFFF_FFFFu32,
    });
    cmd.populate_chksum().unwrap();

    let response = model
        .mailbox_execute(
            CommandId::OCP_LOCK_CLEAR_KEY_CACHE.into(),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    let clear_key_cache_resp =
        OcpLockClearKeyCacheResp::ref_from_bytes(response.as_bytes()).unwrap();

    // Verify response checksum
    assert!(caliptra_common::checksum::verify_checksum(
        clear_key_cache_resp.hdr.chksum,
        0x0,
        &clear_key_cache_resp.as_bytes()
            [core::mem::size_of_val(&clear_key_cache_resp.hdr.chksum)..],
    ));

    // Verify FIPS status
    assert_eq!(
        clear_key_cache_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    assert_eq!(clear_key_cache_resp.reserved, 0);
}

#[test]
fn test_clear_key_cache_ready_timeout() {
    let mut model = init_model(TestConfig {
        subsystem_mode: true,
        ocp_lock_en: true,
    });

    let mut cmd = MailboxReq::OcpLockClearKeyCache(OcpLockClearKeyCacheReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        cmd_timeout: 0xFFFF_FFFF,
        rdy_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_CLEAR_KEY_CACHE.into(),
        cmd.as_bytes().unwrap(),
    );
    let error_code = response.unwrap_err();
    assert_eq!(
        error_code,
        ModelError::MailboxCmdFailed(CaliptraError::OCP_LOCK_ENGINE_TIMEOUT.into())
    );
}

#[test]
fn test_clear_key_cache_command_timeout() {
    let mut model = init_model(TestConfig {
        subsystem_mode: true,
        ocp_lock_en: true,
    });

    let mut cmd = MailboxReq::OcpLockClearKeyCache(OcpLockClearKeyCacheReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        cmd_timeout: 0,
        rdy_timeout: 0xFFFF_FFFF,
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_CLEAR_KEY_CACHE.into(),
        cmd.as_bytes().unwrap(),
    );
    let error_code = response.unwrap_err();
    assert_eq!(
        error_code,
        ModelError::MailboxCmdFailed(CaliptraError::OCP_LOCK_ENGINE_TIMEOUT.into())
    );
}

#[test]
fn test_clear_key_cache_truncated_request() {
    let mut model = init_model(TestConfig {
        subsystem_mode: true,
        ocp_lock_en: true,
    });

    let mut cmd = MailboxReq::OcpLockClearKeyCache(OcpLockClearKeyCacheReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        cmd_timeout: 0,
        rdy_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let payload = cmd.as_bytes().unwrap();

    let response = model.mailbox_execute(CommandId::OCP_LOCK_CLEAR_KEY_CACHE.into(), &payload[..8]);
    let error_code = response.unwrap_err();
    assert_eq!(
        error_code,
        ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_INVALID_REQUEST_LENGTH.into())
    );
}

#[test]
fn test_clear_key_cache_request_with_trailing_zero() {
    let mut model = init_model(TestConfig {
        subsystem_mode: true,
        ocp_lock_en: true,
    });

    let mut cmd = MailboxReq::OcpLockClearKeyCache(OcpLockClearKeyCacheReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        cmd_timeout: 0,
        rdy_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let mut payload = [0u8; size_of::<OcpLockClearKeyCacheReq>() + 4];
    payload[..size_of::<OcpLockClearKeyCacheReq>()].copy_from_slice(cmd.as_bytes().unwrap());

    let response = model.mailbox_execute(CommandId::OCP_LOCK_CLEAR_KEY_CACHE.into(), &payload);
    let error_code = response.unwrap_err();
    assert_eq!(
        error_code,
        ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_INVALID_REQUEST_LENGTH.into())
    );
}

#[test]
fn test_clear_key_cache_lock_disabled() {
    command_failure_test(TestConfig {
        subsystem_mode: true,
        ocp_lock_en: false,
    })
}

#[test]
fn test_clear_key_cache_subsystem_disabled() {
    command_failure_test(TestConfig {
        subsystem_mode: false,
        ocp_lock_en: true,
    })
}

#[test]
fn test_clear_key_cache_subsystem_lock_disabled() {
    command_failure_test(TestConfig {
        subsystem_mode: false,
        ocp_lock_en: false,
    })
}
