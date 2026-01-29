// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, MailboxReq, MailboxReqHeader, MailboxRespHeader, OcpLockClearKeyCacheReq,
    OcpLockClearKeyCacheResp,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError};
use zerocopy::{FromBytes, IntoBytes};

use super::{
    boot_ocp_lock_runtime, validate_ocp_lock_response, InitializeMekSecretParams, OcpLockBootParams,
};

#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
#[test]
fn test_clear_key_cache_success() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockClearKeyCache(OcpLockClearKeyCacheReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        cmd_timeout: 0xFFFF_FFFFu32,
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_CLEAR_KEY_CACHE.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
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
    });
}

#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
#[test]
fn test_clear_key_cache_command_timeout() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockClearKeyCache(OcpLockClearKeyCacheReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        cmd_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_CLEAR_KEY_CACHE.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let error_code = response.unwrap_err();
        assert_eq!(
            error_code,
            ModelError::MailboxCmdFailed(CaliptraError::OCP_LOCK_ENGINE_TIMEOUT.into())
        );
    });
}

#[test]
fn test_clear_key_cache_truncated_request() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockClearKeyCache(OcpLockClearKeyCacheReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        cmd_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let payload = cmd.as_bytes().unwrap();

    let response = model.mailbox_execute(CommandId::OCP_LOCK_CLEAR_KEY_CACHE.into(), &payload[..8]);

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let error_code = response.unwrap_err();
        assert_eq!(
            error_code,
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS.into())
        );
    });
}

#[test]
fn test_clear_key_cache_request_with_trailing_zero() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockClearKeyCache(OcpLockClearKeyCacheReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        cmd_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let mut payload = [0u8; size_of::<OcpLockClearKeyCacheReq>() + 4];
    payload[..size_of::<OcpLockClearKeyCacheReq>()].copy_from_slice(cmd.as_bytes().unwrap());

    let response = model.mailbox_execute(CommandId::OCP_LOCK_CLEAR_KEY_CACHE.into(), &payload);

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let error_code = response.unwrap_err();
        assert_eq!(
            error_code,
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS.into())
        );
    });
}
