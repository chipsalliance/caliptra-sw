// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, MailboxReq, MailboxReqHeader, MailboxRespHeader, OcpLockLoadKatMekReq,
    OcpLockLoadKatMekResp,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel, ModelError};
use zerocopy::{FromBytes, IntoBytes};

use super::{
    boot_ocp_lock_runtime, validate_ocp_lock_response, OcpLockBootParams, TEST_AUX, TEST_METADATA,
};

fn validate_failure_response(
    model: &mut DefaultHwModel,
    response: std::result::Result<Option<Vec<u8>>, ModelError>,
    expected_error: CaliptraError,
) {
    validate_ocp_lock_response(model, response, |response, _| {
        let error_code = response.unwrap_err();
        assert_eq!(
            error_code,
            ModelError::MailboxCmdFailed(expected_error.into())
        );
    });
}

fn validate_success_response(
    model: &mut DefaultHwModel,
    response: std::result::Result<Option<Vec<u8>>, ModelError>,
) {
    validate_ocp_lock_response(model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let response = OcpLockLoadKatMekResp::ref_from_bytes(response.as_bytes()).unwrap();

        // Verify response checksum
        assert!(caliptra_common::checksum::verify_checksum(
            response.hdr.chksum,
            0x0,
            &response.as_bytes()[core::mem::size_of_val(&response.hdr.chksum)..],
        ));

        // Verify FIPS status
        assert_eq!(
            response.hdr.fips_status,
            MailboxRespHeader::FIPS_STATUS_APPROVED
        );
    });
}

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_load_kat_mek_command_success() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        force_ocp_lock_en: true,
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockLoadKatMek(OcpLockLoadKatMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        cmd_timeout: 0xFFFF_FFFF,
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_LOAD_KAT_MEK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_success_response(&mut model, response);
}

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_load_kat_mek_timeout() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        force_ocp_lock_en: true,
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockLoadKatMek(OcpLockLoadKatMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        cmd_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_LOAD_KAT_MEK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_failure_response(&mut model, response, CaliptraError::OCP_LOCK_ENGINE_TIMEOUT);
}

#[test]
fn test_load_kat_mek_truncated_request() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        force_ocp_lock_en: true,
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockLoadKatMek(OcpLockLoadKatMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        cmd_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let payload = cmd.as_bytes().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_LOAD_KAT_MEK.into(),
        &payload[..payload.len() - 4],
    );

    validate_failure_response(
        &mut model,
        response,
        CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
    );
}

#[test]
fn test_load_kat_mek_request_with_trailing_zero() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        force_ocp_lock_en: true,
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockLoadKatMek(OcpLockLoadKatMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        aux_metadata: TEST_AUX,
        cmd_timeout: 0xFFFF_FFFF,
    });
    cmd.populate_chksum().unwrap();

    let mut payload = [0u8; size_of::<OcpLockLoadKatMekReq>() + 4];
    payload[..size_of::<OcpLockLoadKatMekReq>()].copy_from_slice(cmd.as_bytes().unwrap());

    let response = model.mailbox_execute(CommandId::OCP_LOCK_LOAD_KAT_MEK.into(), &payload);

    validate_failure_response(
        &mut model,
        response,
        CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
    );
}
