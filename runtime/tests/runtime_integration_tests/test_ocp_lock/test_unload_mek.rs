// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, MailboxReq, MailboxReqHeader, MailboxRespHeader, OcpLockUnloadMekReq,
    OcpLockUnloadMekResp, OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE,
};
use caliptra_api::SocManager;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError};
use zerocopy::{FromBytes, IntoBytes};

use super::{
    boot_ocp_lock_runtime, validate_ocp_lock_response, InitializeMekSecretParams, OcpLockBootParams,
};

const TEST_METADATA: [u8; OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE] =
    [0xDE; OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE];

#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
#[test]
fn test_unload_mek_success() {
    // TODO: after implementing LOAD_MEK
}

#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
#[test]
fn test_unload_mek_without_loading() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockUnloadMek(OcpLockUnloadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        cmd_timeout: 0xFFFF_FFFFu32,
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_UNLOAD_MEK.into(),
        cmd.as_bytes().unwrap(),
    );

    let result = validate_ocp_lock_response(&mut model, response, |response, _| {
        // behavior of unloading non-existing metadata might be dependent to encryption engine implementation
        if response.is_ok() {
            let response = response.unwrap().unwrap();
            let unload_mek_resp =
                OcpLockUnloadMekResp::ref_from_bytes(response.as_bytes()).unwrap();

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
            Ok(())
        } else {
            let error_code = response.unwrap_err();
            assert_eq!(
                error_code,
                ModelError::MailboxCmdFailed(CaliptraError::OCP_LOCK_ENGINE_ERR.into())
            );
            Err(error_code)
        }
    });

    // Check if FW_EXTENDED_ERROR_INFO is non-zero when there was an encryption engine error
    if let Some(Err(ModelError::MailboxCmdFailed(x))) = result {
        if x == CaliptraError::OCP_LOCK_ENGINE_ERR.0.get() {
            assert_ne!(0, model.soc_ifc().cptra_fw_extended_error_info().read()[0]);
        }
    }
}

#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
#[test]
fn test_unload_mek_command_timeout() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockUnloadMek(OcpLockUnloadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        cmd_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_UNLOAD_MEK.into(),
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
fn test_unload_mek_truncated_request() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockUnloadMek(OcpLockUnloadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        cmd_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let payload = cmd.as_bytes().unwrap();

    let response = model.mailbox_execute(CommandId::OCP_LOCK_UNLOAD_MEK.into(), &payload[..28]);

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let error_code = response.unwrap_err();
        assert_eq!(
            error_code,
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS.into())
        );
    });
}

#[test]
fn test_unload_mek_request_with_trailing_zero() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockUnloadMek(OcpLockUnloadMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        metadata: TEST_METADATA,
        cmd_timeout: 0,
    });
    cmd.populate_chksum().unwrap();

    let mut payload = [0u8; size_of::<OcpLockUnloadMekReq>() + 4];
    payload[..size_of::<OcpLockUnloadMekReq>()].copy_from_slice(cmd.as_bytes().unwrap());

    let response = model.mailbox_execute(CommandId::OCP_LOCK_UNLOAD_MEK.into(), &payload);

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let error_code = response.unwrap_err();
        assert_eq!(
            error_code,
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS.into())
        );
    });
}
