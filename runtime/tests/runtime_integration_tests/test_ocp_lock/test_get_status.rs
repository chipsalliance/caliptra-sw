// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, MailboxReq, MailboxReqHeader, MailboxRespHeader, OcpLockGetStatusReq,
    OcpLockGetStatusResp,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError};
use zerocopy::{FromBytes, IntoBytes};

use super::{
    boot_ocp_lock_runtime, validate_ocp_lock_response, InitializeMekSecretParams, OcpLockBootParams,
};

#[test]
fn test_get_status_success() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            CommandId::OCP_LOCK_GET_STATUS.into(),
            &[],
        ),
    };

    let response = model.mailbox_execute(CommandId::OCP_LOCK_GET_STATUS.into(), payload.as_bytes());

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let get_status_resp = OcpLockGetStatusResp::ref_from_bytes(response.as_bytes()).unwrap();

        // Verify response checksum
        assert!(caliptra_common::checksum::verify_checksum(
            get_status_resp.hdr.chksum,
            0x0,
            &get_status_resp.as_bytes()[core::mem::size_of_val(&get_status_resp.hdr.chksum)..],
        ));

        // Verify FIPS status
        assert_eq!(
            get_status_resp.hdr.fips_status,
            MailboxRespHeader::FIPS_STATUS_APPROVED
        );

        assert_eq!(get_status_resp.reserved, [0u32; 4]);

        #[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
        {
            const CTRL_READY: u32 = 0x8000_0000;
            assert_eq!(get_status_resp.ctrl_register, CTRL_READY);
        }
    });
}

#[test]
fn test_get_status_request_with_trailing_zero() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockGetStatus(OcpLockGetStatusReq {
        hdr: MailboxReqHeader { chksum: 0 },
    });
    cmd.populate_chksum().unwrap();

    let mut payload = [0u8; size_of::<OcpLockGetStatusReq>() + 4];
    payload[..size_of::<OcpLockGetStatusReq>()].copy_from_slice(cmd.as_bytes().unwrap());

    let response = model.mailbox_execute(CommandId::OCP_LOCK_GET_STATUS.into(), &payload);

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let error_code = response.unwrap_err();
        assert_eq!(
            error_code,
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS.into())
        );
    });
}
