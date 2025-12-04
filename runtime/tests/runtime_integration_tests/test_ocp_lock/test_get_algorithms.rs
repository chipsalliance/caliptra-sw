// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    AccessKeySizes, CommandId, EndorsementAlgorithms, HpkeAlgorithms, MailboxReqHeader,
    MailboxRespHeader, OcpLockGetAlgorithmsResp,
};
use caliptra_api::SocManager;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_runtime::RtBootStatus;

use crate::common::{run_rt_test, RuntimeTestArgs};

use zerocopy::{FromBytes, IntoBytes};

#[test]
fn test_get_algorithms() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::OCP_LOCK_GET_ALGORITHMS),
            &[],
        ),
    };

    let response = model.mailbox_execute(
        u32::from(CommandId::OCP_LOCK_GET_ALGORITHMS),
        payload.as_bytes(),
    );

    if model.subsystem_mode() && model.supports_ocp_lock() {
        let response = response.unwrap().unwrap();
        let get_algs_resp = OcpLockGetAlgorithmsResp::ref_from_bytes(response.as_bytes()).unwrap();

        // Verify response checksum
        assert!(caliptra_common::checksum::verify_checksum(
            get_algs_resp.hdr.chksum,
            0x0,
            &get_algs_resp.as_bytes()[core::mem::size_of_val(&get_algs_resp.hdr.chksum)..],
        ));
        // Verify FIPS status
        assert_eq!(
            get_algs_resp.hdr.fips_status,
            MailboxRespHeader::FIPS_STATUS_APPROVED
        );

        assert_eq!(
            get_algs_resp.endorsement_algorithms,
            EndorsementAlgorithms::all()
        );
        assert_eq!(get_algs_resp.hpke_algorithms, HpkeAlgorithms::all());
        assert_eq!(get_algs_resp.access_key_sizes, AccessKeySizes::LEN_256);
    } else {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_OCP_LOCK_UNSUPPORTED_COMMAND.into(),
            )
        );
    }
}
