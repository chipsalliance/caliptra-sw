// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, HpkeAlgorithms, MailboxReq, MailboxRespHeader, OcpLockEnumerateHpkeHandlesReq,
    OcpLockEnumerateHpkeHandlesResp,
};
use caliptra_hw_model::HwModel;

use zerocopy::{FromBytes, IntoBytes};

use super::{boot_ocp_lock_runtime, validate_ocp_lock_response, OcpLockBootParams};

// TODO(clundin): Add tests for hybrid and ECDH KEMs once implemented
// * https://github.com/chipsalliance/caliptra-sw/issues/3033
// * https://github.com/chipsalliance/caliptra-sw/issues/3034

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_enumerate_hpke_handles() {
    // This command should have no dependency on the HEK's availability, so don't include it here.
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams::default());

    let mut cmd =
        MailboxReq::OcpLockEnumerateHpkeHandles(OcpLockEnumerateHpkeHandlesReq::default());
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_ENUMERATE_HPKE_HANDLES.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let enumerate_resp =
            OcpLockEnumerateHpkeHandlesResp::ref_from_bytes(response.as_bytes()).unwrap();

        // Verify response checksum
        assert!(caliptra_common::checksum::verify_checksum(
            enumerate_resp.hdr.chksum,
            0x0,
            &enumerate_resp.as_bytes()[core::mem::size_of_val(&enumerate_resp.hdr.chksum)..],
        ));
        // Verify FIPS status
        assert_eq!(
            enumerate_resp.hdr.fips_status,
            MailboxRespHeader::FIPS_STATUS_APPROVED
        );

        // Currently only ML-KEM is implemented.
        assert_eq!(enumerate_resp.hpke_handle_count, 1);

        let ml_kem = enumerate_resp
            .hpke_handles
            .iter()
            .find(|entry| {
                entry.hpke_algorithm == HpkeAlgorithms::ML_KEM_1024_HKDF_SHA384_AES_256_GCM
            })
            .unwrap();
        assert_eq!(
            ml_kem.hpke_algorithm,
            HpkeAlgorithms::ML_KEM_1024_HKDF_SHA384_AES_256_GCM
        );
        // Handle should not have been rotated yet.
        assert_eq!(ml_kem.handle, 1);
    });
}
