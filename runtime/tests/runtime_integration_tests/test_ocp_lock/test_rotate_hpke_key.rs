// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, HpkeAlgorithms, HpkeHandle, MailboxReq, MailboxRespHeader,
    OcpLockEnumerateHpkeHandlesReq, OcpLockEnumerateHpkeHandlesResp, OcpLockRotateHpkeKeyReq,
    OcpLockRotateHpkeKeyResp,
};
use caliptra_hw_model::{HwModel, ModelError};

use caliptra_kat::CaliptraError;
use zerocopy::{FromBytes, IntoBytes};

use super::{
    boot_ocp_lock_runtime, ocp_lock_supported, validate_ocp_lock_response, verify_hpke_pub_key,
    OcpLockBootParams,
};

// TODO(clundin): Verify that the public key from endorsement changes.
// TODO(clundin): When multiple algs are supported verify different orders of rotations will work.

#[test]
fn test_rotate_ml_kem_hpke_handle() {
    // This command should have no dependency on the HEK's availability, so don't include it here.
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams::default());

    let mut cmd =
        MailboxReq::OcpLockEnumerateHpkeHandles(OcpLockEnumerateHpkeHandlesReq::default());
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_ENUMERATE_HPKE_HANDLES.into(),
        cmd.as_bytes().unwrap(),
    );

    // If we don't get the first handle the rest of the test doesn't make such anymore.
    let Some(handle) = validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let enumerate_resp =
            OcpLockEnumerateHpkeHandlesResp::ref_from_bytes(response.as_bytes()).unwrap();

        let key_pair = enumerate_resp
            .hpke_handles
            .iter()
            .find(|handle| {
                handle.hpke_algorithm == HpkeAlgorithms::ML_KEM_1024_HKDF_SHA384_AES_256_GCM
            })
            .unwrap();
        key_pair.handle
    }) else {
        return;
    };

    let first_endorsement = verify_hpke_pub_key(
        &mut model,
        HpkeHandle {
            handle,
            hpke_algorithm: HpkeAlgorithms::ML_KEM_1024_HKDF_SHA384_AES_256_GCM,
        },
    );

    let mut cmd = MailboxReq::OcpLockRotateHpkeKey(OcpLockRotateHpkeKeyReq {
        hpke_handle: handle,
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_ROTATE_HPKE_KEY.into(),
        cmd.as_bytes().unwrap(),
    );
    let Some(handle) = validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let response = OcpLockRotateHpkeKeyResp::ref_from_bytes(response.as_bytes()).unwrap();

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

        assert_eq!(response.hpke_handle, handle + 1);
        response.hpke_handle
    }) else {
        return;
    };

    let second_endorsement = verify_hpke_pub_key(
        &mut model,
        HpkeHandle {
            handle,
            hpke_algorithm: HpkeAlgorithms::ML_KEM_1024_HKDF_SHA384_AES_256_GCM,
        },
    );

    // Don't need this check but let's make sure this test doesn't fail open.
    if ocp_lock_supported(&mut model) {
        assert_ne!(
            first_endorsement.unwrap().pub_key,
            second_endorsement.unwrap().pub_key
        );
    }
}

#[test]
fn test_rotate_unknown_hpke_handle() {
    // This command should have no dependency on the HEK's availability, so don't include it here.
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams::default());

    let mut cmd = MailboxReq::OcpLockRotateHpkeKey(OcpLockRotateHpkeKeyReq {
        hpke_handle: u32::MAX,
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_ROTATE_HPKE_KEY.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_OCP_LOCK_UNKNOWN_HPKE_HANDLE.into(),
            )
        );
    });
}
