// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{CommandId, HpkeAlgorithms, MailboxReq, OcpLockEndorseHpkePubKeyReq};
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_kat::CaliptraError;

use super::{
    boot_ocp_lock_runtime, get_validated_hpke_handle, validate_ocp_lock_response, OcpLockBootParams,
};

// TODO(clundin): Add tests for hybrid and ECDH KEMs once implemented
// * https://github.com/chipsalliance/caliptra-sw/issues/3033
// * https://github.com/chipsalliance/caliptra-sw/issues/3034

#[test]
fn test_endorse_hpke_pubkey() {
    // This command should have no dependency on the HEK's availability, so don't include it here.
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams::default());

    let _ = get_validated_hpke_handle(
        &mut model,
        HpkeAlgorithms::ML_KEM_1024_HKDF_SHA384_AES_256_GCM,
    );
}

#[test]
fn test_endorse_unknown_hpke_handle() {
    // This command should have no dependency on the HEK's availability, so don't include it here.
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams::default());

    let mut cmd = MailboxReq::OcpLockEndorseHpkePubKey(OcpLockEndorseHpkePubKeyReq {
        hpke_handle: u32::MAX,
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_ENDORSE_HPKE_PUB_KEY.into(),
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
