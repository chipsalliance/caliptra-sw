// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, MailboxReq, OcpLockGenerateMekReq, OcpLockGenerateMekResp, WrappedKey,
    OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN,
};
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_kat::CaliptraError;

use crate::test_ocp_lock::InitializeMekSecretParams;

use super::{boot_ocp_lock_runtime, validate_ocp_lock_response, OcpLockBootParams};

use zerocopy::{FromBytes, IntoBytes};

const WRAPPED_MEK_TYPE: u16 = 0x3;
const WRAPPED_KEY_LEN: u32 = 64;

#[test]
fn test_generate_mek() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockGenerateMek(OcpLockGenerateMekReq::default());
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_GENERATE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let response = OcpLockGenerateMekResp::ref_from_bytes(response.as_bytes()).unwrap();
        validate_wrapped_key(&response.wrapped_mek);
    });
}

#[test]
fn test_generate_missing_secret_seed() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockGenerateMek(OcpLockGenerateMekReq::default());
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_GENERATE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED.into(),
            )
        );
    });
}

#[test]
fn test_generate_consumed_secret_seed() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockGenerateMek(OcpLockGenerateMekReq::default());
    cmd.populate_chksum().unwrap();

    // Consumes the `MEK_SECRET_SEED` so `GENERATE_MEK` will not work until another call to `INITIALIZE_MEK_SECRET`
    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_GENERATE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let response = OcpLockGenerateMekResp::ref_from_bytes(response.as_bytes()).unwrap();
        validate_wrapped_key(&response.wrapped_mek);
    });

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_GENERATE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );
    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED.into(),
            )
        );
    });
}

#[test]
fn test_generate_mek_missing_hek() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: false,
        force_ocp_lock_en: true,
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockGenerateMek(OcpLockGenerateMekReq::default());
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_GENERATE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED.into(),
            )
        );
    });
}

fn validate_wrapped_key(key: &WrappedKey) {
    assert_eq!(key.key_type, WRAPPED_MEK_TYPE);
    assert_ne!(key.salt, [0; 12]);
    assert_ne!(key.iv, [0; 12]);
    assert_ne!(key.cipher_text_and_auth_tag, [0; 80]);
    assert_eq!(key.metadata_len, 0);
    assert_eq!(key.key_len, WRAPPED_KEY_LEN);
    assert_eq!(key.metadata, [0; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN]);
}
