// Licensed under the Apache-2.0 license

//! Integration tests for the SIGN_WITH_EXPORTED_MLDSA mailbox command.
//!
//! The exported ML-DSA CDI slot is normally populated by a DPE export command
//! that does not exist yet, and there is no test backdoor to seed it. Until one
//! exists the successful-sign path is deferred, but every request-validation
//! path (privilege, malformed request, handle-not-found) runs before the CDI
//! lookup and so is covered here.

use caliptra_api::SocManager;
use caliptra_builder::firmware::APP_MLDSA_ATTESTATION;
use caliptra_common::checksum::calc_checksum;
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, SetPqSeedReq, SignWithExportedMldsaReq,
    SET_PQ_SEED_SEED_SIZE,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_runtime::RtBootStatus;
use zerocopy::IntoBytes;

use crate::common::{assert_error, run_pqc_rt_test, run_rt_test, RuntimeTestArgs};

/// Issue SIGN_WITH_EXPORTED_MLDSA and return the raw response bytes.
fn sign(
    model: &mut caliptra_hw_model::DefaultHwModel,
    handle: [u8; 32],
    sign_mode: u32,
    message: &[u8],
) -> Result<Vec<u8>, ModelError> {
    let mut req = SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: handle,
        sign_mode,
        message_size: message.len() as u32,
        message: [0u8; SignWithExportedMldsaReq::MAX_DATA_SIZE],
    };
    req.message[..message.len()].copy_from_slice(message);

    let mut cmd = MailboxReq::SignWithExportedMldsa(req);
    cmd.populate_chksum().unwrap();

    model
        .mailbox_execute(
            CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
            cmd.as_bytes().unwrap(),
        )
        .map(|resp| resp.expect("expected a SIGN_WITH_EXPORTED_MLDSA response"))
}

/// Issue SIGN_WITH_EXPORTED_MLDSA encoded as the full fixed-size struct (rather
/// than the `message_size`-trimmed form). This lets a `message_size` larger than
/// the request buffer be sent, which the checksum-aware `MailboxReq` encoder
/// would otherwise reject client-side.
fn sign_full(
    model: &mut caliptra_hw_model::DefaultHwModel,
    sign_mode: u32,
    message_size: u32,
) -> Result<Vec<u8>, ModelError> {
    let mut req = SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: [0u8; 32],
        sign_mode,
        message_size,
        message: [0u8; SignWithExportedMldsaReq::MAX_DATA_SIZE],
    };
    let cmd_id = u32::from(CommandId::SIGN_WITH_EXPORTED_MLDSA);
    // Checksum covers the request payload after the chksum field itself.
    req.hdr.chksum = calc_checksum(cmd_id, &req.as_bytes()[4..]);

    model
        .mailbox_execute(cmd_id, req.as_bytes())
        .map(|resp| resp.expect("expected a SIGN_WITH_EXPORTED_MLDSA response"))
}

/// Provision the PQ.DevID CDI via SET_PQ_SEED, enabling PQC mode. Signing with an
/// exported CDI requires this to have run first.
fn set_pq_seed(model: &mut caliptra_hw_model::DefaultHwModel) {
    let mut cmd = MailboxReq::SetPqSeed(SetPqSeedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        seed: [0x5a; SET_PQ_SEED_SEED_SIZE],
    });
    cmd.populate_chksum().unwrap();
    model
        .mailbox_execute(u32::from(CommandId::SET_PQ_SEED), cmd.as_bytes().unwrap())
        .expect("SET_PQ_SEED failed");
}

#[test]
fn test_sign_with_exported_mldsa_invalid_sign_mode() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);

    // sign_mode is neither SIGN_MODE_DATA nor SIGN_MODE_EXTERNAL_MU.
    let result = sign(&mut model, [0u8; 32], 0xDEAD_BEEF, b"message");
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_INVALID_PARAMS,
        result.unwrap_err(),
    );
}

#[test]
fn test_sign_with_exported_mldsa_external_mu_wrong_size() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);

    // External-mu mode requires exactly MLDSA87_MU_BYTES (64) of message; any
    // other length is rejected before the CDI lookup.
    for len in [0usize, 32, 63, 65] {
        let msg = vec![0u8; len];
        let result = sign(
            &mut model,
            [0u8; 32],
            SignWithExportedMldsaReq::SIGN_MODE_EXTERNAL_MU,
            &msg,
        );
        assert_error(
            &mut model,
            CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_INVALID_PARAMS,
            result.unwrap_err(),
        );
    }
}

#[test]
fn test_sign_with_exported_mldsa_message_too_large() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);

    // A message_size larger than the buffer must be rejected as invalid params
    // (and must not be used to index the message buffer).
    let result = sign_full(
        &mut model,
        SignWithExportedMldsaReq::SIGN_MODE_DATA,
        SignWithExportedMldsaReq::MAX_DATA_SIZE as u32 + 1,
    );
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_INVALID_PARAMS,
        result.unwrap_err(),
    );
}

#[test]
fn test_sign_with_exported_mldsa_handle_not_found() {
    let mut model = run_pqc_rt_test();
    set_pq_seed(&mut model);

    // No CDI has been exported, so any handle must be rejected as not found.
    let result = sign(
        &mut model,
        [0xFFu8; 32],
        SignWithExportedMldsaReq::SIGN_MODE_DATA,
        b"message",
    );
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_NOT_FOUND,
        result.unwrap_err(),
    );
}

#[test]
fn test_sign_with_exported_mldsa_before_set_pq_seed() {
    let mut model = run_pqc_rt_test();

    // SET_PQ_SEED has not run, so PQC mode is not initialized. A well-formed
    // request that reaches the CDI derivation must be rejected before signing.
    let result = sign(
        &mut model,
        [0u8; 32],
        SignWithExportedMldsaReq::SIGN_MODE_DATA,
        b"message",
    );
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_PQC_NOT_INITIALIZED,
        result.unwrap_err(),
    );
}

#[test]
fn test_sign_with_exported_mldsa_pl1_rejected() {
    use caliptra_builder::ImageOptions;

    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = None;

    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&APP_MLDSA_ATTESTATION),
        test_image_options: Some(image_opts),
        ..Default::default()
    });
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // The privilege check runs before the CDI lookup, so this is rejected
    // regardless of whether a CDI has been exported.
    let result = sign(
        &mut model,
        [0u8; 32],
        SignWithExportedMldsaReq::SIGN_MODE_DATA,
        b"message",
    );
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
        result.unwrap_err(),
    );
}
