// Licensed under the Apache-2.0 license.

//! Integration tests for the `MLDSA87_SIGNATURE_VERIFY` runtime mailbox
//! command.
//!
//! The command verifies an ML-DSA-87 signature over a message digest that
//! has been streamed through Caliptra's SHA accelerator (the same pattern
//! used by `ECDSA384_VERIFY` and `LMS_VERIFY`). Keeping the hashing inside
//! the SHA accelerator preserves the FIPS module boundary for this verify
//! operation.
//!
//! These tests:
//!
//! * derive a deterministic ML-DSA-87 keypair on the host from a seed,
//! * deterministically sign the SHA-384 digest of a host-side message,
//! * stream the same message into the SHA accelerator,
//! * round-trip the resulting `(pub_key, signature)` pair through the
//!   runtime mailbox, and
//! * verify both the happy path and a comprehensive set of negative /
//!   malformed inputs.

use crate::common::{assert_error, run_rt_test, RuntimeTestArgs};
use caliptra_builder::firmware::APP_MLDSA_ATTESTATION;
use caliptra_common::checksum::calc_checksum;
use caliptra_common::mailbox_api::{CommandId, MailboxReq, MailboxRespHeader, Mldsa87VerifyReq};
use caliptra_hw_model::{HwModel, ShaAccMode};
use caliptra_mldsa::{
    Mldsa87, MLDSA87_PRIVATE_SEED_BYTES, MLDSA87_PUBLIC_KEY_BYTES, MLDSA87_SIGNATURE_BYTES,
};
use caliptra_runtime::RtBootStatus;
use openssl::sha::sha384;
use zerocopy::FromBytes;

/// Two distinct seeds let us exercise distinct keypairs and confirm that the
/// command rejects cross-key verification.
const SEED_A: [u8; MLDSA87_PRIVATE_SEED_BYTES] = [0x42; MLDSA87_PRIVATE_SEED_BYTES];
const SEED_B: [u8; MLDSA87_PRIVATE_SEED_BYTES] = [0xa5; MLDSA87_PRIVATE_SEED_BYTES];

/// Two distinct messages used to derive the SHA-384 digest that ML-DSA-87
/// will be asked to verify. The contents are arbitrary — the point is that
/// the host and the SHA accelerator agree on the resulting digest bytes.
const MSG_1: &[u8] = b"caliptra mldsa-87 verify test message #1";
const MSG_2: &[u8] = b"caliptra mldsa-87 verify test message #2 (distinct)";

/// Helper: derive (pub_key, signature) for `seed` over the SHA-384 digest
/// of `msg`.
///
/// The boxed return values keep the ~7 KB of crypto material off the test
/// stack frame.
fn keygen_and_sign(
    seed: &[u8; MLDSA87_PRIVATE_SEED_BYTES],
    msg: &[u8],
) -> (
    Box<[u8; MLDSA87_PUBLIC_KEY_BYTES]>,
    Box<[u8; MLDSA87_SIGNATURE_BYTES]>,
) {
    let mut pk = Box::new([0u8; MLDSA87_PUBLIC_KEY_BYTES]);
    let mut sig = Box::new([0u8; MLDSA87_SIGNATURE_BYTES]);
    Mldsa87::pub_from_seed(seed, &mut pk);
    Mldsa87::sign_deterministic(seed, &sha384(msg), &mut sig);
    (pk, sig)
}

/// Helper: build a fully-populated `MailboxReq::Mldsa87Verify` and stamp a
/// valid checksum. The message itself is not part of the request — callers
/// must stream it through the SHA accelerator separately.
fn build_verify_req(
    pub_key: &[u8; MLDSA87_PUBLIC_KEY_BYTES],
    signature: &[u8; MLDSA87_SIGNATURE_BYTES],
) -> MailboxReq {
    let mut req = Box::new(Mldsa87VerifyReq::default());
    req.pub_key = *pub_key;
    req.signature = *signature;
    let mut cmd = MailboxReq::Mldsa87Verify(*req);
    cmd.populate_chksum().unwrap();
    cmd
}

/// Stream `msg` through the SHA accelerator so the runtime can pick the
/// SHA-384 digest off the accelerator's digest register.
fn prime_sha_acc<T: HwModel>(model: &mut T, msg: &[u8]) {
    model
        .compute_sha512_acc_digest(msg, ShaAccMode::Sha384Stream)
        .unwrap();
}

/// Helper: send an already-populated request and assert the response header
/// looks like a successful FIPS-approved verify.
fn execute_ok<T: HwModel>(model: &mut T, cmd: &MailboxReq) {
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::MLDSA87_SIGNATURE_VERIFY),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("mailbox should have returned a response");

    let resp_hdr = MailboxRespHeader::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    // Checksum field is just 0 because FIPS_STATUS_APPROVED == 0.
    assert_eq!(resp_hdr.chksum, 0);
    assert_eq!(model.soc_ifc().cptra_fw_error_non_fatal().read(), 0);
}

/// Wait until the runtime image is ready to take mailbox commands.
fn boot_ready<T: HwModel>(model: &mut T) {
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });
}

// -------------------------------------------------------------------------
// Positive tests
// -------------------------------------------------------------------------

/// End-to-end happy path: two distinct seeds × two distinct messages.
/// Exercises the full SHA-stream -> request-parse -> verify -> response
/// path.
#[test]
fn test_mldsa87_verify_cmd() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&APP_MLDSA_ATTESTATION),
        ..Default::default()
    });
    boot_ready(&mut model);

    for seed in [&SEED_A, &SEED_B] {
        for msg in [MSG_1, MSG_2] {
            let (pk, sig) = keygen_and_sign(seed, msg);
            prime_sha_acc(&mut model, msg);
            let cmd = build_verify_req(&pk, &sig);
            execute_ok(&mut model, &cmd);
        }
    }
}

// -------------------------------------------------------------------------
// Negative tests (well-formed request, signature does not verify)
// -------------------------------------------------------------------------

/// Flipping a single bit in the signature must cause verification to fail
/// with `RUNTIME_MLDSA87_VERIFY_FAILED` rather than crash or pass.
#[test]
fn test_mldsa87_verify_failure_tampered_signature() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&APP_MLDSA_ATTESTATION),
        ..Default::default()
    });
    boot_ready(&mut model);

    let (pk, mut sig) = keygen_and_sign(&SEED_A, MSG_1);
    sig[0] ^= 0xff;

    prime_sha_acc(&mut model, MSG_1);
    let cmd = build_verify_req(&pk, &sig);
    let err = model
        .mailbox_execute(
            u32::from(CommandId::MLDSA87_SIGNATURE_VERIFY),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();

    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_MLDSA87_VERIFY_FAILED,
        err,
    );
}

/// Verifying a signature against a different message (i.e., a different
/// SHA-384 digest streamed into the accelerator) must fail.
#[test]
fn test_mldsa87_verify_failure_wrong_message() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&APP_MLDSA_ATTESTATION),
        ..Default::default()
    });
    boot_ready(&mut model);

    let (pk, sig) = keygen_and_sign(&SEED_A, MSG_1);
    // Stream a *different* message so the digest in the SHA accelerator
    // does not match what the signature was produced for.
    prime_sha_acc(&mut model, MSG_2);
    let cmd = build_verify_req(&pk, &sig);
    let err = model
        .mailbox_execute(
            u32::from(CommandId::MLDSA87_SIGNATURE_VERIFY),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();

    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_MLDSA87_VERIFY_FAILED,
        err,
    );
}

/// Verifying a signature against a public key from a different seed must
/// fail.
#[test]
fn test_mldsa87_verify_failure_wrong_pub_key() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&APP_MLDSA_ATTESTATION),
        ..Default::default()
    });
    boot_ready(&mut model);

    let (_, sig_a) = keygen_and_sign(&SEED_A, MSG_1);
    let (pk_b, _) = keygen_and_sign(&SEED_B, MSG_1);

    prime_sha_acc(&mut model, MSG_1);
    let cmd = build_verify_req(&pk_b, &sig_a);
    let err = model
        .mailbox_execute(
            u32::from(CommandId::MLDSA87_SIGNATURE_VERIFY),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();

    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_MLDSA87_VERIFY_FAILED,
        err,
    );
}

/// All-zero public key + signature is a degenerate input that the verify
/// algorithm must reject. This exercises the "structurally valid but
/// cryptographically meaningless" path.
#[test]
fn test_mldsa87_verify_failure_all_zero() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&APP_MLDSA_ATTESTATION),
        ..Default::default()
    });
    boot_ready(&mut model);

    let pk = [0u8; MLDSA87_PUBLIC_KEY_BYTES];
    let sig = [0u8; MLDSA87_SIGNATURE_BYTES];
    prime_sha_acc(&mut model, MSG_1);
    let cmd = build_verify_req(&pk, &sig);
    let err = model
        .mailbox_execute(
            u32::from(CommandId::MLDSA87_SIGNATURE_VERIFY),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();

    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_MLDSA87_VERIFY_FAILED,
        err,
    );
}

// -------------------------------------------------------------------------
// Malformed-request tests (request shape is wrong; handler must reject)
// -------------------------------------------------------------------------

/// Sending the request with `chksum = 0` exercises the dispatcher's
/// pre-handler checksum gate. A real client would call `populate_chksum`
/// first; skipping that step must surface as `RUNTIME_INVALID_CHECKSUM`.
#[test]
fn test_mldsa87_verify_bad_chksum() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&APP_MLDSA_ATTESTATION),
        ..Default::default()
    });
    boot_ready(&mut model);

    let (pk, sig) = keygen_and_sign(&SEED_A, MSG_1);
    let mut req = Box::new(Mldsa87VerifyReq::default());
    req.pub_key = *pk;
    req.signature = *sig;
    // Note: NOT calling populate_chksum, so hdr.chksum stays at 0.
    let cmd = MailboxReq::Mldsa87Verify(*req);

    prime_sha_acc(&mut model, MSG_1);
    let err = model
        .mailbox_execute(
            u32::from(CommandId::MLDSA87_SIGNATURE_VERIFY),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();

    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_INVALID_CHECKSUM,
        err,
    );
}

/// Sending a payload larger than `Mldsa87VerifyReq` must be rejected by the
/// mailbox length guard with `RUNTIME_INSUFFICIENT_MEMORY` (the request does
/// not fit the handler's fixed-size request buffer).
///
/// Note: an under-sized (truncated) request is *not* rejected here — the
/// mailbox zero-pads it into the request buffer, so it degenerates to an
/// all-zero key/signature and fails closed with `RUNTIME_MLDSA87_VERIFY_FAILED`
/// (see `test_mldsa87_verify_failure_all_zero`).
#[test]
fn test_mldsa87_verify_oversized_request() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&APP_MLDSA_ATTESTATION),
        ..Default::default()
    });
    boot_ready(&mut model);

    // One word larger than the request buffer trips the mailbox size guard.
    let mut payload = vec![0u8; core::mem::size_of::<Mldsa87VerifyReq>() + 4];
    // A valid checksum is not required to reach the guard (the size check runs
    // first), but stamp one so the payload is otherwise well-formed.
    let chksum_size = core::mem::size_of::<u32>();
    let chksum = calc_checksum(
        u32::from(CommandId::MLDSA87_SIGNATURE_VERIFY),
        &payload[chksum_size..],
    );
    payload[..chksum_size].copy_from_slice(&chksum.to_le_bytes());

    prime_sha_acc(&mut model, MSG_1);
    let err = model
        .mailbox_execute(u32::from(CommandId::MLDSA87_SIGNATURE_VERIFY), &payload)
        .unwrap_err();

    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_INSUFFICIENT_MEMORY,
        err,
    );
}
