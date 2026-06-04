// Licensed under the Apache-2.0 license.

//! Integration tests for the `MLDSA87_SIGNATURE_VERIFY` runtime mailbox
//! command (RFC #3700).
//!
//! The command is a thin wrapper around the pure-software ML-DSA-87 verify
//! implementation in `caliptra-mldsa`, so these tests:
//!
//! * derive a deterministic ML-DSA-87 keypair on the host from a seed,
//! * deterministically sign a 64-byte message with that key,
//! * round-trip the resulting `(pub_key, signature, message)` triple through
//!   the runtime mailbox, and
//! * verify both the happy path and a comprehensive set of negative /
//!   malformed inputs.
//!
//! Because the SoC firmware is expected to pre-hash large payloads (see
//! `runtime/README.md`), the `message` field is always 64 bytes and we treat
//! it as opaque — no SHA accelerator interaction is required, unlike the
//! ECDSA / LMS verify mailbox commands.

use crate::common::{assert_error, run_rt_test, RuntimeTestArgs};
use caliptra_common::checksum::calc_checksum;
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, MailboxRespHeader, Mldsa87VerifyReq,
};
use caliptra_hw_model::HwModel;
use caliptra_mldsa::{
    Mldsa87, MLDSA87_PRIVATE_SEED_BYTES, MLDSA87_PUBLIC_KEY_BYTES, MLDSA87_SIGNATURE_BYTES,
};
use caliptra_runtime::RtBootStatus;
use zerocopy::FromBytes;

const MSG_BYTES: usize = 64;

/// Two distinct seeds let us exercise distinct keypairs and confirm that the
/// command rejects cross-key verification.
const SEED_A: [u8; MLDSA87_PRIVATE_SEED_BYTES] = [0x42; MLDSA87_PRIVATE_SEED_BYTES];
const SEED_B: [u8; MLDSA87_PRIVATE_SEED_BYTES] = [0xa5; MLDSA87_PRIVATE_SEED_BYTES];

/// Two distinct 64-byte "digests" used as the verified message. The actual
/// content is irrelevant — these stand in for, e.g., SHA-512 outputs.
const MSG_1: [u8; MSG_BYTES] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];
const MSG_2: [u8; MSG_BYTES] = [
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xfe, 0xed, 0xfa, 0xce, 0xba, 0xad, 0xf0, 0x0d,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x55, 0x55, 0x55, 0x55, 0xaa, 0xaa, 0xaa, 0xaa, 0x5a, 0x5a, 0x5a, 0x5a, 0xa5, 0xa5, 0xa5, 0xa5,
];

/// Helper: derive (pub_key, signature) for `seed` over `msg`.
///
/// The boxed return values keep the ~7 KB of crypto material off the test
/// stack frame.
fn keygen_and_sign(
    seed: &[u8; MLDSA87_PRIVATE_SEED_BYTES],
    msg: &[u8; MSG_BYTES],
) -> (
    Box<[u8; MLDSA87_PUBLIC_KEY_BYTES]>,
    Box<[u8; MLDSA87_SIGNATURE_BYTES]>,
) {
    let mut pk = Box::new([0u8; MLDSA87_PUBLIC_KEY_BYTES]);
    let mut sig = Box::new([0u8; MLDSA87_SIGNATURE_BYTES]);
    Mldsa87::pub_from_seed(seed, &mut pk);
    Mldsa87::sign_deterministic(seed, msg, &mut sig);
    (pk, sig)
}

/// Helper: build a fully-populated `MailboxReq::Mldsa87Verify` and stamp a
/// valid checksum.
fn build_verify_req(
    pub_key: &[u8; MLDSA87_PUBLIC_KEY_BYTES],
    signature: &[u8; MLDSA87_SIGNATURE_BYTES],
    message: &[u8; MSG_BYTES],
) -> MailboxReq {
    let mut req = Box::new(Mldsa87VerifyReq::default());
    req.pub_key = *pub_key;
    req.signature = *signature;
    req._sig_pad = 0;
    req.message = *message;
    let mut cmd = MailboxReq::Mldsa87Verify(*req);
    cmd.populate_chksum().unwrap();
    cmd
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
/// Exercises the full request-parse -> verify -> response path.
#[test]
fn test_mldsa87_verify_cmd() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    boot_ready(&mut model);

    for seed in [&SEED_A, &SEED_B] {
        for msg in [&MSG_1, &MSG_2] {
            let (pk, sig) = keygen_and_sign(seed, msg);
            let cmd = build_verify_req(&pk, &sig, msg);
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
    let mut model = run_rt_test(RuntimeTestArgs::default());
    boot_ready(&mut model);

    let (pk, mut sig) = keygen_and_sign(&SEED_A, &MSG_1);
    sig[0] ^= 0xff;

    let cmd = build_verify_req(&pk, &sig, &MSG_1);
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

/// Verifying a signature against a different message must fail.
#[test]
fn test_mldsa87_verify_failure_wrong_message() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    boot_ready(&mut model);

    let (pk, sig) = keygen_and_sign(&SEED_A, &MSG_1);
    let cmd = build_verify_req(&pk, &sig, &MSG_2);
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
    let mut model = run_rt_test(RuntimeTestArgs::default());
    boot_ready(&mut model);

    let (_, sig_a) = keygen_and_sign(&SEED_A, &MSG_1);
    let (pk_b, _) = keygen_and_sign(&SEED_B, &MSG_1);

    let cmd = build_verify_req(&pk_b, &sig_a, &MSG_1);
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
    let mut model = run_rt_test(RuntimeTestArgs::default());
    boot_ready(&mut model);

    let pk = [0u8; MLDSA87_PUBLIC_KEY_BYTES];
    let sig = [0u8; MLDSA87_SIGNATURE_BYTES];
    let cmd = build_verify_req(&pk, &sig, &MSG_1);
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
    let mut model = run_rt_test(RuntimeTestArgs::default());
    boot_ready(&mut model);

    let (pk, sig) = keygen_and_sign(&SEED_A, &MSG_1);
    let mut req = Box::new(Mldsa87VerifyReq::default());
    req.pub_key = *pk;
    req.signature = *sig;
    req.message = MSG_1;
    // Note: NOT calling populate_chksum, so hdr.chksum stays at 0.
    let cmd = MailboxReq::Mldsa87Verify(*req);

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

/// The `_sig_pad` byte exists solely to align `message` on an 8-byte
/// boundary inside the request struct; RFC #3700 mandates that it be zero.
/// Setting it to a nonzero value must be rejected explicitly with
/// `RUNTIME_MLDSA87_VERIFY_INVALID_PADDING` (i.e., before any verify work
/// is done).
#[test]
fn test_mldsa87_verify_invalid_padding() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    boot_ready(&mut model);

    let (pk, sig) = keygen_and_sign(&SEED_A, &MSG_1);
    let mut req = Box::new(Mldsa87VerifyReq::default());
    req.pub_key = *pk;
    req.signature = *sig;
    req._sig_pad = 1; // RFC #3700 violation
    req.message = MSG_1;
    let mut cmd = MailboxReq::Mldsa87Verify(*req);
    // Recompute checksum so we exercise the padding check, not the chksum check.
    cmd.populate_chksum().unwrap();

    let err = model
        .mailbox_execute(
            u32::from(CommandId::MLDSA87_SIGNATURE_VERIFY),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();

    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_MLDSA87_VERIFY_INVALID_PADDING,
        err,
    );
}

/// Sending a payload that's shorter than `Mldsa87VerifyReq` (but with a
/// valid checksum over the truncated bytes, so the dispatcher's chksum
/// gate passes) must be rejected by the handler's `ref_from_bytes` parse
/// with `RUNTIME_INSUFFICIENT_MEMORY`.
#[test]
fn test_mldsa87_verify_truncated_request() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    boot_ready(&mut model);

    // Build a payload that contains the mailbox header plus a few extra
    // bytes — well short of the full request size.
    let mut payload = vec![0u8; core::mem::size_of::<MailboxReqHeader>() + 32];
    // Compute a valid checksum over everything after the chksum field.
    let chksum_size = core::mem::size_of::<u32>();
    let chksum = calc_checksum(
        u32::from(CommandId::MLDSA87_SIGNATURE_VERIFY),
        &payload[chksum_size..],
    );
    payload[..chksum_size].copy_from_slice(&chksum.to_le_bytes());

    let err = model
        .mailbox_execute(u32::from(CommandId::MLDSA87_SIGNATURE_VERIFY), &payload)
        .unwrap_err();

    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_INSUFFICIENT_MEMORY,
        err,
    );
}
