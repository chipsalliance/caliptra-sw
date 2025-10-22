// Licensed under the Apache-2.0 license

use caliptra_common::mailbox_api::{
    CommandId, MailboxReqHeader, MailboxRespHeader, MldsaVerifyReq,
};
use caliptra_hw_model::{Fuses, HwModel, ModelError};
use caliptra_kat::CaliptraError;
use ml_dsa::signature::Signer;
use ml_dsa::{KeyGen, MlDsa87};
use rand::thread_rng;
use zerocopy::{FromBytes, IntoBytes};

use crate::helpers;

#[test]
fn test_mldsa_verify_cmd() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), Default::default());

    // Generate keypair and sign a message using ml-dsa
    let mut rng = thread_rng();
    let keypair = MlDsa87::key_gen(&mut rng);

    let message = b"Hello, MLDSA verification test!";
    let signature = keypair.signing_key().sign(message);

    // Extract raw bytes for the public key and signature
    let public_key_bytes = keypair.verifying_key().encode();
    let signature_bytes = signature.encode();

    // Pad signature to match expected size (4628 bytes)
    let mut padded_signature = [0u8; 4628];
    padded_signature[..signature_bytes.len()].copy_from_slice(&signature_bytes);

    // First test: bad signature - should fail
    let mut bad_signature = padded_signature;
    bad_signature[0] ^= 0x01; // Flip one bit in the first byte

    let mut bad_cmd = MldsaVerifyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pub_key: public_key_bytes.into(),
        signature: bad_signature,
        message_size: message.len() as u32,
        message: {
            let mut msg_array = [0u8; 4096]; // MAX_CMB_DATA_SIZE
            msg_array[..message.len()].copy_from_slice(message);
            msg_array
        },
    };

    // Calculate checksum for bad signature test
    bad_cmd.hdr.chksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::MLDSA87_SIGNATURE_VERIFY),
        &bad_cmd.as_bytes()[core::mem::size_of_val(&bad_cmd.hdr.chksum)..],
    );

    // This should fail because the signature is invalid
    let bad_response = hw
        .mailbox_execute(
            CommandId::MLDSA87_SIGNATURE_VERIFY.into(),
            bad_cmd.as_bytes(),
        )
        .unwrap_err();

    assert_eq!(
        bad_response,
        ModelError::MailboxCmdFailed(CaliptraError::ROM_MLDSA_VERIFY_FAILED.into())
    );

    // Second test: good signature - should succeed
    let mut cmd = MldsaVerifyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pub_key: public_key_bytes.into(),
        signature: padded_signature,
        message_size: message.len() as u32,
        message: {
            let mut msg_array = [0u8; 4096]; // MAX_CMB_DATA_SIZE
            msg_array[..message.len()].copy_from_slice(message);
            msg_array
        },
    };

    // Calculate checksum
    cmd.hdr.chksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::MLDSA87_SIGNATURE_VERIFY),
        &cmd.as_bytes()[core::mem::size_of_val(&cmd.hdr.chksum)..],
    );

    let response = hw
        .mailbox_execute(CommandId::MLDSA87_SIGNATURE_VERIFY.into(), cmd.as_bytes())
        .unwrap()
        .unwrap();

    let resp_hdr = MailboxRespHeader::ref_from_bytes(response.as_bytes()).unwrap();

    // Verify response checksum
    assert!(caliptra_common::checksum::verify_checksum(
        resp_hdr.chksum,
        0x0,
        &response.as_bytes()[core::mem::size_of_val(&resp_hdr.chksum)..],
    ));

    // Verify FIPS status
    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
}
