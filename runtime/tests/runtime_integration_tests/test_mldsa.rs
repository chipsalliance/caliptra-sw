// Licensed under the Apache-2.0 license.

use crate::common::{run_rt_test, RuntimeTestArgs};
use caliptra_api::mailbox::{MailboxReq, MailboxReqHeader, MailboxRespHeader, MldsaVerifyReq};
use caliptra_api::SocManager;
use caliptra_common::mailbox_api::CommandId;
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;
use ml_dsa::signature::Signer;
use ml_dsa::{KeyGen, MlDsa87};
use rand::thread_rng;
use zerocopy::{FromBytes, IntoBytes};

#[test]
fn test_mldsa_verify_cmd() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

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

    // Create MLDSA verify request
    let mut cmd = MailboxReq::MldsaVerify(MldsaVerifyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pub_key: public_key_bytes.into(),
        signature: padded_signature,
        message_size: message.len() as u32,
        message: {
            let mut msg_array = [0u8; 4096]; // MAX_CMB_DATA_SIZE
            msg_array[..message.len()].copy_from_slice(message);
            msg_array
        },
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::MLDSA87_VERIFY),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let resp_hdr: &MailboxRespHeader = MailboxRespHeader::ref_from_bytes(resp.as_bytes()).unwrap();

    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    // Checksum is just going to be 0 because FIPS_STATUS_APPROVED is 0
    assert_eq!(resp_hdr.chksum, 0);
    assert_eq!(model.soc_ifc().cptra_fw_error_non_fatal().read(), 0);

    // Test with modified message to ensure signature verification fails
    let mut modified_message = *message;
    modified_message[0] ^= 0x01; // Flip one bit in the first byte

    let mut cmd_fail = MailboxReq::MldsaVerify(MldsaVerifyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pub_key: public_key_bytes.into(),
        signature: padded_signature,
        message_size: modified_message.len() as u32,
        message: {
            let mut msg_array = [0u8; 4096]; // MAX_CMB_DATA_SIZE
            msg_array[..modified_message.len()].copy_from_slice(&modified_message);
            msg_array
        },
    });
    cmd_fail.populate_chksum().unwrap();

    let resp_fail = model
        .mailbox_execute(
            u32::from(CommandId::MLDSA87_VERIFY),
            cmd_fail.as_bytes().unwrap(),
        )
        .unwrap_err();

    crate::common::assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_MLDSA_VERIFY_FAILED,
        resp_fail,
    );
}

#[test]
fn test_mldsa_verify_bad_chksum() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let cmd = MailboxReq::MldsaVerify(MldsaVerifyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pub_key: [0u8; 2592],   // MLDSA87_PUB_KEY_BYTE_SIZE
        signature: [0u8; 4628], // MLDSA87_SIGNATURE_BYTE_SIZE
        message_size: 32,
        message: [0u8; 4096],
    });

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::MLDSA87_VERIFY),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();

    crate::common::assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_INVALID_CHECKSUM,
        resp,
    );
}
