// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CmHashAlgorithm, CmShaReq, MailboxRespHeaderVarSize, MAX_CM_SHA_INPUT_SIZE,
};
use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader, MailboxRespHeader};
use caliptra_drivers::MBOX_SIZE_SUBSYSTEM;
use caliptra_hw_model::{Fuses, HwModel};
use openssl::sha::{sha384, sha512};
use zerocopy::{FromBytes, IntoBytes};

use crate::helpers;

const MAX_CM_SHA_INPUT_SIZE_SUBSYSTEM: usize = 16384 - 12;

#[test]
fn test_cm_sha_sha384() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), Default::default());

    // Message to hash
    let msg: &[u8] = b"Hello, Caliptra! This is a test message for SHA-384 hashing.";

    // Calculate expected hash using OpenSSL
    let expected_hash = sha384(msg);

    // Build the request
    let mut cmd = CmShaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        hash_algorithm: CmHashAlgorithm::Sha384.into(),
        input_size: msg.len() as u32,
        input: [0u8; MAX_CM_SHA_INPUT_SIZE],
    };
    cmd.input[..msg.len()].copy_from_slice(msg);

    // Calculate checksum
    cmd.hdr.chksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::CM_SHA),
        &cmd.as_bytes()[core::mem::size_of_val(&cmd.hdr.chksum)..],
    );

    let response = hw
        .mailbox_execute(
            CommandId::CM_SHA.into(),
            &cmd.as_bytes()[..MAX_CM_SHA_INPUT_SIZE_SUBSYSTEM],
        )
        .unwrap()
        .unwrap();

    // Parse header and hash separately since response is variable size
    let resp_bytes = response.as_bytes();
    let (hdr, hash_bytes) = MailboxRespHeaderVarSize::ref_from_prefix(resp_bytes).unwrap();

    // Verify response checksum
    assert!(caliptra_common::checksum::verify_checksum(
        hdr.hdr.chksum,
        0x0,
        &resp_bytes[core::mem::size_of_val(&hdr.hdr.chksum)..],
    ));

    // Verify FIPS status
    assert_eq!(hdr.hdr.fips_status, MailboxRespHeader::FIPS_STATUS_APPROVED);

    // Verify the hash length
    assert_eq!(hdr.data_len, 48); // SHA-384 produces 48 bytes

    // Verify the hash matches
    assert_eq!(&hash_bytes[..48], &expected_hash[..]);
}

#[test]
fn test_cm_sha_sha512() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), Default::default());

    // Message to hash
    let msg: &[u8] = b"Hello, Caliptra! This is a test message for SHA-512 hashing.";

    // Calculate expected hash using OpenSSL
    let expected_hash = sha512(msg);

    // Build the request
    let mut cmd = CmShaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        hash_algorithm: CmHashAlgorithm::Sha512.into(),
        input_size: msg.len() as u32,
        input: [0u8; MAX_CM_SHA_INPUT_SIZE],
    };
    cmd.input[..msg.len()].copy_from_slice(msg);

    // Calculate checksum
    cmd.hdr.chksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::CM_SHA),
        &cmd.as_bytes()[core::mem::size_of_val(&cmd.hdr.chksum)..],
    );

    let response = hw
        .mailbox_execute(
            CommandId::CM_SHA.into(),
            &cmd.as_bytes()[..MAX_CM_SHA_INPUT_SIZE_SUBSYSTEM],
        )
        .unwrap()
        .unwrap();

    // Parse header and hash separately since response is variable size
    let resp_bytes = response.as_bytes();
    let (hdr, hash_bytes) = MailboxRespHeaderVarSize::ref_from_prefix(resp_bytes).unwrap();

    // Verify response checksum
    assert!(caliptra_common::checksum::verify_checksum(
        hdr.hdr.chksum,
        0x0,
        &resp_bytes[core::mem::size_of_val(&hdr.hdr.chksum)..],
    ));

    // Verify FIPS status
    assert_eq!(hdr.hdr.fips_status, MailboxRespHeader::FIPS_STATUS_APPROVED);

    // Verify the hash length
    assert_eq!(hdr.data_len, 64); // SHA-512 produces 64 bytes

    // Verify the hash matches
    assert_eq!(&hash_bytes[..64], &expected_hash[..]);
}

#[test]
fn test_cm_sha_empty_input() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), Default::default());

    // Empty message
    let msg: &[u8] = b"";

    // Calculate expected hash using OpenSSL
    let expected_hash = sha384(msg);

    // Build the request
    let mut cmd = CmShaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        hash_algorithm: CmHashAlgorithm::Sha384.into(),
        input_size: 0,
        input: [0u8; MAX_CM_SHA_INPUT_SIZE],
    };

    // Calculate checksum
    cmd.hdr.chksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::CM_SHA),
        &cmd.as_bytes()[core::mem::size_of_val(&cmd.hdr.chksum)..],
    );

    let response = hw
        .mailbox_execute(
            CommandId::CM_SHA.into(),
            &cmd.as_bytes()[..MAX_CM_SHA_INPUT_SIZE_SUBSYSTEM],
        )
        .unwrap()
        .unwrap();

    // Parse header and hash separately since response is variable size
    let resp_bytes = response.as_bytes();
    let (hdr, hash_bytes) = MailboxRespHeaderVarSize::ref_from_prefix(resp_bytes).unwrap();

    // Verify the hash length
    assert_eq!(hdr.data_len, 48);

    // Verify the hash matches
    assert_eq!(&hash_bytes[..48], &expected_hash[..]);
}

#[test]
fn test_cm_sha_invalid_algorithm() {
    use caliptra_hw_model::ModelError;
    use caliptra_kat::CaliptraError;

    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), Default::default());

    // Message to hash
    let msg: &[u8] = b"Test message";

    // Build the request with invalid algorithm (0 = Reserved)
    let mut cmd = CmShaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        hash_algorithm: 0, // Invalid: Reserved
        input_size: msg.len() as u32,
        input: [0u8; MAX_CM_SHA_INPUT_SIZE],
    };
    cmd.input[..msg.len()].copy_from_slice(msg);

    // Calculate checksum
    cmd.hdr.chksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::CM_SHA),
        &cmd.as_bytes()[core::mem::size_of_val(&cmd.hdr.chksum)..],
    );

    // This should fail because the algorithm is invalid
    let bad_response = hw
        .mailbox_execute(
            CommandId::CM_SHA.into(),
            &cmd.as_bytes()[..MAX_CM_SHA_INPUT_SIZE_SUBSYSTEM],
        )
        .unwrap_err();

    assert_eq!(
        bad_response,
        ModelError::MailboxCmdFailed(CaliptraError::FW_PROC_MAILBOX_INVALID_PARAMS.into())
    );
}

#[test]
fn test_cm_sha_full_mailbox_all_0xff() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), Default::default());

    // Create a full mailbox payload filled with 0xff (12 bytes overhead)

    let size = if cfg!(feature = "fpga_subsystem") {
        (MBOX_SIZE_SUBSYSTEM - 12) as usize
    } else {
        MAX_CM_SHA_INPUT_SIZE
    };
    let msg = vec![0xffu8; size];

    // Calculate expected hash using OpenSSL
    let expected_hash = sha384(&msg);

    // Build the request with full payload
    let mut cmd = CmShaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        hash_algorithm: CmHashAlgorithm::Sha384.into(),
        input_size: size as u32,
        input: [0xffu8; MAX_CM_SHA_INPUT_SIZE],
    };

    // Calculate checksum
    cmd.hdr.chksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::CM_SHA),
        &cmd.as_bytes()[core::mem::size_of_val(&cmd.hdr.chksum)..size + 12],
    );

    let response = hw
        .mailbox_execute(CommandId::CM_SHA.into(), &cmd.as_bytes()[..size + 12])
        .unwrap()
        .unwrap();

    // Parse header and hash separately since response is variable size
    let resp_bytes = response.as_bytes();
    let (hdr, hash_bytes) = MailboxRespHeaderVarSize::ref_from_prefix(resp_bytes).unwrap();

    // Verify response checksum
    assert!(caliptra_common::checksum::verify_checksum(
        hdr.hdr.chksum,
        0x0,
        &resp_bytes[core::mem::size_of_val(&hdr.hdr.chksum)..],
    ));

    // Verify FIPS status
    assert_eq!(hdr.hdr.fips_status, MailboxRespHeader::FIPS_STATUS_APPROVED);

    // Verify the hash length
    assert_eq!(hdr.data_len, 48); // SHA-384 produces 48 bytes

    // Verify the hash matches
    assert_eq!(&hash_bytes[..48], &expected_hash[..]);
}
