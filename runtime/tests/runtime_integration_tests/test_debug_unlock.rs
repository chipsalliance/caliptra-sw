// Licensed under the Apache-2.0 license

use crate::common::{run_rt_test, RuntimeTestArgs};
use crate::test_set_auth_manifest::create_auth_manifest_with_metadata;

use caliptra_api::{
    mailbox::{
        CommandId, MailboxReqHeader, ProductionAuthDebugUnlockChallenge,
        ProductionAuthDebugUnlockReq, ProductionAuthDebugUnlockToken,
    },
    SocManager,
};
use caliptra_auth_man_types::{AuthManifestImageMetadata, ImageMetadataFlags};
use caliptra_common::{
    memory_layout::{ROM_ORG, ROM_SIZE, ROM_STACK_ORG, ROM_STACK_SIZE, STACK_ORG, STACK_SIZE},
    FMC_ORG, FMC_SIZE, RUNTIME_ORG, RUNTIME_SIZE,
};
use caliptra_drivers::CaliptraError;
use caliptra_hw_model::{
    CodeRange, DeviceLifecycle, HwModel, ImageInfo, InitParams, ModelError, SecurityState,
    StackInfo, StackRange,
};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_gen::{from_hw_format, ImageGeneratorCrypto};
use fips204::traits::{SerDes, Signer};
use p384::ecdsa::VerifyingKey;
use rand::{rngs::StdRng, SeedableRng};
use sha2::Digest;
use zerocopy::{FromBytes, IntoBytes};

fn u8_to_u32_be(input: &[u8]) -> Vec<u32> {
    input
        .chunks(4)
        .map(|chunk| {
            let mut array = [0u8; 4];
            array.copy_from_slice(chunk);
            u32::from_be_bytes(array)
        })
        .collect()
}

fn u8_to_u32_le(input: &[u8]) -> Vec<u32> {
    input
        .chunks(4)
        .map(|chunk| {
            let mut array = [0u8; 4];
            array.copy_from_slice(chunk);
            u32::from_le_bytes(array)
        })
        .collect()
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_dbg_unlock_prod_success() {
    let signing_ecc_key = p384::ecdsa::SigningKey::random(&mut StdRng::from_entropy());
    let verifying_ecc_key = VerifyingKey::from(&signing_ecc_key);
    let ecc_pub_key_bytes = {
        let mut pk = [0; 96];
        let ecc_key = verifying_ecc_key.to_encoded_point(false);
        pk[..48].copy_from_slice(ecc_key.x().unwrap());
        pk[48..].copy_from_slice(ecc_key.y().unwrap());
        pk
    };

    // Convert to hardware format i.e. big endian for ECC.
    let ecc_pub_key = u8_to_u32_be(&ecc_pub_key_bytes);
    let ecc_pub_key_bytes = ecc_pub_key.as_bytes();

    let (verifying_mldsa_key, signing_mldsa_key) = fips204::ml_dsa_87::try_keygen().unwrap();
    let mldsa_pub_key_bytes = verifying_mldsa_key.into_bytes();

    // Convert to hardware format i.e. little endian for MLDSA.
    let mldsa_pub_key = u8_to_u32_le(&mldsa_pub_key_bytes);
    let mldsa_pub_key_bytes = mldsa_pub_key.as_bytes();

    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let image_info = vec![
        ImageInfo::new(
            StackRange::new(ROM_STACK_ORG + ROM_STACK_SIZE, ROM_STACK_ORG),
            CodeRange::new(ROM_ORG, ROM_ORG + ROM_SIZE),
        ),
        ImageInfo::new(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(FMC_ORG, FMC_ORG + FMC_SIZE),
        ),
        ImageInfo::new(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(RUNTIME_ORG, RUNTIME_ORG + RUNTIME_SIZE),
        ),
    ];

    let unlock_level = 5u8;
    let mut prod_dbg_unlock_keypairs: Vec<(&[u8; 96], &[u8; 2592])> =
        vec![(&[0; 96], &[0; 2592]); 8];
    prod_dbg_unlock_keypairs[(unlock_level - 1) as usize] = (
        ecc_pub_key_bytes.try_into().unwrap(),
        mldsa_pub_key_bytes.try_into().unwrap(),
    );

    let init_params = InitParams {
        rom: &rom,
        security_state,
        prod_dbg_unlock_keypairs,
        debug_intent: true,
        subsystem_mode: true,
        stack_info: Some(StackInfo::new(image_info)),
        ..Default::default()
    };

    let mcu_fw = vec![1, 2, 3, 4];
    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
    let crypto = Crypto::default();
    let digest = from_hw_format(&crypto.sha384_digest(&mcu_fw).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];
    let soc_manifest = create_auth_manifest_with_metadata(metadata);
    let soc_manifest = soc_manifest.as_bytes();

    let runtime_args = RuntimeTestArgs {
        init_params: Some(init_params),
        soc_manifest: Some(soc_manifest),
        mcu_fw_image: Some(&mcu_fw),
        ..Default::default()
    };

    let mut model = run_rt_test(runtime_args);
    model
        .step_until_output_contains("[rt] RT listening for mailbox commands...\n")
        .unwrap();

    // Set the request bit
    model
        .soc_ifc()
        .ss_dbg_manuf_service_reg_req()
        .write(|w| w.prod_dbg_unlock_req(true));

    let request = ProductionAuthDebugUnlockReq {
        length: {
            let req_len = size_of::<ProductionAuthDebugUnlockReq>() - size_of::<MailboxReqHeader>();
            (req_len / size_of::<u32>()) as u32
        },
        unlock_level,
        ..Default::default()
    };
    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ),
        &request.as_bytes()[4..],
    );
    let request = ProductionAuthDebugUnlockReq {
        hdr: MailboxReqHeader { chksum: checksum },
        ..request
    };
    let resp = model
        .mailbox_execute(
            CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ.into(),
            request.as_bytes(),
        )
        .unwrap()
        .unwrap();

    let challenge = ProductionAuthDebugUnlockChallenge::read_from_bytes(resp.as_slice()).unwrap();
    let reserved = [0u8; 3];

    let mut sha384 = sha2::Sha384::new();
    sha384.update(challenge.unique_device_identifier);
    sha384.update([unlock_level]);
    sha384.update(reserved);
    sha384.update(challenge.challenge);
    let sha384_digest = sha384.finalize();
    let (ecc_signature, _id) = signing_ecc_key
        .sign_prehash_recoverable(sha384_digest.as_slice())
        .unwrap();
    let ecc_signature = ecc_signature.to_bytes();
    let ecc_signature = ecc_signature.as_slice();
    // Convert to hardware format i.e. big endian for ECC.
    let ecc_signature = u8_to_u32_be(ecc_signature);

    let mut sha512 = sha2::Sha512::new();
    sha512.update(challenge.unique_device_identifier);
    sha512.update([unlock_level]);
    sha512.update(reserved);
    sha512.update(challenge.challenge);
    let sha512_digest = sha512.finalize();

    let mldsa_signature = signing_mldsa_key
        .try_sign_with_seed(&[0; 32], &sha512_digest, &[])
        .unwrap();
    // Convert to hardware format i.e. little endian for MLDSA
    let mldsa_signature = {
        let mut sig = [0; 4628];
        sig[..4627].copy_from_slice(&mldsa_signature);
        u8_to_u32_le(&sig)
    };

    let token = ProductionAuthDebugUnlockToken {
        length: {
            let req_len =
                size_of::<ProductionAuthDebugUnlockToken>() - size_of::<MailboxReqHeader>();
            (req_len / size_of::<u32>()) as u32
        },
        unique_device_identifier: challenge.unique_device_identifier,
        unlock_level,
        challenge: challenge.challenge,
        ecc_public_key: ecc_pub_key.try_into().unwrap(),
        mldsa_public_key: mldsa_pub_key.try_into().unwrap(),
        ecc_signature: ecc_signature.try_into().unwrap(),
        mldsa_signature: mldsa_signature.try_into().unwrap(),
        ..Default::default()
    };
    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN),
        &token.as_bytes()[4..],
    );
    let token = ProductionAuthDebugUnlockToken {
        hdr: MailboxReqHeader { chksum: checksum },
        ..token
    };

    let _resp = model
        .mailbox_execute(
            CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN.into(),
            token.as_bytes(),
        )
        .unwrap();

    model.step_until(|m| {
        let resp = m.soc_ifc().ss_dbg_manuf_service_reg_rsp().read();
        !resp.prod_dbg_unlock_in_progress()
    });

    assert!(model
        .soc_ifc()
        .ss_dbg_manuf_service_reg_rsp()
        .read()
        .prod_dbg_unlock_success());

    let mut value = model
        .soc_ifc()
        .ss_soc_dbg_unlock_level()
        .get(0)
        .unwrap()
        .read();
    let mut soc_debug_level = 0;

    while value > 1 {
        value >>= 1;
        soc_debug_level += 1;
    }
    soc_debug_level += 1;
    assert!(soc_debug_level == unlock_level);
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_dbg_unlock_prod_invalid_length() {
    let signing_ecc_key = p384::ecdsa::SigningKey::random(&mut StdRng::from_entropy());
    let verifying_ecc_key = VerifyingKey::from(&signing_ecc_key);
    let ecc_pub_key_bytes = {
        let mut pk = [0; 96];
        let ecc_key = verifying_ecc_key.to_encoded_point(false);
        pk[..48].copy_from_slice(ecc_key.x().unwrap());
        pk[48..].copy_from_slice(ecc_key.y().unwrap());
        pk
    };

    // Convert to hardware format i.e. big endian for ECC.
    let ecc_pub_key = u8_to_u32_be(&ecc_pub_key_bytes);
    let ecc_pub_key_bytes = ecc_pub_key.as_bytes();

    let (verifying_mldsa_key, _) = fips204::ml_dsa_87::try_keygen().unwrap();
    let mldsa_pub_key_bytes = verifying_mldsa_key.into_bytes();

    // Convert to hardware format i.e. little endian for MLDSA.
    let mldsa_pub_key = u8_to_u32_le(&mldsa_pub_key_bytes);
    let mldsa_pub_key_bytes = mldsa_pub_key.as_bytes();

    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let image_info = vec![
        ImageInfo::new(
            StackRange::new(ROM_STACK_ORG + ROM_STACK_SIZE, ROM_STACK_ORG),
            CodeRange::new(ROM_ORG, ROM_ORG + ROM_SIZE),
        ),
        ImageInfo::new(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(FMC_ORG, FMC_ORG + FMC_SIZE),
        ),
        ImageInfo::new(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(RUNTIME_ORG, RUNTIME_ORG + RUNTIME_SIZE),
        ),
    ];

    let unlock_level = 2u8;
    let mut prod_dbg_unlock_keypairs: Vec<(&[u8; 96], &[u8; 2592])> =
        vec![(&[0; 96], &[0; 2592]); 8];
    prod_dbg_unlock_keypairs[(unlock_level - 1) as usize] = (
        ecc_pub_key_bytes.try_into().unwrap(),
        mldsa_pub_key_bytes.try_into().unwrap(),
    );

    let init_params = InitParams {
        rom: &rom,
        security_state,
        prod_dbg_unlock_keypairs,
        debug_intent: true,
        subsystem_mode: true,
        stack_info: Some(StackInfo::new(image_info)),
        ..Default::default()
    };

    let mcu_fw = vec![1, 2, 3, 4];
    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
    let crypto = Crypto::default();
    let digest = from_hw_format(&crypto.sha384_digest(&mcu_fw).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];
    let soc_manifest = create_auth_manifest_with_metadata(metadata);
    let soc_manifest = soc_manifest.as_bytes();

    let runtime_args = RuntimeTestArgs {
        init_params: Some(init_params),
        soc_manifest: Some(soc_manifest),
        mcu_fw_image: Some(&mcu_fw),
        ..Default::default()
    };

    let mut model = run_rt_test(runtime_args);
    model
        .step_until_output_contains("[rt] RT listening for mailbox commands...\n")
        .unwrap();

    // Set the request bit
    model
        .soc_ifc()
        .ss_dbg_manuf_service_reg_req()
        .write(|w| w.prod_dbg_unlock_req(true));

    let request = ProductionAuthDebugUnlockReq {
        length: 123u32, // Set an incorrect length
        unlock_level,
        ..Default::default()
    };

    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ),
        &request.as_bytes()[4..],
    );
    let request = ProductionAuthDebugUnlockReq {
        hdr: MailboxReqHeader { chksum: checksum },
        ..request
    };

    assert_eq!(
        model.mailbox_execute(
            CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ.into(),
            request.as_bytes(),
        ),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::SS_DBG_UNLOCK_PROD_INVALID_REQ.into()
        ))
    );
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_dbg_unlock_prod_invalid_token_challenge() {
    let signing_ecc_key = p384::ecdsa::SigningKey::random(&mut StdRng::from_entropy());
    let verifying_ecc_key = VerifyingKey::from(&signing_ecc_key);
    let ecc_pub_key_bytes = {
        let mut pk = [0; 96];
        let ecc_key = verifying_ecc_key.to_encoded_point(false);
        pk[..48].copy_from_slice(ecc_key.x().unwrap());
        pk[48..].copy_from_slice(ecc_key.y().unwrap());
        pk
    };

    // Convert to hardware format i.e. big endian for ECC.
    let ecc_pub_key = u8_to_u32_be(&ecc_pub_key_bytes);
    let ecc_pub_key_bytes = ecc_pub_key.as_bytes();

    let (verifying_mldsa_key, _) = fips204::ml_dsa_87::try_keygen().unwrap();
    let mldsa_pub_key_bytes = verifying_mldsa_key.into_bytes();

    // Convert to hardware format i.e. little endian for MLDSA.
    let mldsa_pub_key = u8_to_u32_le(&mldsa_pub_key_bytes);
    let mldsa_pub_key_bytes = mldsa_pub_key.as_bytes();

    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let image_info = vec![
        ImageInfo::new(
            StackRange::new(ROM_STACK_ORG + ROM_STACK_SIZE, ROM_STACK_ORG),
            CodeRange::new(ROM_ORG, ROM_ORG + ROM_SIZE),
        ),
        ImageInfo::new(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(FMC_ORG, FMC_ORG + FMC_SIZE),
        ),
        ImageInfo::new(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(RUNTIME_ORG, RUNTIME_ORG + RUNTIME_SIZE),
        ),
    ];

    let unlock_level = 5u8;
    let mut prod_dbg_unlock_keypairs: Vec<(&[u8; 96], &[u8; 2592])> =
        vec![(&[0; 96], &[0; 2592]); 8];
    prod_dbg_unlock_keypairs[(unlock_level - 1) as usize] = (
        ecc_pub_key_bytes.try_into().unwrap(),
        mldsa_pub_key_bytes.try_into().unwrap(),
    );

    let init_params = InitParams {
        rom: &rom,
        security_state,
        prod_dbg_unlock_keypairs,
        debug_intent: true,
        subsystem_mode: true,
        stack_info: Some(StackInfo::new(image_info)),
        ..Default::default()
    };

    let mcu_fw = vec![1, 2, 3, 4];
    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
    let crypto = Crypto::default();
    let digest = from_hw_format(&crypto.sha384_digest(&mcu_fw).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];
    let soc_manifest = create_auth_manifest_with_metadata(metadata);
    let soc_manifest = soc_manifest.as_bytes();

    let runtime_args = RuntimeTestArgs {
        init_params: Some(init_params),
        soc_manifest: Some(soc_manifest),
        mcu_fw_image: Some(&mcu_fw),
        ..Default::default()
    };

    let mut model = run_rt_test(runtime_args);
    model
        .step_until_output_contains("[rt] RT listening for mailbox commands...\n")
        .unwrap();

    // Set the request bit
    model
        .soc_ifc()
        .ss_dbg_manuf_service_reg_req()
        .write(|w| w.prod_dbg_unlock_req(true));

    let request = ProductionAuthDebugUnlockReq {
        length: {
            let req_len = size_of::<ProductionAuthDebugUnlockReq>() - size_of::<MailboxReqHeader>();
            (req_len / size_of::<u32>()) as u32
        },
        unlock_level,
        ..Default::default()
    };
    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ),
        &request.as_bytes()[4..],
    );
    let request = ProductionAuthDebugUnlockReq {
        hdr: MailboxReqHeader { chksum: checksum },
        ..request
    };
    let resp = model
        .mailbox_execute(
            CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ.into(),
            request.as_bytes(),
        )
        .unwrap()
        .unwrap();

    let challenge = ProductionAuthDebugUnlockChallenge::read_from_bytes(resp.as_slice()).unwrap();
    let invalid_challenge = [0u8; 48];

    let token = ProductionAuthDebugUnlockToken {
        length: {
            let req_len =
                size_of::<ProductionAuthDebugUnlockToken>() - size_of::<MailboxReqHeader>();
            (req_len / size_of::<u32>()) as u32
        },
        unique_device_identifier: challenge.unique_device_identifier,
        unlock_level,
        challenge: invalid_challenge,
        ecc_public_key: ecc_pub_key.try_into().unwrap(),
        mldsa_public_key: mldsa_pub_key.try_into().unwrap(),
        ecc_signature: [0u32; 24],     // Invalid signature
        mldsa_signature: [0u32; 1157], // Invalid signature
        ..Default::default()
    };
    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN),
        &token.as_bytes()[4..],
    );
    let token = ProductionAuthDebugUnlockToken {
        hdr: MailboxReqHeader { chksum: checksum },
        ..token
    };

    let _ = model.mailbox_execute(
        CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN.into(),
        token.as_bytes(),
    );

    model.step_until(|m| {
        let resp = m.soc_ifc().ss_dbg_manuf_service_reg_rsp().read();
        !resp.prod_dbg_unlock_in_progress()
    });

    assert!(model
        .soc_ifc()
        .ss_dbg_manuf_service_reg_rsp()
        .read()
        .prod_dbg_unlock_fail());
}

#[test]
fn test_dbg_unlock_prod_wrong_public_keys() {
    let signing_ecc_key = p384::ecdsa::SigningKey::random(&mut StdRng::from_entropy());
    let verifying_ecc_key = VerifyingKey::from(&signing_ecc_key);
    let ecc_pub_key_bytes = {
        let mut pk = [0; 96];
        let ecc_key = verifying_ecc_key.to_encoded_point(false);
        pk[..48].copy_from_slice(ecc_key.x().unwrap());
        pk[48..].copy_from_slice(ecc_key.y().unwrap());
        pk
    };

    // Convert to hardware format i.e. big endian for ECC.
    let ecc_pub_key = u8_to_u32_be(&ecc_pub_key_bytes);
    let ecc_pub_key_bytes = ecc_pub_key.as_bytes();

    let (verifying_mldsa_key, _) = fips204::ml_dsa_87::try_keygen().unwrap();
    let mldsa_pub_key_bytes = verifying_mldsa_key.into_bytes();

    // Convert to hardware format i.e. little endian for MLDSA.
    let mldsa_pub_key = u8_to_u32_le(&mldsa_pub_key_bytes);
    let mldsa_pub_key_bytes = mldsa_pub_key.as_bytes();

    // Generate a different set of keys that aren't registered with the hardware
    let different_signing_ecc_key = p384::ecdsa::SigningKey::random(&mut StdRng::from_entropy());
    let different_verifying_ecc_key = VerifyingKey::from(&different_signing_ecc_key);
    let different_ecc_pub_key_bytes = {
        let mut pk = [0; 96];
        let ecc_key = different_verifying_ecc_key.to_encoded_point(false);
        pk[..48].copy_from_slice(ecc_key.x().unwrap());
        pk[48..].copy_from_slice(ecc_key.y().unwrap());
        pk
    };
    let different_ecc_pub_key = u8_to_u32_be(&different_ecc_pub_key_bytes);

    let (different_verifying_mldsa_key, _) = fips204::ml_dsa_87::try_keygen().unwrap();
    let different_mldsa_pub_key_bytes = different_verifying_mldsa_key.into_bytes();
    let different_mldsa_pub_key = u8_to_u32_be(&different_mldsa_pub_key_bytes);

    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let image_info = vec![
        ImageInfo::new(
            StackRange::new(ROM_STACK_ORG + ROM_STACK_SIZE, ROM_STACK_ORG),
            CodeRange::new(ROM_ORG, ROM_ORG + ROM_SIZE),
        ),
        ImageInfo::new(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(FMC_ORG, FMC_ORG + FMC_SIZE),
        ),
        ImageInfo::new(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(RUNTIME_ORG, RUNTIME_ORG + RUNTIME_SIZE),
        ),
    ];

    let unlock_level = 5u8;
    let mut prod_dbg_unlock_keypairs: Vec<(&[u8; 96], &[u8; 2592])> =
        vec![(&[0; 96], &[0; 2592]); 8];
    prod_dbg_unlock_keypairs[(unlock_level - 1) as usize] = (
        ecc_pub_key_bytes.try_into().unwrap(),
        mldsa_pub_key_bytes.try_into().unwrap(),
    );

    let init_params = InitParams {
        rom: &rom,
        security_state,
        prod_dbg_unlock_keypairs,
        debug_intent: true,
        subsystem_mode: true,
        stack_info: Some(StackInfo::new(image_info)),
        ..Default::default()
    };

    let mcu_fw = vec![1, 2, 3, 4];
    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
    let crypto = Crypto::default();
    let digest = from_hw_format(&crypto.sha384_digest(&mcu_fw).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];
    let soc_manifest = create_auth_manifest_with_metadata(metadata);
    let soc_manifest = soc_manifest.as_bytes();

    let runtime_args = RuntimeTestArgs {
        init_params: Some(init_params),
        soc_manifest: Some(soc_manifest),
        mcu_fw_image: Some(&mcu_fw),
        ..Default::default()
    };

    let mut model = run_rt_test(runtime_args);
    model
        .step_until_output_contains("[rt] RT listening for mailbox commands...\n")
        .unwrap();

    // Set the request bit
    model
        .soc_ifc()
        .ss_dbg_manuf_service_reg_req()
        .write(|w| w.prod_dbg_unlock_req(true));

    let request = ProductionAuthDebugUnlockReq {
        length: {
            let req_len = size_of::<ProductionAuthDebugUnlockReq>() - size_of::<MailboxReqHeader>();
            (req_len / size_of::<u32>()) as u32
        },
        unlock_level,
        ..Default::default()
    };
    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ),
        &request.as_bytes()[4..],
    );
    let request = ProductionAuthDebugUnlockReq {
        hdr: MailboxReqHeader { chksum: checksum },
        ..request
    };
    let resp = model
        .mailbox_execute(
            CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ.into(),
            request.as_bytes(),
        )
        .unwrap()
        .unwrap();

    let challenge = ProductionAuthDebugUnlockChallenge::read_from_bytes(resp.as_slice()).unwrap();

    let token = ProductionAuthDebugUnlockToken {
        length: {
            let req_len =
                size_of::<ProductionAuthDebugUnlockToken>() - size_of::<MailboxReqHeader>();
            (req_len / size_of::<u32>()) as u32
        },
        unique_device_identifier: challenge.unique_device_identifier,
        unlock_level,
        challenge: challenge.challenge,
        // Use the different public keys that weren't registered with the hardware
        ecc_public_key: different_ecc_pub_key.try_into().unwrap(),
        mldsa_public_key: different_mldsa_pub_key.try_into().unwrap(),
        ecc_signature: [0u32; 24], // Signature doesn't matter since keys will fail first
        mldsa_signature: [0u32; 1157], // Signature doesn't matter since keys will fail first
        ..Default::default()
    };
    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN),
        &token.as_bytes()[4..],
    );
    let token = ProductionAuthDebugUnlockToken {
        hdr: MailboxReqHeader { chksum: checksum },
        ..token
    };

    let _ = model.mailbox_execute(
        CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN.into(),
        token.as_bytes(),
    );

    model.step_until(|m| {
        let resp = m.soc_ifc().ss_dbg_manuf_service_reg_rsp().read();
        !resp.prod_dbg_unlock_in_progress()
    });

    assert!(model
        .soc_ifc()
        .ss_dbg_manuf_service_reg_rsp()
        .read()
        .prod_dbg_unlock_fail());
}

#[test]
fn test_dbg_unlock_prod_wrong_cmd() {
    let signing_ecc_key = p384::ecdsa::SigningKey::random(&mut StdRng::from_entropy());
    let verifying_ecc_key = VerifyingKey::from(&signing_ecc_key);
    let ecc_pub_key_bytes = {
        let mut pk = [0; 96];
        let ecc_key = verifying_ecc_key.to_encoded_point(false);
        pk[..48].copy_from_slice(ecc_key.x().unwrap());
        pk[48..].copy_from_slice(ecc_key.y().unwrap());
        pk
    };

    // Convert to hardware format i.e. big endian for ECC.
    let ecc_pub_key = u8_to_u32_be(&ecc_pub_key_bytes);
    let ecc_pub_key_bytes = ecc_pub_key.as_bytes();

    let (verifying_mldsa_key, _) = fips204::ml_dsa_87::try_keygen().unwrap();
    let mldsa_pub_key_bytes = verifying_mldsa_key.into_bytes();

    // Convert to hardware format i.e. little endian for MLDSA.
    let mldsa_pub_key = u8_to_u32_le(&mldsa_pub_key_bytes);
    let mldsa_pub_key_bytes = mldsa_pub_key.as_bytes();

    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let image_info = vec![
        ImageInfo::new(
            StackRange::new(ROM_STACK_ORG + ROM_STACK_SIZE, ROM_STACK_ORG),
            CodeRange::new(ROM_ORG, ROM_ORG + ROM_SIZE),
        ),
        ImageInfo::new(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(FMC_ORG, FMC_ORG + FMC_SIZE),
        ),
        ImageInfo::new(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(RUNTIME_ORG, RUNTIME_ORG + RUNTIME_SIZE),
        ),
    ];

    let unlock_level = 5u8;
    let mut prod_dbg_unlock_keypairs: Vec<(&[u8; 96], &[u8; 2592])> =
        vec![(&[0; 96], &[0; 2592]); 8];
    prod_dbg_unlock_keypairs[(unlock_level - 1) as usize] = (
        ecc_pub_key_bytes.try_into().unwrap(),
        mldsa_pub_key_bytes.try_into().unwrap(),
    );

    let init_params = InitParams {
        rom: &rom,
        security_state,
        prod_dbg_unlock_keypairs,
        debug_intent: true,
        subsystem_mode: true,
        stack_info: Some(StackInfo::new(image_info)),
        ..Default::default()
    };

    let mcu_fw = vec![1, 2, 3, 4];
    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
    let crypto = Crypto::default();
    let digest = from_hw_format(&crypto.sha384_digest(&mcu_fw).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];
    let soc_manifest = create_auth_manifest_with_metadata(metadata);
    let soc_manifest = soc_manifest.as_bytes();

    let runtime_args = RuntimeTestArgs {
        init_params: Some(init_params),
        soc_manifest: Some(soc_manifest),
        mcu_fw_image: Some(&mcu_fw),
        ..Default::default()
    };

    let mut model = run_rt_test(runtime_args);
    model
        .step_until_output_contains("[rt] RT listening for mailbox commands...\n")
        .unwrap();

    // Set the request bit
    model
        .soc_ifc()
        .ss_dbg_manuf_service_reg_req()
        .write(|w| w.prod_dbg_unlock_req(true));

    let request = ProductionAuthDebugUnlockReq {
        length: {
            let req_len = size_of::<ProductionAuthDebugUnlockReq>() - size_of::<MailboxReqHeader>();
            (req_len / size_of::<u32>()) as u32
        },
        unlock_level,
        ..Default::default()
    };
    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ),
        &request.as_bytes()[4..],
    );
    let request = ProductionAuthDebugUnlockReq {
        hdr: MailboxReqHeader { chksum: checksum },
        ..request
    };

    assert_eq!(
        model.mailbox_execute(0, request.as_bytes()),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::RUNTIME_INVALID_CHECKSUM.into()
        ))
    );
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_dbg_unlock_prod_unlock_levels_success() {
    for unlock_level in 1..=8 {
        println!("unlock_level: {}", unlock_level);
        let signing_ecc_key = p384::ecdsa::SigningKey::random(&mut StdRng::from_entropy());
        let verifying_ecc_key = VerifyingKey::from(&signing_ecc_key);
        let ecc_pub_key_bytes = {
            let mut pk = [0; 96];
            let ecc_key = verifying_ecc_key.to_encoded_point(false);
            pk[..48].copy_from_slice(ecc_key.x().unwrap());
            pk[48..].copy_from_slice(ecc_key.y().unwrap());
            pk
        };

        // Convert to hardware format i.e. big endian for ECC.
        let ecc_pub_key = u8_to_u32_be(&ecc_pub_key_bytes);
        let ecc_pub_key_bytes = ecc_pub_key.as_bytes();

        let (verifying_mldsa_key, signing_mldsa_key) = fips204::ml_dsa_87::try_keygen().unwrap();
        let mldsa_pub_key_bytes = verifying_mldsa_key.into_bytes();

        // Convert to hardware format i.e. little endian for MLDSA.
        let mldsa_pub_key = u8_to_u32_le(&mldsa_pub_key_bytes);
        let mldsa_pub_key_bytes = mldsa_pub_key.as_bytes();

        let security_state = *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production);

        let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
        let image_info = vec![
            ImageInfo::new(
                StackRange::new(ROM_STACK_ORG + ROM_STACK_SIZE, ROM_STACK_ORG),
                CodeRange::new(ROM_ORG, ROM_ORG + ROM_SIZE),
            ),
            ImageInfo::new(
                StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
                CodeRange::new(FMC_ORG, FMC_ORG + FMC_SIZE),
            ),
            ImageInfo::new(
                StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
                CodeRange::new(RUNTIME_ORG, RUNTIME_ORG + RUNTIME_SIZE),
            ),
        ];

        let mut prod_dbg_unlock_keypairs: Vec<(&[u8; 96], &[u8; 2592])> =
            vec![(&[0; 96], &[0; 2592]); 8];
        prod_dbg_unlock_keypairs[(unlock_level - 1) as usize] = (
            ecc_pub_key_bytes.try_into().unwrap(),
            mldsa_pub_key_bytes.try_into().unwrap(),
        );

        let init_params = InitParams {
            rom: &rom,
            security_state,
            prod_dbg_unlock_keypairs,
            debug_intent: true,
            subsystem_mode: true,
            stack_info: Some(StackInfo::new(image_info)),
            ..Default::default()
        };

        let mcu_fw = vec![1, 2, 3, 4];
        const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
        let mut flags = ImageMetadataFlags(0);
        flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
        let crypto = Crypto::default();
        let digest = from_hw_format(&crypto.sha384_digest(&mcu_fw).unwrap());
        let metadata = vec![AuthManifestImageMetadata {
            fw_id: 2,
            flags: flags.0,
            digest,
            ..Default::default()
        }];
        let soc_manifest = create_auth_manifest_with_metadata(metadata);
        let soc_manifest = soc_manifest.as_bytes();

        let runtime_args = RuntimeTestArgs {
            init_params: Some(init_params),
            soc_manifest: Some(soc_manifest),
            mcu_fw_image: Some(&mcu_fw),
            ..Default::default()
        };

        let mut model = run_rt_test(runtime_args);
        model
            .step_until_output_contains("[rt] RT listening for mailbox commands...\n")
            .unwrap();

        // Set the request bit
        model
            .soc_ifc()
            .ss_dbg_manuf_service_reg_req()
            .write(|w| w.prod_dbg_unlock_req(true));

        let request = ProductionAuthDebugUnlockReq {
            length: {
                let req_len =
                    size_of::<ProductionAuthDebugUnlockReq>() - size_of::<MailboxReqHeader>();
                (req_len / size_of::<u32>()) as u32
            },
            unlock_level,
            ..Default::default()
        };
        let checksum = caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ),
            &request.as_bytes()[4..],
        );
        let request = ProductionAuthDebugUnlockReq {
            hdr: MailboxReqHeader { chksum: checksum },
            ..request
        };
        let resp = model
            .mailbox_execute(
                CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ.into(),
                request.as_bytes(),
            )
            .unwrap()
            .unwrap();

        let challenge =
            ProductionAuthDebugUnlockChallenge::read_from_bytes(resp.as_slice()).unwrap();
        let reserved = [0u8; 3];

        let mut sha384 = sha2::Sha384::new();
        sha384.update(challenge.unique_device_identifier);
        sha384.update([unlock_level]);
        sha384.update(reserved);
        sha384.update(challenge.challenge);
        let sha384_digest = sha384.finalize();
        let (ecc_signature, _id) = signing_ecc_key
            .sign_prehash_recoverable(sha384_digest.as_slice())
            .unwrap();
        let ecc_signature = ecc_signature.to_bytes();
        let ecc_signature = ecc_signature.as_slice();
        // Convert to hardware format i.e. big endian for ECC.
        let ecc_signature = u8_to_u32_be(ecc_signature);

        let mut sha512 = sha2::Sha512::new();
        sha512.update(challenge.unique_device_identifier);
        sha512.update([unlock_level]);
        sha512.update(reserved);
        sha512.update(challenge.challenge);
        let sha512_digest = sha512.finalize();

        let mldsa_signature = signing_mldsa_key
            .try_sign_with_seed(&[0; 32], &sha512_digest, &[])
            .unwrap();
        // Convert to hardware format i.e. little endian for MLDSA
        let mldsa_signature = {
            let mut sig = [0; 4628];
            sig[..4627].copy_from_slice(&mldsa_signature);
            u8_to_u32_le(&sig)
        };

        let token = ProductionAuthDebugUnlockToken {
            length: {
                let req_len =
                    size_of::<ProductionAuthDebugUnlockToken>() - size_of::<MailboxReqHeader>();
                (req_len / size_of::<u32>()) as u32
            },
            unique_device_identifier: challenge.unique_device_identifier,
            unlock_level,
            challenge: challenge.challenge,
            ecc_public_key: ecc_pub_key.try_into().unwrap(),
            mldsa_public_key: mldsa_pub_key.try_into().unwrap(),
            ecc_signature: ecc_signature.try_into().unwrap(),
            mldsa_signature: mldsa_signature.try_into().unwrap(),
            ..Default::default()
        };
        let checksum = caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN),
            &token.as_bytes()[4..],
        );
        let token = ProductionAuthDebugUnlockToken {
            hdr: MailboxReqHeader { chksum: checksum },
            ..token
        };

        let _resp = model
            .mailbox_execute(
                CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN.into(),
                token.as_bytes(),
            )
            .unwrap();

        model.step_until(|m| {
            let resp = m.soc_ifc().ss_dbg_manuf_service_reg_rsp().read();
            !resp.prod_dbg_unlock_in_progress()
        });

        assert!(model
            .soc_ifc()
            .ss_dbg_manuf_service_reg_rsp()
            .read()
            .prod_dbg_unlock_success());

        let mut value = model
            .soc_ifc()
            .ss_soc_dbg_unlock_level()
            .get(0)
            .unwrap()
            .read();
        let mut soc_debug_level = 0;

        while value > 1 {
            value >>= 1;
            soc_debug_level += 1;
        }
        soc_debug_level += 1;
        assert!(soc_debug_level == unlock_level);
    }
}
