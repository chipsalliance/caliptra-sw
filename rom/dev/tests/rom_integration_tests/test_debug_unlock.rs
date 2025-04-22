// Licensed under the Apache-2.0 license

use std::mem::size_of;

use caliptra_api::mailbox::{
    CommandId, MailboxReqHeader, ManufDebugUnlockTokenReq, ProductionAuthDebugUnlockChallenge,
    ProductionAuthDebugUnlockReq, ProductionAuthDebugUnlockToken,
};
use caliptra_api::SocManager;
use caliptra_builder::firmware::ROM_WITH_UART;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    DbgManufServiceRegReq, DeviceLifecycle, HwModel, ModelError, SecurityState,
};
use fips204::traits::{SerDes, Signer};
use p384::ecdsa::VerifyingKey;
use rand::{rngs::StdRng, SeedableRng};
use sha2::Digest;
use zerocopy::{FromBytes, IntoBytes};

//TODO: https://github.com/chipsalliance/caliptra-sw/issues/2070
#[test]
#[cfg(not(feature = "fpga_realtime"))]
fn test_dbg_unlock_manuf_req_in_passive_mode() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Manufacturing);

    let dbg_manuf_service = *DbgManufServiceRegReq::default().set_manuf_dbg_unlock_req(true);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            dbg_manuf_service,
            debug_intent: true,
            subsystem_mode: false,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    let token = ManufDebugUnlockTokenReq {
        token: caliptra_hw_model_types::DEFAULT_MANUF_DEBUG_UNLOCK_TOKEN
            .as_bytes()
            .try_into()
            .unwrap(),
        ..Default::default()
    };
    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::MANUF_DEBUG_UNLOCK_REQ_TOKEN),
        &token.as_bytes()[4..],
    );
    let token = ManufDebugUnlockTokenReq {
        hdr: MailboxReqHeader { chksum: checksum },
        ..token
    };
    assert_eq!(
        hw.mailbox_execute(
            CommandId::MANUF_DEBUG_UNLOCK_REQ_TOKEN.into(),
            token.as_bytes(),
        ),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::ROM_SS_DBG_UNLOCK_REQ_IN_PASSIVE_MODE.into()
        ))
    );
}

//TODO: https://github.com/chipsalliance/caliptra-sw/issues/2070
#[test]
#[cfg(not(feature = "fpga_realtime"))]
fn test_dbg_unlock_manuf_success() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Manufacturing);

    let dbg_manuf_service = *DbgManufServiceRegReq::default().set_manuf_dbg_unlock_req(true);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            dbg_manuf_service,
            debug_intent: true,
            subsystem_mode: true,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    let token_req = ManufDebugUnlockTokenReq {
        token: caliptra_hw_model_types::DEFAULT_MANUF_DEBUG_UNLOCK_TOKEN
            .as_bytes()
            .try_into()
            .unwrap(),
        ..Default::default()
    };
    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::MANUF_DEBUG_UNLOCK_REQ_TOKEN),
        &token_req.as_bytes()[4..],
    );
    let token = ManufDebugUnlockTokenReq {
        hdr: MailboxReqHeader { chksum: checksum },
        ..token_req
    };
    let _ = hw
        .mailbox_execute(
            CommandId::MANUF_DEBUG_UNLOCK_REQ_TOKEN.into(),
            token.as_bytes(),
        )
        .unwrap()
        .unwrap();

    hw.step_until(|m| {
        let resp = m.soc_ifc().ss_dbg_manuf_service_reg_rsp().read();
        !resp.manuf_dbg_unlock_in_progress()
    });

    assert!(hw
        .soc_ifc()
        .ss_dbg_manuf_service_reg_rsp()
        .read()
        .manuf_dbg_unlock_success());
}

//TODO: https://github.com/chipsalliance/caliptra-sw/issues/2070
#[test]
#[cfg(not(feature = "fpga_realtime"))]
fn test_dbg_unlock_manuf_wrong_cmd() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Manufacturing);

    let dbg_manuf_service = *DbgManufServiceRegReq::default().set_manuf_dbg_unlock_req(true);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            dbg_manuf_service,
            debug_intent: true,
            subsystem_mode: true,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    let token = ManufDebugUnlockTokenReq {
        token: caliptra_hw_model_types::DEFAULT_MANUF_DEBUG_UNLOCK_TOKEN
            .as_bytes()
            .try_into()
            .unwrap(),
        ..Default::default()
    };
    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::MANUF_DEBUG_UNLOCK_REQ_TOKEN),
        &token.as_bytes()[4..],
    );
    let token = ManufDebugUnlockTokenReq {
        hdr: MailboxReqHeader { chksum: checksum },
        ..token
    };
    assert_eq!(
        hw.mailbox_execute(0, token.as_bytes(),),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::ROM_SS_DBG_UNLOCK_MANUF_INVALID_MBOX_CMD.into()
        ))
    );

    hw.step_until(|m| {
        let resp = m.soc_ifc().ss_dbg_manuf_service_reg_rsp().read();
        !resp.manuf_dbg_unlock_in_progress()
    });
}

//TODO: https://github.com/chipsalliance/caliptra-sw/issues/2070
#[test]
#[cfg(not(feature = "fpga_realtime"))]
fn test_dbg_unlock_manuf_invalid_token() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Manufacturing);

    let dbg_manuf_service = *DbgManufServiceRegReq::default().set_manuf_dbg_unlock_req(true);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            dbg_manuf_service,
            debug_intent: true,
            subsystem_mode: true,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    // Defaults to 0 token
    let token = ManufDebugUnlockTokenReq {
        ..Default::default()
    };
    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::MANUF_DEBUG_UNLOCK_REQ_TOKEN),
        &token.as_bytes()[4..],
    );
    let token = ManufDebugUnlockTokenReq {
        hdr: MailboxReqHeader { chksum: checksum },
        ..token
    };
    let _ = hw
        .mailbox_execute(
            CommandId::MANUF_DEBUG_UNLOCK_REQ_TOKEN.into(),
            token.as_bytes(),
        )
        .unwrap()
        .unwrap();

    hw.step_until(|m| {
        let resp = m.soc_ifc().ss_dbg_manuf_service_reg_rsp().read();
        !resp.manuf_dbg_unlock_in_progress()
    });
    assert!(hw
        .soc_ifc()
        .ss_dbg_manuf_service_reg_rsp()
        .read()
        .manuf_dbg_unlock_fail());
}

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

// [TODO][CAP2] test_dbg_unlock_manuf_req_in_passive_mode

//TODO: https://github.com/chipsalliance/caliptra-sw/issues/2070
#[test]
#[cfg(not(feature = "fpga_realtime"))]
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

    // Convert to hardware format i.e. little endian.
    let ecc_pub_key = u8_to_u32_be(&ecc_pub_key_bytes);
    let ecc_pub_key_bytes = ecc_pub_key.as_bytes();

    let (verifying_mldsa_key, signing_mldsa_key) = fips204::ml_dsa_87::try_keygen().unwrap();
    let mldsa_pub_key_bytes = verifying_mldsa_key.into_bytes();

    let mldsa_pub_key = u8_to_u32_be(&mldsa_pub_key_bytes);
    let mldsa_pub_key_bytes = mldsa_pub_key.as_bytes();

    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let dbg_manuf_service = *DbgManufServiceRegReq::default().set_prod_dbg_unlock_req(true);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    let unlock_level = 5u8;
    let mut prod_dbg_unlock_keypairs: Vec<(&[u8; 96], &[u8; 2592])> =
        vec![(&[0; 96], &[0; 2592]); 8];
    prod_dbg_unlock_keypairs[(unlock_level - 1) as usize] = (
        ecc_pub_key_bytes.try_into().unwrap(),
        mldsa_pub_key_bytes.try_into().unwrap(),
    );

    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            dbg_manuf_service,
            prod_dbg_unlock_keypairs,
            debug_intent: true,
            subsystem_mode: true,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    // [TODO][CAP2] With wrong len mbox err 0 gets returned which is not right
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
    let resp = hw
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
    // Convert to hardware format i.e. little endian.
    let ecc_signature = u8_to_u32_be(ecc_signature);

    let mut sha512 = sha2::Sha512::new();
    sha512.update(challenge.unique_device_identifier);
    sha512.update([unlock_level]);
    sha512.update(reserved);
    sha512.update(challenge.challenge);
    let mut sha512_digest = sha512.finalize();
    let msg = {
        let msg: &mut [u8] = sha512_digest.as_mut_slice();
        msg
    };

    let mldsa_signature = signing_mldsa_key
        .try_sign_with_seed(&[0; 32], msg, &[])
        .unwrap();
    // Convert to hardware format i.e. little endian.
    let mldsa_signature = {
        let mut sig = [0; 4628];
        sig[..4627].copy_from_slice(&mldsa_signature);
        u8_to_u32_be(&sig)
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

    let _resp = hw
        .mailbox_execute(
            CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN.into(),
            token.as_bytes(),
        )
        .unwrap();

    hw.step_until(|m| {
        let resp = m.soc_ifc().ss_dbg_manuf_service_reg_rsp().read();
        !resp.prod_dbg_unlock_in_progress()
    });

    assert!(hw
        .soc_ifc()
        .ss_dbg_manuf_service_reg_rsp()
        .read()
        .prod_dbg_unlock_success());

    let mut value = hw
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

//TODO: https://github.com/chipsalliance/caliptra-sw/issues/2070
#[test]
#[cfg(not(feature = "fpga_realtime"))]
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

    // Convert to hardware format i.e. little endian.
    let ecc_pub_key = u8_to_u32_be(&ecc_pub_key_bytes);
    let ecc_pub_key_bytes = ecc_pub_key.as_bytes();

    let (verifying_mldsa_key, _signing_mldsa_key) = fips204::ml_dsa_87::try_keygen().unwrap();
    let mldsa_pub_key_bytes = verifying_mldsa_key.into_bytes();
    let mldsa_pub_key = u8_to_u32_be(&mldsa_pub_key_bytes);
    let mldsa_pub_key_bytes = mldsa_pub_key.as_bytes();

    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let dbg_manuf_service = *DbgManufServiceRegReq::default().set_prod_dbg_unlock_req(true);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            dbg_manuf_service,
            prod_dbg_unlock_keypairs: vec![(
                ecc_pub_key_bytes.try_into().unwrap(),
                &mldsa_pub_key_bytes.try_into().unwrap(),
            )],
            debug_intent: true,
            subsystem_mode: true,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    let unlock_level = 2u8;

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
    let _ = hw.mailbox_execute(
        CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ.into(),
        request.as_bytes(),
    );

    hw.step_until(|m| {
        let resp = m.soc_ifc().ss_dbg_manuf_service_reg_rsp().read();
        !resp.prod_dbg_unlock_in_progress()
    });

    assert!(hw
        .soc_ifc()
        .ss_dbg_manuf_service_reg_rsp()
        .read()
        .prod_dbg_unlock_fail());
}

//TODO: https://github.com/chipsalliance/caliptra-sw/issues/2070
#[test]
#[cfg(not(feature = "fpga_realtime"))]
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
    // Convert to hardware format i.e. little endian.
    let ecc_pub_key = u8_to_u32_be(&ecc_pub_key_bytes);
    let ecc_pub_key_bytes = ecc_pub_key.as_bytes();

    let (verifying_mldsa_key, _signing_mldsa_key) = fips204::ml_dsa_87::try_keygen().unwrap();
    let mldsa_pub_key_bytes = verifying_mldsa_key.into_bytes();
    let mldsa_pub_key = u8_to_u32_be(&mldsa_pub_key_bytes);
    let mldsa_pub_key_bytes = mldsa_pub_key.as_bytes();

    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let dbg_manuf_service = *DbgManufServiceRegReq::default().set_prod_dbg_unlock_req(true);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            dbg_manuf_service,
            prod_dbg_unlock_keypairs: vec![(
                ecc_pub_key_bytes.try_into().unwrap(),
                mldsa_pub_key_bytes.try_into().unwrap(),
            )],
            subsystem_mode: true,
            debug_intent: true,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    let unlock_level = 3u8;

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
    let resp = hw
        .mailbox_execute(
            CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ.into(),
            request.as_bytes(),
        )
        .unwrap()
        .unwrap();

    let challenge = ProductionAuthDebugUnlockChallenge::read_from_bytes(resp.as_slice()).unwrap();

    // Create an invalid token by using a different challenge than what was received
    let invalid_challenge = [0u8; 48];

    let token = ProductionAuthDebugUnlockToken {
        length: {
            let req_len =
                size_of::<ProductionAuthDebugUnlockToken>() - size_of::<MailboxReqHeader>();
            (req_len / size_of::<u32>()) as u32
        },
        unique_device_identifier: challenge.unique_device_identifier,
        unlock_level,
        challenge: invalid_challenge, // Use invalid challenge
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

    let _ = hw.mailbox_execute(
        CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN.into(),
        token.as_bytes(),
    );

    hw.step_until(|m| {
        let resp = m.soc_ifc().ss_dbg_manuf_service_reg_rsp().read();
        !resp.prod_dbg_unlock_in_progress()
    });

    assert!(hw
        .soc_ifc()
        .ss_dbg_manuf_service_reg_rsp()
        .read()
        .prod_dbg_unlock_fail());
}

//TODO: https://github.com/chipsalliance/caliptra-sw/issues/2070
#[test]
#[cfg(not(feature = "fpga_realtime"))]
fn test_dbg_unlock_prod_invalid_signature() {
    let signing_ecc_key = p384::ecdsa::SigningKey::random(&mut StdRng::from_entropy());
    let verifying_ecc_key = VerifyingKey::from(&signing_ecc_key);
    let ecc_pub_key_bytes = {
        let mut pk = [0; 96];
        let ecc_key = verifying_ecc_key.to_encoded_point(false);
        pk[..48].copy_from_slice(ecc_key.x().unwrap());
        pk[48..].copy_from_slice(ecc_key.y().unwrap());
        pk
    };
    // Convert to hardware format i.e. little endian.
    let ecc_pub_key = u8_to_u32_be(&ecc_pub_key_bytes);
    let ecc_pub_key_bytes = ecc_pub_key.as_bytes();

    let (verifying_mldsa_key, signing_mldsa_key) = fips204::ml_dsa_87::try_keygen().unwrap();
    let mldsa_pub_key_bytes = verifying_mldsa_key.into_bytes();

    // Convert to hardware format i.e. little endian.
    let mldsa_pub_key = u8_to_u32_be(&mldsa_pub_key_bytes);
    let mldsa_pub_key_bytes = mldsa_pub_key.as_bytes();

    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let dbg_manuf_service = *DbgManufServiceRegReq::default().set_prod_dbg_unlock_req(true);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            dbg_manuf_service,
            prod_dbg_unlock_keypairs: vec![(
                ecc_pub_key_bytes.try_into().unwrap(),
                mldsa_pub_key_bytes.try_into().unwrap(),
            )],
            debug_intent: true,
            subsystem_mode: true,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    let unlock_level = 4u8;

    // [TODO][CAP2] With wrong len mbox err 0 gets returned which is not right
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
    let resp = hw
        .mailbox_execute(
            CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ.into(),
            request.as_bytes(),
        )
        .unwrap()
        .unwrap();

    let challenge = ProductionAuthDebugUnlockChallenge::read_from_bytes(resp.as_slice()).unwrap();

    let mut sha512 = sha2::Sha512::new();
    sha512.update(challenge.challenge);
    sha512.update(challenge.unique_device_identifier);
    let mut sha512_digest = sha512.finalize();
    let msg = {
        let msg: &mut [u8] = sha512_digest.as_mut_slice();
        msg
    };

    let mldsa_signature = signing_mldsa_key
        .try_sign_with_seed(&[0; 32], msg, &[])
        .unwrap();
    let mldsa_signature = {
        let mut sig = [0; 4628];
        sig[..4627].copy_from_slice(&mldsa_signature);
        u8_to_u32_be(&sig)
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
        ecc_signature: [0xab; 24], // Invalid signature
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

    let _ = hw.mailbox_execute(
        CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN.into(),
        token.as_bytes(),
    );

    hw.step_until(|m| {
        let resp = m.soc_ifc().ss_dbg_manuf_service_reg_rsp().read();
        !resp.prod_dbg_unlock_in_progress()
    });

    assert!(hw
        .soc_ifc()
        .ss_dbg_manuf_service_reg_rsp()
        .read()
        .prod_dbg_unlock_fail());
}

//TODO: https://github.com/chipsalliance/caliptra-sw/issues/2070
#[test]
#[cfg(not(feature = "fpga_realtime"))]
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
    // Convert to hardware format i.e. little endian.
    let ecc_pub_key = u8_to_u32_be(&ecc_pub_key_bytes);
    let ecc_pub_key_bytes = ecc_pub_key.as_bytes();

    let (verifying_mldsa_key, _signing_mldsa_key) = fips204::ml_dsa_87::try_keygen().unwrap();
    let mldsa_pub_key_bytes = verifying_mldsa_key.into_bytes();
    // Convert to hardware format i.e. little endian.
    let mldsa_pub_key = u8_to_u32_be(&mldsa_pub_key_bytes);
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

    let dbg_manuf_service = *DbgManufServiceRegReq::default().set_prod_dbg_unlock_req(true);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            dbg_manuf_service,
            prod_dbg_unlock_keypairs: vec![(
                ecc_pub_key_bytes.try_into().unwrap(),
                mldsa_pub_key_bytes.try_into().unwrap(),
            )],
            debug_intent: true,
            subsystem_mode: true,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    let unlock_level = 5u8;

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
    let resp = hw
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

    let _ = hw.mailbox_execute(
        CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN.into(),
        token.as_bytes(),
    );

    hw.step_until(|m| {
        let resp = m.soc_ifc().ss_dbg_manuf_service_reg_rsp().read();
        !resp.prod_dbg_unlock_in_progress()
    });

    assert!(hw
        .soc_ifc()
        .ss_dbg_manuf_service_reg_rsp()
        .read()
        .prod_dbg_unlock_fail());
}

//TODO: https://github.com/chipsalliance/caliptra-sw/issues/2070
#[test]
#[cfg(not(feature = "fpga_realtime"))]
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
    // Convert to hardware format i.e. little endian.
    let ecc_pub_key = u8_to_u32_be(&ecc_pub_key_bytes);
    let ecc_pub_key_bytes = ecc_pub_key.as_bytes();

    let (verifying_mldsa_key, _signing_mldsa_key) = fips204::ml_dsa_87::try_keygen().unwrap();
    let mldsa_pub_key_bytes = verifying_mldsa_key.into_bytes();
    // Convert to hardware format i.e. little endian.
    let mldsa_pub_key = u8_to_u32_be(&mldsa_pub_key_bytes);
    let mldsa_pub_key_bytes = mldsa_pub_key.as_bytes();

    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let dbg_manuf_service = *DbgManufServiceRegReq::default().set_prod_dbg_unlock_req(true);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            dbg_manuf_service,
            prod_dbg_unlock_keypairs: vec![(
                ecc_pub_key_bytes.try_into().unwrap(),
                mldsa_pub_key_bytes.try_into().unwrap(),
            )],
            debug_intent: true,
            subsystem_mode: true,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    let unlock_level = 6u8;

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
        hw.mailbox_execute(0, request.as_bytes()),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_REQ_MBOX_CMD.into()
        ))
    );
}

#[test]
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
        let ecc_pub_key = u8_to_u32_be(&ecc_pub_key_bytes);
        let ecc_pub_key_bytes = ecc_pub_key.as_bytes();

        let (verifying_mldsa_key, signing_mldsa_key) = fips204::ml_dsa_87::try_keygen().unwrap();
        let mldsa_pub_key_bytes = verifying_mldsa_key.into_bytes();
        let mldsa_pub_key = u8_to_u32_be(&mldsa_pub_key_bytes);
        let mldsa_pub_key_bytes = mldsa_pub_key.as_bytes();

        let security_state = *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production);

        let dbg_manuf_service = *DbgManufServiceRegReq::default().set_prod_dbg_unlock_req(true);

        let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

        let mut prod_dbg_unlock_keypairs = Vec::new();
        for _ in 0..8 {
            prod_dbg_unlock_keypairs.push((
                ecc_pub_key_bytes.try_into().unwrap(),
                mldsa_pub_key_bytes.try_into().unwrap(),
            ));
        }

        let mut hw = caliptra_hw_model::new(
            caliptra_hw_model::InitParams {
                rom: &rom,
                security_state,
                dbg_manuf_service,
                prod_dbg_unlock_keypairs,
                debug_intent: true,
                subsystem_mode: true,
                ..Default::default()
            },
            caliptra_hw_model::BootParams::default(),
        )
        .unwrap();

        // [TODO][CAP2] With wrong len mbox err 0 gets returned which is not right
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
        let resp = hw
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
        let ecc_signature = u8_to_u32_be(ecc_signature);

        let mut sha512 = sha2::Sha512::new();
        sha512.update(challenge.unique_device_identifier);
        sha512.update([unlock_level]);
        sha512.update(reserved);
        sha512.update(challenge.challenge);
        let mut sha512_digest = sha512.finalize();
        let msg = {
            let msg: &mut [u8] = sha512_digest.as_mut_slice();
            msg
        };

        let mldsa_signature = signing_mldsa_key
            .try_sign_with_seed(&[0; 32], msg, &[])
            .unwrap();
        let mldsa_signature = {
            let mut sig = [0; 4628];
            sig[..4627].copy_from_slice(&mldsa_signature);
            u8_to_u32_be(&sig)
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

        let _resp = hw
            .mailbox_execute(
                CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN.into(),
                token.as_bytes(),
            )
            .unwrap();

        hw.step_until(|m| {
            let resp = m.soc_ifc().ss_dbg_manuf_service_reg_rsp().read();
            !resp.prod_dbg_unlock_in_progress()
        });
        assert!(hw
            .soc_ifc()
            .ss_dbg_manuf_service_reg_rsp()
            .read()
            .prod_dbg_unlock_success());
    }
}

#[test]
fn test_dbg_unlock_prod_unlock_levels_failure() {
    for unlock_level in [0, 9, 16] {
        let signing_ecc_key = p384::ecdsa::SigningKey::random(&mut StdRng::from_entropy());
        let verifying_ecc_key = VerifyingKey::from(&signing_ecc_key);
        let ecc_pub_key_bytes = {
            let mut pk = [0; 96];
            let ecc_key = verifying_ecc_key.to_encoded_point(false);
            pk[..48].copy_from_slice(ecc_key.x().unwrap());
            pk[48..].copy_from_slice(ecc_key.y().unwrap());
            pk
        };
        let ecc_pub_key = u8_to_u32_be(&ecc_pub_key_bytes);
        let ecc_pub_key_bytes = ecc_pub_key.as_bytes();

        let (verifying_mldsa_key, signing_mldsa_key) = fips204::ml_dsa_87::try_keygen().unwrap();
        let mldsa_pub_key_bytes = verifying_mldsa_key.into_bytes();
        let mldsa_pub_key = u8_to_u32_be(&mldsa_pub_key_bytes);
        let mldsa_pub_key_bytes = mldsa_pub_key.as_bytes();

        let security_state = *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production);

        let dbg_manuf_service = *DbgManufServiceRegReq::default().set_prod_dbg_unlock_req(true);

        let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

        let mut hw = caliptra_hw_model::new(
            caliptra_hw_model::InitParams {
                rom: &rom,
                security_state,
                dbg_manuf_service,
                prod_dbg_unlock_keypairs: vec![(
                    ecc_pub_key_bytes.try_into().unwrap(),
                    mldsa_pub_key_bytes.try_into().unwrap(),
                )],
                debug_intent: true,
                subsystem_mode: true,
                ..Default::default()
            },
            caliptra_hw_model::BootParams::default(),
        )
        .unwrap();

        // [TODO][CAP2] With wrong len mbox err 0 gets returned which is not right
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
        let resp = hw
            .mailbox_execute(
                CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ.into(),
                request.as_bytes(),
            )
            .unwrap()
            .unwrap();

        if unlock_level > 8 {
            assert_eq!(resp.as_slice(), [0, 0, 0, 0, 0, 0, 0, 0]);
            return;
        }

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
        let ecc_signature = u8_to_u32_be(ecc_signature);

        let mut sha512 = sha2::Sha512::new();
        sha512.update(challenge.unique_device_identifier);
        sha512.update([unlock_level]);
        sha512.update(reserved);
        sha512.update(challenge.challenge);
        let mut sha512_digest = sha512.finalize();
        let msg = {
            let msg: &mut [u8] = sha512_digest.as_mut_slice();
            msg
        };

        let mldsa_signature = signing_mldsa_key
            .try_sign_with_seed(&[0; 32], msg, &[])
            .unwrap();
        let mldsa_signature = {
            let mut sig = [0; 4628];
            sig[..4627].copy_from_slice(&mldsa_signature);
            u8_to_u32_be(&sig)
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

        let _ = hw
            .mailbox_execute(
                CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN.into(),
                token.as_bytes(),
            )
            .unwrap();

        hw.step_until(|m| {
            let resp = m.soc_ifc().ss_dbg_manuf_service_reg_rsp().read();
            !resp.prod_dbg_unlock_in_progress()
        });
        assert!(hw
            .soc_ifc()
            .ss_dbg_manuf_service_reg_rsp()
            .read()
            .prod_dbg_unlock_fail());
    }
}
