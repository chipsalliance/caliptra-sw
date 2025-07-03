// Licensed under the Apache-2.0 license

use crate::helpers;
use aes_gcm::{aead::AeadMutInPlace, Key};
use caliptra_api::mailbox::{
    CmHashAlgorithm, CmHmacReq, CmHmacResp, DeriveStableKeyReq, DeriveStableKeyResp, StableKeyType,
    CMK_SIZE_BYTES, MAX_CMB_DATA_SIZE, STABLE_KEY_INFO_SIZE_BYTES,
};
use caliptra_builder::firmware;
use caliptra_builder::firmware::{rom_tests::TEST_FMC_WITH_UART, APP_WITH_UART};
use caliptra_builder::ImageOptions;
use caliptra_common::crypto::{EncryptedCmk, UnencryptedCmk};
use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader, MailboxRespHeader};
use caliptra_common::RomBootStatus::ColdResetComplete;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams, ModelError};
use hmac::{Hmac, Mac};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha2::Sha512;
use zerocopy::{FromBytes, IntoBytes};

const DOT_KEY_TYPES: [StableKeyType; 2] = [StableKeyType::IDevId, StableKeyType::LDevId];

fn decrypt_cmk(key: &[u8], cmk: &EncryptedCmk) -> Option<UnencryptedCmk> {
    use aes_gcm::KeyInit;
    let key: &Key<aes_gcm::Aes256Gcm> = key.into();
    let mut cipher = aes_gcm::Aes256Gcm::new(key);
    let mut buffer = cmk.ciphertext.to_vec();
    match cipher.decrypt_in_place_detached(&cmk.iv.into(), &[], &mut buffer, &cmk.gcm_tag.into()) {
        Ok(_) => UnencryptedCmk::ref_from_bytes(&buffer).ok().cloned(),
        Err(_) => None,
    }
}

fn hmac512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).unwrap();
    mac.update(data);
    let result = mac.finalize();
    result.into_bytes().into()
}

#[test]
fn test_derive_stable_key() {
    for key_type in DOT_KEY_TYPES.iter() {
        let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
        let image_bundle = caliptra_builder::build_and_sign_image(
            &TEST_FMC_WITH_UART,
            &APP_WITH_UART,
            ImageOptions::default(),
        )
        .unwrap()
        .to_bytes()
        .unwrap();
        let mut hw = caliptra_hw_model::new(
            InitParams {
                rom: &rom,
                ..Default::default()
            },
            BootParams::default(),
        )
        .unwrap();

        let mut request = DeriveStableKeyReq {
            hdr: MailboxReqHeader { chksum: 0 },
            key_type: (*key_type).into(),
            info: [0u8; STABLE_KEY_INFO_SIZE_BYTES],
        };
        request.hdr.chksum = caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::DERIVE_STABLE_KEY),
            &request.as_bytes()[core::mem::size_of_val(&request.hdr.chksum)..],
        );
        let response = hw
            .mailbox_execute(CommandId::DERIVE_STABLE_KEY.into(), request.as_bytes())
            .unwrap()
            .unwrap();

        let resp = DeriveStableKeyResp::ref_from_bytes(response.as_bytes()).unwrap();

        // Verify response checksum
        assert!(caliptra_common::checksum::verify_checksum(
            resp.hdr.chksum,
            0x0,
            &resp.as_bytes()[core::mem::size_of_val(&resp.hdr.chksum)..],
        ));

        // Verify FIPS status
        assert_eq!(
            resp.hdr.fips_status,
            MailboxRespHeader::FIPS_STATUS_APPROVED
        );

        let cmk = resp.cmk.0;
        assert_ne!(cmk, [0u8; CMK_SIZE_BYTES]);

        let seed_bytes = [1u8; 32];
        let mut seeded_rng = StdRng::from_seed(seed_bytes);
        let mut data = vec![0u8; MAX_CMB_DATA_SIZE];
        seeded_rng.fill_bytes(&mut data);

        let mut cm_hmac = CmHmacReq {
            cmk: resp.cmk.clone(),
            hash_algorithm: CmHashAlgorithm::Sha512.into(),
            data_size: MAX_CMB_DATA_SIZE as u32,
            ..Default::default()
        };
        cm_hmac.data[..MAX_CMB_DATA_SIZE].copy_from_slice(&data);
        cm_hmac.hdr.chksum = caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::CM_HMAC),
            &cm_hmac.as_bytes()[core::mem::size_of_val(&cm_hmac.hdr.chksum)..],
        );

        let response = hw
            .mailbox_execute(CommandId::CM_HMAC.into(), cm_hmac.as_bytes())
            .unwrap()
            .unwrap();

        let resp = CmHmacResp::ref_from_bytes(response.as_bytes()).unwrap();
        let expected_mac = resp.mac;

        hw.upload_firmware(image_bundle.as_bytes()).unwrap();
        hw.step_until_boot_status(u32::from(ColdResetComplete), true);

        let result = hw.mailbox_execute(0x1000_0012, &[]);
        assert!(result.is_ok(), "{:?}", result);

        let aes_key = result.unwrap().unwrap();

        let cmk = EncryptedCmk::ref_from_bytes(&cmk).unwrap();
        let cmk = decrypt_cmk(&aes_key, cmk).expect("Decrypt CMK failed");

        let computed_mac = hmac512(&cmk.key_material, &data);
        assert_eq!(computed_mac, expected_mac);
    }
}

#[test]
fn test_derive_stable_key_invalid_key_type() {
    let (mut hw, _) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let mut request = DeriveStableKeyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_type: StableKeyType::Reserved.into(),
        info: [0u8; STABLE_KEY_INFO_SIZE_BYTES],
    };
    request.hdr.chksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::DERIVE_STABLE_KEY),
        &request.as_bytes()[core::mem::size_of_val(&request.hdr.chksum)..],
    );
    assert_eq!(
        hw.mailbox_execute(CommandId::DERIVE_STABLE_KEY.into(), request.as_bytes()),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::DOT_INVALID_KEY_TYPE.into()
        ))
    );
}
