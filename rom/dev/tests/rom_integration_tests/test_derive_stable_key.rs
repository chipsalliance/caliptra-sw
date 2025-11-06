// Licensed under the Apache-2.0 license

use crate::helpers;
use aes_gcm::{aead::AeadMutInPlace, Key};
use caliptra_api::mailbox::{
    CmDeriveStableKeyReq, CmDeriveStableKeyResp, CmHashAlgorithm, CmHmacReq, CmHmacResp,
    CmRandomGenerateReq, CmRandomGenerateResp, CmStableKeyType, MailboxReq,
    MailboxRespHeaderVarSize, CMK_SIZE_BYTES, CM_STABLE_KEY_INFO_SIZE_BYTES, MAX_CMB_DATA_SIZE,
};
use caliptra_builder::{
    firmware::{self, rom_tests::TEST_FMC_INTERACTIVE, APP_WITH_UART},
    ImageOptions,
};
use caliptra_common::{
    crypto::{EncryptedCmk, UnencryptedCmk, UNENCRYPTED_CMK_SIZE_BYTES},
    mailbox_api::{CommandId, MailboxReqHeader, MailboxRespHeader},
    RomBootStatus::ColdResetComplete,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams, ModelError};
use hmac::{Hmac, Mac};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha2::Sha512;
use zerocopy::{transmute, FromBytes, IntoBytes};

const DOT_KEY_TYPES: [CmStableKeyType; 2] = [CmStableKeyType::IDevId, CmStableKeyType::LDevId];

fn decrypt_cmk(key: &[u8], cmk: &EncryptedCmk) -> Option<UnencryptedCmk> {
    use aes_gcm::KeyInit;
    let key: &Key<aes_gcm::Aes256Gcm> = key.into();
    let mut cipher = aes_gcm::Aes256Gcm::new(key);
    let mut buffer = cmk.ciphertext.to_vec();
    match cipher.decrypt_in_place_detached(
        cmk.iv.as_bytes().into(),
        &[],
        &mut buffer,
        cmk.gcm_tag.as_bytes().into(),
    ) {
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

fn parse_encrypted_cmk(bytes: &[u8]) -> EncryptedCmk {
    assert!(
        bytes.len() >= size_of::<EncryptedCmk>(),
        "Byte slice too small"
    );

    let domain = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let domain_metadata = bytes[4..20].try_into().unwrap();
    let iv: [u8; 12] = bytes[20..32].try_into().unwrap();
    let ciphertext = bytes[32..(32 + UNENCRYPTED_CMK_SIZE_BYTES)]
        .try_into()
        .unwrap();
    let gcm_tag_start = 32 + UNENCRYPTED_CMK_SIZE_BYTES;
    let gcm_tag: [u8; 16] = bytes[gcm_tag_start..(gcm_tag_start + 16)]
        .try_into()
        .unwrap();

    EncryptedCmk {
        domain,
        domain_metadata,
        iv: transmute!(iv),
        ciphertext,
        gcm_tag: transmute!(gcm_tag),
    }
}

#[test]
fn test_derive_stable_key() {
    for key_type in DOT_KEY_TYPES.iter() {
        let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
        let image_bundle = caliptra_builder::build_and_sign_image(
            &TEST_FMC_INTERACTIVE,
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

        let mut request = CmDeriveStableKeyReq {
            hdr: MailboxReqHeader { chksum: 0 },
            key_type: (*key_type).into(),
            info: [0u8; CM_STABLE_KEY_INFO_SIZE_BYTES],
        };
        request.hdr.chksum = caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::CM_DERIVE_STABLE_KEY),
            &request.as_bytes()[core::mem::size_of_val(&request.hdr.chksum)..],
        );
        let response = hw
            .mailbox_execute(CommandId::CM_DERIVE_STABLE_KEY.into(), request.as_bytes())
            .unwrap()
            .unwrap();

        let resp = CmDeriveStableKeyResp::ref_from_bytes(response.as_bytes()).unwrap();

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

        let cmk = parse_encrypted_cmk(&cmk);
        let cmk = decrypt_cmk(&aes_key, &cmk).unwrap();

        let computed_mac = hmac512(&cmk.key_material, &data);
        assert_eq!(computed_mac, expected_mac);
    }
}

#[test]
fn test_derive_stable_key_invalid_key_type() {
    let (mut hw, _) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let mut request = CmDeriveStableKeyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_type: CmStableKeyType::Reserved.into(),
        info: [0u8; CM_STABLE_KEY_INFO_SIZE_BYTES],
    };
    request.hdr.chksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::CM_DERIVE_STABLE_KEY),
        &request.as_bytes()[core::mem::size_of_val(&request.hdr.chksum)..],
    );
    assert_eq!(
        hw.mailbox_execute(CommandId::CM_DERIVE_STABLE_KEY.into(), request.as_bytes()),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::DOT_INVALID_KEY_TYPE.into()
        ))
    );
}

#[test]
fn test_random_generate() {
    let (mut model, _) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // check too large of an input
    let mut cm_random_generate = MailboxReq::CmRandomGenerate(CmRandomGenerateReq {
        hdr: MailboxReqHeader::default(),
        size: u32::MAX,
    });
    cm_random_generate.populate_chksum().unwrap();

    model
        .mailbox_execute(
            u32::from(CommandId::CM_RANDOM_GENERATE),
            cm_random_generate.as_bytes().unwrap(),
        )
        .expect_err("Should have been an error");

    // 0 bytes
    let mut cm_random_generate = MailboxReq::CmRandomGenerate(CmRandomGenerateReq {
        hdr: MailboxReqHeader::default(),
        size: 0,
    });
    cm_random_generate.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_RANDOM_GENERATE),
            cm_random_generate.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let mut resp = CmRandomGenerateResp::default();
    const VAR_HEADER_SIZE: usize = size_of::<MailboxRespHeaderVarSize>();
    resp.hdr = MailboxRespHeaderVarSize::read_from_bytes(&resp_bytes[..VAR_HEADER_SIZE]).unwrap();
    assert_eq!(resp.hdr.data_len, 0);
    assert!(resp_bytes[VAR_HEADER_SIZE..].iter().all(|&x| x == 0));

    // 1 byte
    let mut cm_random_generate = MailboxReq::CmRandomGenerate(CmRandomGenerateReq {
        hdr: MailboxReqHeader::default(),
        size: 1,
    });
    cm_random_generate.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_RANDOM_GENERATE),
            cm_random_generate.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let mut resp = CmRandomGenerateResp {
        hdr: MailboxRespHeaderVarSize::read_from_bytes(&resp_bytes[..VAR_HEADER_SIZE]).unwrap(),
        ..Default::default()
    };
    let len = resp.hdr.data_len as usize;
    assert_eq!(len, 1);
    resp.data[..len].copy_from_slice(&resp_bytes[VAR_HEADER_SIZE..VAR_HEADER_SIZE + len]);
    // We can't check if it is non-zero because it will randomly be 0 sometimes.

    for req_len in [47usize, 48, 1044] {
        let mut cm_random_generate = MailboxReq::CmRandomGenerate(CmRandomGenerateReq {
            hdr: MailboxReqHeader::default(),
            size: req_len as u32,
        });
        cm_random_generate.populate_chksum().unwrap();

        let resp_bytes = model
            .mailbox_execute(
                u32::from(CommandId::CM_RANDOM_GENERATE),
                cm_random_generate.as_bytes().unwrap(),
            )
            .unwrap()
            .expect("We should have received a response");

        let mut resp = CmRandomGenerateResp {
            hdr: MailboxRespHeaderVarSize::read_from_bytes(&resp_bytes[..VAR_HEADER_SIZE]).unwrap(),
            ..Default::default()
        };
        let len = resp.hdr.data_len as usize;
        assert_eq!(len, req_len);
        resp.data[..len].copy_from_slice(&resp_bytes[VAR_HEADER_SIZE..VAR_HEADER_SIZE + len]);
        assert!(
            resp.data[..len]
                .iter()
                .copied()
                .reduce(|a, b| (a | b))
                .unwrap()
                != 0
        );
    }
}
