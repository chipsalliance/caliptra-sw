// Licensed under the Apache-2.0 license

use crate::helpers;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use caliptra_api::mailbox::{
    CmHashAlgorithm, CmHmacReq, CmHmacResp, DeriveDotKeyReq, DeriveDotKeyResp, DotKeyType,
    MailboxRespHeaderVarSize, CMK_SIZE_BYTES, DOT_INFO_SIZE_BYTES, MAX_CMB_DATA_SIZE,
};
use caliptra_builder::firmware;
use caliptra_builder::firmware::rom_tests::TEST_FMC_WITH_UART;
use caliptra_builder::firmware::APP_WITH_UART;
use caliptra_builder::ImageOptions;
use caliptra_common::crypto::EncryptedCmk;
use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader, MailboxRespHeader};
use caliptra_common::RomBootStatus::ColdResetComplete;
use caliptra_error::CaliptraError;
use caliptra_hw_model::BootParams;
use caliptra_hw_model::InitParams;
use caliptra_hw_model::{Fuses, HwModel, ModelError};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use zerocopy::{FromBytes, IntoBytes};

const DOT_KEY_TYPES: [DotKeyType; 2] = [DotKeyType::IDevId, DotKeyType::LDevId];

#[test]
fn test_derive_dot_key() {
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

        let mut request = DeriveDotKeyReq {
            hdr: MailboxReqHeader { chksum: 0 },
            key_type: (*key_type).into(),
            info: [0u8; DOT_INFO_SIZE_BYTES],
        };
        request.hdr.chksum = caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::DERIVE_DOT_KEY),
            &request.as_bytes()[core::mem::size_of_val(&request.hdr.chksum)..],
        );
        let response = hw
            .mailbox_execute(CommandId::DERIVE_DOT_KEY.into(), request.as_bytes())
            .unwrap()
            .unwrap();

        let resp = DeriveDotKeyResp::ref_from_bytes(response.as_bytes()).unwrap();

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

        const HMAC_HEADER_SIZE: usize = size_of::<MailboxRespHeaderVarSize>();
        let _resp = CmHmacResp {
            hdr: MailboxRespHeaderVarSize::read_from_bytes(&response[..HMAC_HEADER_SIZE]).unwrap(),
            ..Default::default()
        };

        hw.upload_firmware(&image_bundle.as_bytes()).unwrap();
        hw.step_until_boot_status(u32::from(ColdResetComplete), true);

        // [TODO][CAP2] Get the KEKE, decrypt the CMK to obtain the HMAC key and verify the mac.
        let result = hw.mailbox_execute(0x1000_0012, &[]);
        assert!(result.is_ok(), "{:?}", result);

        let key = {
            let key_bytes = result.unwrap().unwrap();
            let mut key0 = [0u8; 32];
            let mut key1 = [0u8; 32];
            key0.copy_from_slice(&key_bytes[..32]);
            key1.copy_from_slice(&key_bytes[32..]);
            (key0, key1)
        };

        // let iv = [0u8; 16];
        // let mut out_block = [0u8; 1024];
        let uncmk = EncryptedCmk::ref_from_bytes(&cmk).unwrap();
        let decryptor = cbc::Decryptor::<aes::Aes256>::new(&key.0.into(), &uncmk.iv.into());
        // let result = decryptor.decrypt_padded_b2b_mut::<Pkcs7>(&cmk, &mut out_block);
        // assert!(result.is_ok(), "{:?}", result);
        // println!("{:x?}", out_block);
    }
}

#[test]
fn test_derive_dot_key_invalid_key_type() {
    let (mut hw, _) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let mut request = DeriveDotKeyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_type: DotKeyType::Reserved.into(),
        info: [0u8; DOT_INFO_SIZE_BYTES],
    };
    request.hdr.chksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::DERIVE_DOT_KEY),
        &request.as_bytes()[core::mem::size_of_val(&request.hdr.chksum)..],
    );
    assert_eq!(
        hw.mailbox_execute(CommandId::DERIVE_DOT_KEY.into(), request.as_bytes()),
        Err(ModelError::MailboxCmdFailed(
            CaliptraError::DOT_INVALID_KEY_TYPE.into()
        ))
    );
}
