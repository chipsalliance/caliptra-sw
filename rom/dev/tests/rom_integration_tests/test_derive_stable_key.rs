// Licensed under the Apache-2.0 license

use crate::helpers;
use caliptra_api::mailbox::{
    CmHashAlgorithm, CmHmacReq, CmHmacResp, DeriveStableKeyReq, DeriveStableKeyResp,
    MailboxRespHeaderVarSize, StableKeyType, CMK_SIZE_BYTES, MAX_CMB_DATA_SIZE,
    STABLE_KEY_INFO_SIZE_BYTES,
};
use caliptra_builder::ImageOptions;
use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader, MailboxRespHeader};
use caliptra_hw_model::{Fuses, HwModel};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use zerocopy::{FromBytes, IntoBytes};

const DOT_KEY_TYPES: [StableKeyType; 2] = [StableKeyType::IDevId, StableKeyType::LDevId];

#[test]
fn test_derive_stable_key() {
    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    for key_type in DOT_KEY_TYPES.iter() {
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

        assert_ne!(resp.cmk.0, [0u8; CMK_SIZE_BYTES]);

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

        // [TODO][CAP2] Get the KEKE, decrypt the CMK to obtain the HMAC key and verify the mac.
    }
}
