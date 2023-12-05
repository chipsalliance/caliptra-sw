// Licensed under the Apache-2.0 license

use crate::common::{get_fmc_alias_cert, run_rt_test};
use caliptra_common::mailbox_api::{
    CommandId, ExtendPcrReq, IncrementPcrResetCounterReq, MailboxReq, MailboxReqHeader,
    QuotePcrsReq, QuotePcrsResp,
};
use caliptra_drivers::PcrId;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel, ModelError};
use openssl::{
    bn::BigNum,
    ecdsa::EcdsaSig,
    hash::{Hasher, MessageDigest},
    x509::X509,
};
use zerocopy::{AsBytes, FromBytes};

#[test]
fn test_pcr_quote() {
    let mut model = run_rt_test(None, None, None);

    const RESET_PCR: u32 = 7;

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    let mut cmd = MailboxReq::IncrementPcrResetCounter(IncrementPcrResetCounterReq {
        hdr: MailboxReqHeader { chksum: 0 },
        index: RESET_PCR,
    });
    cmd.populate_chksum().unwrap();

    let _ = model
        .mailbox_execute(
            u32::from(CommandId::INCREMENT_PCR_RESET_COUNTER),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();

    let mut cmd = MailboxReq::QuotePcrs(QuotePcrsReq {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce: [0xf5; 32],
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(u32::from(CommandId::QUOTE_PCRS), cmd.as_bytes().unwrap())
        .unwrap()
        .unwrap();

    let resp = QuotePcrsResp::read_from(resp.as_slice()).unwrap();

    // Compute the digest and compare to mailbox result
    let mut h = Hasher::new(MessageDigest::sha384()).unwrap();
    resp.pcrs.iter().for_each(|x| h.update(x).unwrap());
    h.update(&resp.nonce).unwrap();
    let res = h.finish().unwrap();
    let digest: [u8; 48] = res.as_bytes().try_into().unwrap();
    assert_eq!(resp.digest, digest);

    let pcr7_reset_counter: u32 = resp.reset_ctrs[usize::try_from(RESET_PCR).unwrap()];
    // See if incrementing the reset counter worked
    assert_eq!(pcr7_reset_counter, 1);

    // verify signature
    let big_r = BigNum::from_slice(&resp.signature_r).unwrap();
    let big_s = BigNum::from_slice(&resp.signature_s).unwrap();
    let sig = EcdsaSig::from_private_components(big_r, big_s).unwrap();

    let fmc_resp = get_fmc_alias_cert(&mut model);
    let fmc_cert: X509 = X509::from_der(&fmc_resp.data[..fmc_resp.data_size as usize]).unwrap();
    let pkey = fmc_cert.public_key().unwrap().ec_key().unwrap();

    assert!(sig.verify(&resp.digest, &pkey).unwrap());
}

fn generate_mailbox_extend_pcr_req(idx: u32, pcr_extension_data: [u8; 48]) -> ExtendPcrReq {
    let cmd = ExtendPcrReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pcr_idx: idx,
        data: pcr_extension_data,
    };

    let checksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::EXTEND_PCR),
        &cmd.as_bytes()[4..],
    );

    ExtendPcrReq {
        hdr: MailboxReqHeader { chksum: checksum },
        pcr_idx: cmd.pcr_idx,
        data: cmd.data,
    }
}

pub fn get_model_pcrs(model: &mut DefaultHwModel) -> [[u8; 48]; 32] {
    let mut cmd = MailboxReq::QuotePcrs(QuotePcrsReq {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce: [0u8; 32],
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(u32::from(CommandId::QUOTE_PCRS), cmd.as_bytes().unwrap())
        .unwrap()
        .unwrap();

    return QuotePcrsResp::read_from(resp.as_slice()).unwrap().pcrs;
}

#[test]
fn test_extend_pcr_cmd_multiple_extensions() {
    // 0. Get fresh pcr state and verify
    let mut model = run_rt_test(None, None, None);
    assert_eq!(get_model_pcrs(&mut model)[4], [0u8; 48]);

    // 1.0 Testing for extension_data [0,...,0]
    let extension_data = [0u8; 48];

    let cmd = generate_mailbox_extend_pcr_req(4, extension_data);
    let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes());
    assert!(res.is_ok());

    // 1.1 Checking for PCR values using PCR_QUOTE
    let pcrs = get_model_pcrs(&mut model);
    assert_eq!(
        pcrs[4],
        [
            245, 123, 183, 237, 130, 198, 174, 74, 41, 230, 201, 135, 147, 56, 197, 146, 199, 212,
            42, 57, 19, 85, 131, 232, 204, 190, 57, 64, 242, 52, 75, 14, 182, 235, 133, 3, 219, 15,
            253, 106, 57, 221, 208, 12, 208, 125, 131, 23
        ]
    );

    // 1.2 Extending PCR[4] with another [0,..,0] payload
    let cmd = generate_mailbox_extend_pcr_req(4, extension_data);
    let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes());
    assert!(res.is_ok());

    // 1.3 Checking for PCR values using PCR_QUOTE
    let pcrs = get_model_pcrs(&mut model);
    assert_eq!(
        pcrs[4],
        [
            17, 20, 49, 33, 190, 179, 101, 230, 56, 38, 231, 222, 137, 249, 199, 106, 225, 16, 4,
            17, 251, 150, 67, 209, 152, 231, 48, 183, 96, 58, 131, 164, 151, 124, 118, 238, 230,
            221, 247, 79, 160, 180, 63, 191, 73, 137, 121, 120
        ]
    );

    // 2.0 Testing for extension data with high entropy
    let extension_data: [u8; 48] = [
        225, 73, 188, 244, 110, 120, 121, 204, 185, 203, 86, 129, 104, 186, 33, 110, 125, 116, 216,
        80, 244, 199, 184, 21, 127, 187, 78, 122, 18, 26, 32, 48, 171, 251, 17, 20, 67, 224, 15,
        81, 144, 232, 190, 103, 213, 7, 199, 148,
    ];

    let cmd = generate_mailbox_extend_pcr_req(4, extension_data);
    let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes());
    assert!(res.is_ok());

    // 2.1 Checking for PCR values using PCR_QUOTE
    let pcrs = get_model_pcrs(&mut model);
    assert_eq!(
        pcrs[4],
        [
            126, 22, 167, 237, 252, 6, 123, 255, 55, 116, 215, 208, 142, 112, 160, 65, 123, 224,
            125, 35, 36, 250, 134, 225, 116, 230, 182, 189, 8, 74, 246, 183, 26, 10, 123, 58, 157,
            205, 241, 120, 15, 53, 210, 93, 136, 5, 235, 55
        ]
    );
}

#[test]
fn test_extend_pcr_cmd_invalid_pcr_index() {
    let mut model = run_rt_test(None, None, None);
    let extension_data: [u8; 48] = [0u8; 48];

    // 3. Invalid PCR index
    let cmd = generate_mailbox_extend_pcr_req(33, extension_data);
    let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes());
    assert_eq!(
        res,
        Err(ModelError::MailboxCmdFailed(u32::from(
            CaliptraError::RUNTIME_PCR_INVALID_INDEX
        )))
    );
}

#[test]
fn test_extend_pcr_cmd_reserved_range() {
    let mut model = run_rt_test(None, None, None);
    let extension_data: [u8; 48] = [0u8; 48];

    // 4. Ensure reserved PCR range
    let reserved_pcrs = [PcrId::PcrId0, PcrId::PcrId1, PcrId::PcrId2, PcrId::PcrId3];
    for test_pcr_index_reserved in reserved_pcrs {
        let cmd = generate_mailbox_extend_pcr_req(test_pcr_index_reserved.into(), extension_data);

        let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes());
        assert_eq!(
            res,
            Err(ModelError::MailboxCmdFailed(u32::from(
                CaliptraError::RUNTIME_PCR_RESERVED
            )))
        );
    }
}
