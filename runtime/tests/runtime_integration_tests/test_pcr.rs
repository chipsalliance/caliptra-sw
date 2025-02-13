// Licensed under the Apache-2.0 license

use crate::common::{get_fmc_alias_cert, run_rt_test, RuntimeTestArgs};
use caliptra_api::SocManager;

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
use zerocopy::{FromBytes, IntoBytes};

#[test]
fn test_pcr_quote() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

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

    let resp = QuotePcrsResp::read_from_bytes(resp.as_slice()).unwrap();

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

fn generate_mailbox_extend_pcr_req(idx: u32, pcr_extension_data: [u8; 48]) -> MailboxReq {
    let mut cmd = MailboxReq::ExtendPcr(ExtendPcrReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pcr_idx: idx,
        data: pcr_extension_data,
    });
    cmd.populate_chksum().unwrap();

    cmd
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

    return QuotePcrsResp::read_from_bytes(resp.as_slice())
        .unwrap()
        .pcrs;
}

#[test]
fn test_extend_pcr_cmd_multiple_extensions() {
    fn extend_pcr(current: &[u8; 48], data: &[u8; 48]) -> [u8; 48] {
        let mut h = Hasher::new(MessageDigest::sha384()).unwrap();
        let _ = h.update(current);
        let _ = h.update(data);
        let res = h.finish().unwrap();
        res.as_bytes().try_into().unwrap()
    }

    // 0. Get fresh pcr state and verify
    let mut model = run_rt_test(RuntimeTestArgs::default());
    assert_eq!(get_model_pcrs(&mut model)[4], [0u8; 48]);

    // 1.0 Testing for extension_data [0,...,0]
    let extension_data = [0u8; 48];

    let cmd = generate_mailbox_extend_pcr_req(4, extension_data);
    let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes().unwrap());
    assert!(res.is_ok());

    // 1.1 Checking for PCR values using PCR_QUOTE
    let pcrs = get_model_pcrs(&mut model);
    let pcr = extend_pcr(&[0; 48], &extension_data);
    assert_eq!(pcrs[4], pcr);

    // 1.2 Extending PCR[4] with another [0,..,0] payload
    let cmd = generate_mailbox_extend_pcr_req(4, extension_data);
    let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes().unwrap());

    assert!(res.is_ok());

    // 1.3 Checking for PCR values using PCR_QUOTE
    let pcr = extend_pcr(&pcr, &extension_data);
    let pcrs = get_model_pcrs(&mut model);
    assert_eq!(pcrs[4], pcr);

    // 2.0 Testing for extension data with high entropy
    let extension_data: [u8; 48] = [
        225, 73, 188, 244, 110, 120, 121, 204, 185, 203, 86, 129, 104, 186, 33, 110, 125, 116, 216,
        80, 244, 199, 184, 21, 127, 187, 78, 122, 18, 26, 32, 48, 171, 251, 17, 20, 67, 224, 15,
        81, 144, 232, 190, 103, 213, 7, 199, 148,
    ];

    let cmd = generate_mailbox_extend_pcr_req(4, extension_data);
    let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes().unwrap());
    assert!(res.is_ok());

    // 2.1 Checking for PCR values using PCR_QUOTE
    let pcr = extend_pcr(&pcr, &extension_data);
    let pcrs = get_model_pcrs(&mut model);
    assert_eq!(pcrs[4], pcr);
}

#[test]
fn test_extend_pcr_cmd_invalid_pcr_index() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    let extension_data: [u8; 48] = [0u8; 48];

    // 3. Invalid PCR index
    let cmd = generate_mailbox_extend_pcr_req(33, extension_data);
    let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes().unwrap());
    assert_eq!(
        res,
        Err(ModelError::MailboxCmdFailed(u32::from(
            CaliptraError::RUNTIME_PCR_INVALID_INDEX
        )))
    );
}

#[test]
fn test_extend_pcr_cmd_reserved_range() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    let extension_data: [u8; 48] = [0u8; 48];

    // 4. Ensure reserved PCR range
    let reserved_pcrs = [PcrId::PcrId0, PcrId::PcrId1, PcrId::PcrId2, PcrId::PcrId3];
    for test_pcr_index_reserved in reserved_pcrs {
        let cmd = generate_mailbox_extend_pcr_req(test_pcr_index_reserved.into(), extension_data);

        let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes().unwrap());
        assert_eq!(
            res,
            Err(ModelError::MailboxCmdFailed(u32::from(
                CaliptraError::RUNTIME_PCR_RESERVED
            )))
        );
    }
}
