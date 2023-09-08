// Licensed under the Apache-2.0 license

use crate::common::{get_fmc_alias_cert, run_rt_test};
use caliptra_common::mailbox_api::{
    CommandId, ExtendPcrReq, IncrementPcrResetCounterReq, MailboxReq, MailboxReqHeader,
    QuotePcrsReq, QuotePcrsResp,
};
use caliptra_hw_model::HwModel;
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

#[test]
fn test_extend_pcr_cmd() {
    fn generate_mailbox_extend_pcr_req(
        pcr_idx: u32,
        data_size: usize,
        payload: [u8; ExtendPcrReq::DATA_MAX_SIZE],
    ) -> Result<ExtendPcrReq, ExtendPcrReqErr> {
        let cmd = ExtendPcrReq::new(
            MailboxReqHeader { chksum: 0 },
            pcr_idx,
            data_size as u32,
            payload,
        )?;

        let checksum = caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::EXTEND_PCR),
            &cmd.as_bytes()[4..],
        );

        ExtendPcrReq::new(
            MailboxReqHeader { chksum: checksum },
            cmd.pcr_idx,
            cmd.data_size,
            cmd.data,
        )
    }

    let mut model = run_rt_test(None, None);
    let payload_data = [0u8; ExtendPcrReq::DATA_MAX_SIZE];

    let cmd = generate_mailbox_extend_pcr_req(4, payload_data.len(), payload_data).unwrap();
    let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), &cmd.as_bytes());
    assert!(res.is_ok());

    // Smaller size
    let cmd = generate_mailbox_extend_pcr_req(4, payload_data.len() - 0xf, payload_data).unwrap();
    let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), &cmd.as_bytes());
    assert!(res.is_ok());

    // Invalid size
    let cmd = generate_mailbox_extend_pcr_req(4, payload_data.len() + 0xf, payload_data).unwrap();
    let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), &cmd.as_bytes());
    assert_eq!(
        res,
        Err(ModelError::MailboxCmdFailed(u32::from(
            CaliptraError::DRIVER_PCR_BANK_EXTEND_INVALID_SIZE
        )))
    );

    // Invalid PCR index
    let cmd = generate_mailbox_extend_pcr_req(33, payload_data.len(), payload_data).unwrap();
    let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), &cmd.as_bytes());
    assert_eq!(
        res,
        Err(ModelError::MailboxCmdFailed(u32::from(
            CaliptraError::RUNTIME_PCR_INVALID_INDEX
        )))
    );

    // Ensure reserved PCR range
    let reserved_pcrs = [PcrId::PcrId0, PcrId::PcrId1, PcrId::PcrId2, PcrId::PcrId3];
    for test_pcr_index_reserved in reserved_pcrs {
        let cmd = generate_mailbox_extend_pcr_req(
            test_pcr_index_reserved.into(),
            payload_data.len(),
            payload_data,
        )
        .unwrap();

        let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), &cmd.as_bytes());
        // let error_code: u32 = CaliptraError::RUNTIME_PCR_INVALID_INDEX.0.get();
        assert_eq!(
            res,
            Err(ModelError::MailboxCmdFailed(u32::from(
                CaliptraError::RUNTIME_PCR_RESERVED
            )))
        );
    }
}
