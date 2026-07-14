// Licensed under the Apache-2.0 license

use caliptra_common::{
    checksum::calc_checksum,
    mailbox_api::{CommandId, MailboxReq, MailboxReqHeader, PopulatePqCertReq},
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;

use crate::common::{assert_error, run_pqc_rt_test};

#[test]
fn test_populate_pq_cert() {
    let mut model = run_pqc_rt_test();
    let cert_bytes = [0xa5u8; 64];
    let mut cert_buf = [0u8; PopulatePqCertReq::MAX_CERT_SIZE];
    cert_buf[..cert_bytes.len()].copy_from_slice(&cert_bytes);

    let mut cmd = MailboxReq::PopulatePqCert(PopulatePqCertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        cert_size: cert_bytes.len() as u32,
        cert: cert_buf,
    });
    cmd.populate_chksum().unwrap();

    model
        .mailbox_execute(
            u32::from(CommandId::POPULATE_PQ_CERT),
            cmd.as_bytes().unwrap(),
        )
        .unwrap();
}

#[test]
fn test_populate_pq_cert_size_too_large() {
    let mut model = run_pqc_rt_test();
    let cmd = MailboxReq::PopulatePqCert(PopulatePqCertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        cert_size: 32,
        cert: [0u8; PopulatePqCertReq::MAX_CERT_SIZE],
    });

    // Manually patch the request to inject the bad tbs_size, then re-checksum
    let mut raw = cmd.as_bytes().unwrap().to_vec();
    let bad_size = (PopulatePqCertReq::MAX_CERT_SIZE as u32 + 1).to_le_bytes();
    raw[4..8].copy_from_slice(&bad_size);
    let chksum = calc_checksum(u32::from(CommandId::POPULATE_PQ_CERT), &raw[4..]);
    raw[0..4].copy_from_slice(&chksum.to_le_bytes());

    let resp = model
        .mailbox_execute(u32::from(CommandId::POPULATE_PQ_CERT), &raw)
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        resp,
    );
}

#[test]
fn test_populate_pq_cert_call_outside_pl0() {
    let mut model = run_pqc_rt_test();
    model.set_apb_pauser(2);

    let mut cmd = MailboxReq::PopulatePqCert(PopulatePqCertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        cert_size: 1,
        cert: [0u8; PopulatePqCertReq::MAX_CERT_SIZE],
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::POPULATE_PQ_CERT),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
        resp,
    );
}
